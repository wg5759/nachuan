"""DPAPI-protected offline root for release-policy signatures only."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gateway.secure_store import (
    SecureStorageError,
    read_protected_json,
    write_protected_json_if_absent,
)


_SCHEMA = "nachuan.installed-channel-supervisor-release-authority.v1"
_PURPOSE = "nachuan/installed-channel-supervisor-release-authority"
_FILENAME = "installer-anchor-signing-key.protected.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_POLICY_DOMAIN = b"nachuan-installed-channel-release-policy-v1\0"


class InstalledChannelReleaseAuthorityError(ValueError):
    pass


class InstalledChannelReleaseAuthorityConflict(InstalledChannelReleaseAuthorityError):
    pass


class Ed25519ReleasePolicyVerifier:
    def __init__(self, public_key_spki_der: bytes) -> None:
        try:
            key = serialization.load_der_public_key(public_key_spki_der)
        except (TypeError, ValueError) as exc:
            raise InstalledChannelReleaseAuthorityError(
                "release policy public key is invalid"
            ) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise InstalledChannelReleaseAuthorityError(
                "release policy public key is invalid"
            )
        canonical = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if canonical != public_key_spki_der:
            raise InstalledChannelReleaseAuthorityError(
                "release policy public key is not canonical"
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
            self._key.verify(signature, _RELEASE_POLICY_DOMAIN + payload)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True, repr=False)
class InstalledChannelReleaseAuthority:
    key_id: str
    public_key_spki_der: bytes
    _private_key: Ed25519PrivateKey = field(repr=False)

    def sign_release_policy(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= 16 * 1024:
            raise InstalledChannelReleaseAuthorityError(
                "installer anchor payload is invalid"
            )
        return self._private_key.sign(_RELEASE_POLICY_DOMAIN + payload)

    def embedded_trust_document(
        self,
        *,
        minimum_installer_release_sequence: int,
        minimum_keyring_sequence: int,
    ) -> dict[str, object]:
        for value in (
            minimum_installer_release_sequence,
            minimum_keyring_sequence,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InstalledChannelReleaseAuthorityError(
                    "embedded trust floor is invalid"
                )
        return {
            "algorithm": "ed25519",
            "enabled": True,
            "minimum_installer_release_sequence": minimum_installer_release_sequence,
            "minimum_keyring_sequence": minimum_keyring_sequence,
            "public_key_spki_base64": base64.b64encode(
                self.public_key_spki_der
            ).decode("ascii"),
            "schema": "nachuan.installed-channel-supervisor-embedded-trust.v1",
            "signer_key_id": self.key_id,
        }


def _document(private_key: Ed25519PrivateKey) -> dict[str, str]:
    private_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "algorithm": "ed25519",
        "key_id": hashlib.sha256(public_der).hexdigest(),
        "private_key_pkcs8_b64": base64.b64encode(private_der).decode("ascii"),
        "public_key_spki_b64": base64.b64encode(public_der).decode("ascii"),
        "schema": _SCHEMA,
    }


def _parse(document: object) -> InstalledChannelReleaseAuthority:
    expected = {
        "algorithm",
        "key_id",
        "private_key_pkcs8_b64",
        "public_key_spki_b64",
        "schema",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document.get("schema") != _SCHEMA
        or document.get("algorithm") != "ed25519"
        or not isinstance(document.get("key_id"), str)
        or _HEX64.fullmatch(document["key_id"]) is None
        or not isinstance(document.get("private_key_pkcs8_b64"), str)
        or not isinstance(document.get("public_key_spki_b64"), str)
    ):
        raise InstalledChannelReleaseAuthorityError(
            "release authority document is invalid"
        )
    try:
        private_der = base64.b64decode(
            document["private_key_pkcs8_b64"], validate=True
        )
        public_der = base64.b64decode(document["public_key_spki_b64"], validate=True)
        private_key = serialization.load_der_private_key(private_der, password=None)
    except (TypeError, ValueError) as exc:
        raise InstalledChannelReleaseAuthorityError(
            "release authority key is invalid"
        ) from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise InstalledChannelReleaseAuthorityError(
            "release authority key is invalid"
        )
    canonical_private = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    canonical_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if (
        canonical_private != private_der
        or canonical_public != public_der
        or hashlib.sha256(public_der).hexdigest() != document["key_id"]
        or not isinstance(private_key.public_key(), Ed25519PublicKey)
    ):
        raise InstalledChannelReleaseAuthorityError(
            "release authority key identity is invalid"
        )
    return InstalledChannelReleaseAuthority(
        key_id=document["key_id"],
        public_key_spki_der=public_der,
        _private_key=private_key,
    )


class InstalledChannelReleaseAuthorityStore:
    def __init__(self, path: str | Path) -> None:
        target = Path(os.path.abspath(os.fspath(path)))
        if (
            not Path(path).is_absolute()
            or target.name.casefold() != _FILENAME
            or target.parent.name.casefold() != "release-authority"
        ):
            raise InstalledChannelReleaseAuthorityError(
                "release authority path is invalid"
            )
        self.path = target

    def initialize(self) -> InstalledChannelReleaseAuthority:
        private_key = Ed25519PrivateKey.generate()
        document = _document(private_key)
        try:
            created = write_protected_json_if_absent(
                self.path,
                document,
                purpose=_PURPOSE,
            )
        except SecureStorageError as exc:
            raise InstalledChannelReleaseAuthorityError(
                "release authority could not be created"
            ) from exc
        if not created:
            raise InstalledChannelReleaseAuthorityConflict(
                "release authority already exists"
            )
        return _parse(document)

    def load(self) -> InstalledChannelReleaseAuthority:
        try:
            document = read_protected_json(
                self.path,
                purpose=_PURPOSE,
                migrate_plaintext=False,
            )
        except (FileNotFoundError, SecureStorageError) as exc:
            raise InstalledChannelReleaseAuthorityError(
                "release authority is unavailable"
            ) from exc
        return _parse(document)


__all__ = [
    "InstalledChannelReleaseAuthority",
    "InstalledChannelReleaseAuthorityConflict",
    "InstalledChannelReleaseAuthorityError",
    "InstalledChannelReleaseAuthorityStore",
    "Ed25519ReleasePolicyVerifier",
]
