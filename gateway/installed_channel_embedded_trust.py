"""Embedded, fail-closed trust root for installer-anchor verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from gateway.installed_channel_release_authority import (
    Ed25519ReleasePolicyVerifier,
)


_SCHEMA = "nachuan.installed-channel-supervisor-embedded-trust.v1"
_FILENAME = "installed-channel-supervisor-trust.v1.json"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REPARSE_ATTRIBUTE = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
PRODUCTION_EMBEDDED_TRUST_SHA256 = (
    "6fb3662833e09beb1dec0fab92c79c0aa5af7e9c94c8e0d72224d6c215ce9006"
)


class InstalledChannelEmbeddedTrustError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class InstalledChannelEmbeddedTrust:
    enabled: bool
    document_sha256: str
    signer_key_id: str
    minimum_installer_release_sequence: int
    minimum_keyring_sequence: int
    verifier: Ed25519ReleasePolicyVerifier | None

    def require_verifier(self) -> Ed25519ReleasePolicyVerifier:
        if not self.enabled or self.verifier is None:
            raise InstalledChannelEmbeddedTrustError(
                "production trust root is disabled"
            )
        return self.verifier

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


def load_installed_channel_embedded_trust(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
) -> InstalledChannelEmbeddedTrust:
    target = Path(os.path.abspath(os.fspath(path)))
    if not Path(path).is_absolute() or target.name.casefold() != _FILENAME:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust path is invalid"
        )
    try:
        before = os.lstat(target)
    except OSError as exc:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or target.is_symlink()
        or int(getattr(before, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        or not 1 <= int(before.st_size) <= 16 * 1024
    ):
        raise InstalledChannelEmbeddedTrustError("embedded trust file is invalid")
    try:
        raw = target.read_bytes()
        after = os.lstat(target)
    except OSError as exc:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust is unavailable"
        ) from exc
    identity_before = (int(before.st_dev), int(before.st_ino), int(before.st_size))
    identity_after = (int(after.st_dev), int(after.st_ino), int(after.st_size))
    if identity_before != identity_after or len(raw) != int(before.st_size):
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust changed during verification"
        )
    if expected_sha256 is not None:
        expected_digest = str(expected_sha256 or "").casefold()
        actual_digest = hashlib.sha256(raw).hexdigest()
        if (
            _HEX64.fullmatch(expected_digest) is None
            or not hmac.compare_digest(actual_digest, expected_digest)
        ):
            raise InstalledChannelEmbeddedTrustError(
                "embedded trust digest differs from frozen policy"
            )
    try:
        document = json.loads(
            raw.decode("ascii", errors="strict"),
            parse_constant=_reject_constant,
            object_pairs_hook=_without_duplicates,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust JSON is invalid"
        ) from exc
    expected = {
        "algorithm",
        "enabled",
        "minimum_installer_release_sequence",
        "minimum_keyring_sequence",
        "public_key_spki_base64",
        "schema",
        "signer_key_id",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document.get("schema") != _SCHEMA
        or document.get("algorithm") != "ed25519"
        or type(document.get("enabled")) is not bool
        or raw != _canonical(document) + (b"\n" if raw.endswith(b"\n") else b"")
    ):
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust document is invalid"
        )
    release_floor = document.get("minimum_installer_release_sequence")
    keyring_floor = document.get("minimum_keyring_sequence")
    if (
        isinstance(release_floor, bool)
        or not isinstance(release_floor, int)
        or release_floor < 0
        or isinstance(keyring_floor, bool)
        or not isinstance(keyring_floor, int)
        or keyring_floor < 0
    ):
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust floor is invalid"
        )
    enabled = document["enabled"]
    signer_key_id = document.get("signer_key_id")
    encoded = document.get("public_key_spki_base64")
    if not isinstance(signer_key_id, str) or not isinstance(encoded, str):
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust key is invalid"
        )
    if not enabled:
        if signer_key_id or encoded or release_floor != 0 or keyring_floor != 0:
            raise InstalledChannelEmbeddedTrustError(
                "disabled embedded trust is not empty"
            )
        return InstalledChannelEmbeddedTrust(
            enabled=False,
            document_sha256=hashlib.sha256(raw).hexdigest(),
            signer_key_id="",
            minimum_installer_release_sequence=0,
            minimum_keyring_sequence=0,
            verifier=None,
        )
    if _HEX64.fullmatch(signer_key_id) is None:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust signer is invalid"
        )
    try:
        public_key = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust public key is invalid"
        ) from exc
    try:
        verifier = Ed25519ReleasePolicyVerifier(public_key)
    except Exception as exc:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust public key is invalid"
        ) from exc
    if verifier.key_id != signer_key_id:
        raise InstalledChannelEmbeddedTrustError(
            "embedded trust signer differs from public key"
        )
    return InstalledChannelEmbeddedTrust(
        enabled=True,
        document_sha256=hashlib.sha256(raw).hexdigest(),
        signer_key_id=signer_key_id,
        minimum_installer_release_sequence=release_floor,
        minimum_keyring_sequence=keyring_floor,
        verifier=verifier,
    )


__all__ = [
    "InstalledChannelEmbeddedTrust",
    "InstalledChannelEmbeddedTrustError",
    "PRODUCTION_EMBEDDED_TRUST_SHA256",
    "load_installed_channel_embedded_trust",
]
