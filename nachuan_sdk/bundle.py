"""Deterministic publisher tooling for Nachuan isolated transform plugins.

The SDK writes only the three files accepted by the runtime verifier.  Signing
keys are supplied as live objects and are never serialized by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from orchestrator.isolated_plugin import (
    IsolatedPluginLimits,
    isolated_plugin_signing_payload,
    verify_isolated_plugin_bundle,
)

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_MAX_SOURCE_BYTES = 1024 * 1024


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or int(getattr(info, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


def _require_plain_directory(path: Path) -> None:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
        raise ValueError("bundle parent must be a plain directory")


def default_isolated_limits() -> IsolatedPluginLimits:
    return IsolatedPluginLimits(
        timeout_ms=1_000,
        cpu_time_ms=500,
        memory_bytes=64 * 1024 * 1024,
        max_request_bytes=64 * 1024,
        max_response_bytes=64 * 1024,
    )


@dataclass(frozen=True, slots=True)
class IsolatedTransformPluginSpecV1:
    plugin_id: str
    version: str
    publisher_key_id: str
    license: str
    limits: IsolatedPluginLimits

    def __post_init__(self) -> None:
        if not isinstance(self.plugin_id, str) or _ID.fullmatch(self.plugin_id) is None:
            raise ValueError("plugin id is invalid")
        if not isinstance(self.version, str) or _VERSION.fullmatch(self.version) is None:
            raise ValueError("plugin version is invalid")
        if (
            not isinstance(self.publisher_key_id, str)
            or _KEY_ID.fullmatch(self.publisher_key_id) is None
        ):
            raise ValueError("publisher key id is invalid")
        if (
            not isinstance(self.license, str)
            or not 1 <= len(self.license) <= 128
            or any(ord(char) < 32 for char in self.license)
        ):
            raise ValueError("plugin license is invalid")
        if not isinstance(self.limits, IsolatedPluginLimits):
            raise TypeError("plugin limits are invalid")
        IsolatedPluginLimits.from_mapping(
            {
                "timeout_ms": self.limits.timeout_ms,
                "cpu_time_ms": self.limits.cpu_time_ms,
                "memory_bytes": self.limits.memory_bytes,
                "max_request_bytes": self.limits.max_request_bytes,
                "max_response_bytes": self.limits.max_response_bytes,
            }
        )


@dataclass(frozen=True, slots=True)
class BundleBuildReceiptV1:
    plugin_id: str
    version: str
    artifact_sha256: str
    sbom_sha256: str
    manifest_sha256: str
    publisher_key_id: str
    files: tuple[str, ...] = ("manifest.json", "plugin.py", "sbom.json")
    schema: str = "nachuan.sdk.bundle-build-receipt.v1"

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plugin_id": self.plugin_id,
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "sbom_sha256": self.sbom_sha256,
            "manifest_sha256": self.manifest_sha256,
            "publisher_key_id": self.publisher_key_id,
            "files": list(self.files),
        }


def build_signed_transform_bundle(
    root: str | Path,
    *,
    spec: IsolatedTransformPluginSpecV1,
    plugin_source: bytes,
    private_key: Ed25519PrivateKey,
) -> BundleBuildReceiptV1:
    """Build and self-verify one immutable three-file isolated plugin bundle."""

    if not isinstance(spec, IsolatedTransformPluginSpecV1):
        raise TypeError("plugin spec is invalid")
    if not isinstance(plugin_source, bytes) or not 1 <= len(plugin_source) <= _MAX_SOURCE_BYTES:
        raise ValueError("plugin source is invalid")
    if b"\x00" in plugin_source:
        raise ValueError("plugin source contains NUL")
    try:
        plugin_source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("plugin source must be UTF-8") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("publisher private key is invalid")

    destination = Path(root).resolve()
    parent = destination.parent
    _require_plain_directory(parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("bundle destination already exists")

    artifact_sha256 = hashlib.sha256(plugin_source).hexdigest()
    sbom = _canonical_json(
        {
            "schema": "nachuan.isolated-plugin-sbom.v1",
            "components": [
                {
                    "name": spec.plugin_id,
                    "version": spec.version,
                    "license": spec.license,
                    "sha256": artifact_sha256,
                }
            ],
        }
    )
    sbom_sha256 = hashlib.sha256(sbom).hexdigest()
    limits: Mapping[str, object] = {
        "timeout_ms": spec.limits.timeout_ms,
        "cpu_time_ms": spec.limits.cpu_time_ms,
        "memory_bytes": spec.limits.memory_bytes,
        "max_request_bytes": spec.limits.max_request_bytes,
        "max_response_bytes": spec.limits.max_response_bytes,
    }
    manifest: dict[str, object] = {
        "schema": "nachuan.isolated-plugin.v1",
        "id": spec.plugin_id,
        "version": spec.version,
        "api_version": "1",
        "execution": "isolated_worker",
        "capabilities": ["transform.json"],
        "entrypoint": "plugin.py",
        "artifact_sha256": artifact_sha256,
        "sbom_sha256": sbom_sha256,
        "publisher_key_id": spec.publisher_key_id,
        "limits": dict(limits),
    }
    manifest["signature"] = private_key.sign(
        isolated_plugin_signing_payload(manifest)
    ).hex()
    manifest_bytes = _canonical_json(manifest)

    staging = parent / f".{destination.name}.nachuan-sdk-{secrets.token_hex(8)}"
    try:
        staging.mkdir(mode=0o700)
        for name, payload in (
            ("plugin.py", plugin_source),
            ("sbom.json", sbom),
            ("manifest.json", manifest_bytes),
        ):
            with (staging / name).open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        public = private_key.public_key().public_bytes_raw()
        verify_isolated_plugin_bundle(
            staging,
            trusted_publishers={spec.publisher_key_id: public},
        )
        os.replace(staging, destination)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise

    verify_isolated_plugin_bundle(
        destination,
        trusted_publishers={spec.publisher_key_id: public},
    )
    return BundleBuildReceiptV1(
        plugin_id=spec.plugin_id,
        version=spec.version,
        artifact_sha256=artifact_sha256,
        sbom_sha256=sbom_sha256,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        publisher_key_id=spec.publisher_key_id,
    )


__all__ = [
    "BundleBuildReceiptV1",
    "IsolatedTransformPluginSpecV1",
    "build_signed_transform_bundle",
    "default_isolated_limits",
]
