"""DPAPI-protected configuration authority for the installed channel supervisor."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path

from gateway.installed_channel_file_lock import InstalledChannelFileLock
from gateway.secure_store import (
    SecureStorageError,
    read_protected_json,
    write_protected_json,
    write_protected_json_if_absent,
)


_CONFIG_SCHEMA = "nachuan.installed-channel-supervisor-config.v1"
_STATUS_SCHEMA = "nachuan.installed-channel-supervisor-status.v1"
_KEY_SCHEMA = "nachuan.installed-channel-supervisor-verification-key.v1"
_CONFIG_PURPOSE = "nachuan/installed-channel-supervisor-config"
_KEY_PURPOSE = "nachuan/installed-channel-supervisor-verification-key"
_CONFIG_FILENAME = "installed-channel-supervisor.json"
_KEY_BYTES = 32
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_APP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_LOCK = threading.RLock()


class InstalledChannelConfigError(ValueError):
    pass


class InstalledChannelConfigConflict(InstalledChannelConfigError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class InstalledChannelSupervisorConfig:
    generation: int
    engine_port: int
    runtime_key: str
    approval_key: str
    paid_media_key: str
    weixin_bridge_key: str
    feishu_bridge_key: str
    feishu_app_id: str
    feishu_app_secret: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= 2**63 - 1
        ):
            raise InstalledChannelConfigError("generation is invalid")
        if (
            isinstance(self.engine_port, bool)
            or not isinstance(self.engine_port, int)
            or not 1024 <= self.engine_port <= 65535
        ):
            raise InstalledChannelConfigError("engine port is invalid")
        patterns = {
            "runtime_key": r"sk-local-[0-9a-f]{64}",
            "approval_key": r"sk-approval-[0-9a-f]{64}",
            "paid_media_key": r"sk-paid-media-[0-9a-f]{64}",
            "weixin_bridge_key": r"sk-bridge-v2-weixin-[0-9a-f]{64}",
            "feishu_bridge_key": r"sk-bridge-v2-feishu-[0-9a-f]{64}",
        }
        values: list[str] = []
        for name, pattern in patterns.items():
            value = getattr(self, name)
            if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
                raise InstalledChannelConfigError(f"{name} is invalid")
            values.append(value)
        if len(set(values)) != len(values):
            raise InstalledChannelConfigError("capabilities overlap")
        if not isinstance(self.feishu_app_id, str) or _APP_ID.fullmatch(
            self.feishu_app_id
        ) is None:
            raise InstalledChannelConfigError("Feishu app id is invalid")
        if (
            not isinstance(self.feishu_app_secret, str)
            or not 8 <= len(self.feishu_app_secret) <= 512
            or any(ord(char) < 0x20 for char in self.feishu_app_secret)
        ):
            raise InstalledChannelConfigError("Feishu app secret is invalid")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _key_document(key: bytes) -> dict[str, str]:
    return {"schema": _KEY_SCHEMA, "key_b64": base64.b64encode(key).decode("ascii")}


def _parse_key(document: object) -> bytes:
    if not isinstance(document, dict) or set(document) != {"schema", "key_b64"}:
        raise InstalledChannelConfigError("verification key document is invalid")
    encoded = document.get("key_b64")
    if document.get("schema") != _KEY_SCHEMA or not isinstance(encoded, str):
        raise InstalledChannelConfigError("verification key document is invalid")
    try:
        key = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise InstalledChannelConfigError("verification key document is invalid") from exc
    if len(key) != _KEY_BYTES:
        raise InstalledChannelConfigError("verification key document is invalid")
    return key


def _config_body(config: InstalledChannelSupervisorConfig) -> dict[str, object]:
    return {
        "schema": _CONFIG_SCHEMA,
        "generation": config.generation,
        "engine_port": config.engine_port,
        "runtime_key": config.runtime_key,
        "approval_key": config.approval_key,
        "paid_media_key": config.paid_media_key,
        "weixin_bridge_key": config.weixin_bridge_key,
        "feishu_bridge_key": config.feishu_bridge_key,
        "feishu_app_id": config.feishu_app_id,
        "feishu_app_secret": config.feishu_app_secret,
    }


def _sealed_document(
    config: InstalledChannelSupervisorConfig, verification_key: bytes
) -> dict[str, object]:
    body = _config_body(config)
    return {
        **body,
        "config_hmac_sha256": hmac.new(
            verification_key,
            b"nachuan-installed-channel-config-v1\0" + _canonical_json(body),
            hashlib.sha256,
        ).hexdigest(),
    }


def _parse_config(
    document: object, verification_key: bytes
) -> InstalledChannelSupervisorConfig:
    expected = {
        "schema",
        "generation",
        "engine_port",
        "runtime_key",
        "approval_key",
        "paid_media_key",
        "weixin_bridge_key",
        "feishu_bridge_key",
        "feishu_app_id",
        "feishu_app_secret",
        "config_hmac_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise InstalledChannelConfigError("configuration document is invalid")
    if document.get("schema") != _CONFIG_SCHEMA:
        raise InstalledChannelConfigError("configuration document is invalid")
    config = InstalledChannelSupervisorConfig(
        generation=document.get("generation"),  # type: ignore[arg-type]
        engine_port=document.get("engine_port"),  # type: ignore[arg-type]
        runtime_key=document.get("runtime_key"),  # type: ignore[arg-type]
        approval_key=document.get("approval_key"),  # type: ignore[arg-type]
        paid_media_key=document.get("paid_media_key"),  # type: ignore[arg-type]
        weixin_bridge_key=document.get("weixin_bridge_key"),  # type: ignore[arg-type]
        feishu_bridge_key=document.get("feishu_bridge_key"),  # type: ignore[arg-type]
        feishu_app_id=document.get("feishu_app_id"),  # type: ignore[arg-type]
        feishu_app_secret=document.get("feishu_app_secret"),  # type: ignore[arg-type]
    )
    digest = document.get("config_hmac_sha256")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise InstalledChannelConfigError("configuration HMAC is invalid")
    expected_digest = _sealed_document(config, verification_key)["config_hmac_sha256"]
    if not hmac.compare_digest(digest, str(expected_digest)):
        raise InstalledChannelConfigError("configuration HMAC is invalid")
    return config


def _new_capabilities() -> dict[str, str]:
    return {
        "runtime_key": "sk-local-" + secrets.token_hex(32),
        "approval_key": "sk-approval-" + secrets.token_hex(32),
        "paid_media_key": "sk-paid-media-" + secrets.token_hex(32),
        "weixin_bridge_key": "sk-bridge-v2-weixin-" + secrets.token_hex(32),
        "feishu_bridge_key": "sk-bridge-v2-feishu-" + secrets.token_hex(32),
    }


class InstalledChannelSupervisorConfigStore:
    def __init__(self, path: str | Path) -> None:
        candidate = Path(os.path.abspath(os.fspath(path)))
        if not Path(path).is_absolute() or candidate.name.casefold() != _CONFIG_FILENAME:
            raise InstalledChannelConfigError("configuration path is invalid")
        self.path = candidate
        self.verification_key_path = candidate.with_name(
            candidate.name + ".verification-key"
        )
        self.lock_path = candidate.with_name(candidate.name + ".lock")

    def _load_or_create_key(self) -> bytes:
        if not self.verification_key_path.exists():
            created = write_protected_json_if_absent(
                self.verification_key_path,
                _key_document(secrets.token_bytes(_KEY_BYTES)),
                purpose=_KEY_PURPOSE,
            )
            if not created and not self.verification_key_path.exists():
                raise InstalledChannelConfigConflict("verification key creation lost")
        try:
            return _parse_key(
                read_protected_json(
                    self.verification_key_path,
                    purpose=_KEY_PURPOSE,
                    migrate_plaintext=False,
                )
            )
        except (FileNotFoundError, SecureStorageError, InstalledChannelConfigError) as exc:
            raise InstalledChannelConfigError(
                "verification key is unavailable"
            ) from exc

    def _load_locked(self, key: bytes) -> InstalledChannelSupervisorConfig:
        try:
            document = read_protected_json(
                self.path,
                purpose=_CONFIG_PURPOSE,
                migrate_plaintext=False,
            )
        except (FileNotFoundError, SecureStorageError) as exc:
            raise InstalledChannelConfigError("configuration is unavailable") from exc
        return _parse_config(document, key)

    def create(
        self,
        *,
        engine_port: int,
        feishu_app_id: str,
        feishu_app_secret: str,
    ) -> InstalledChannelSupervisorConfig:
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelConfigConflict,
            busy_message="configuration is busy",
        ):
            if self.path.exists():
                raise InstalledChannelConfigConflict("configuration already exists")
            key = self._load_or_create_key()
            config = InstalledChannelSupervisorConfig(
                generation=1,
                engine_port=engine_port,
                feishu_app_id=feishu_app_id,
                feishu_app_secret=feishu_app_secret,
                **_new_capabilities(),
            )
            if not write_protected_json_if_absent(
                self.path,
                _sealed_document(config, key),
                purpose=_CONFIG_PURPOSE,
            ):
                raise InstalledChannelConfigConflict("configuration already exists")
            return config

    def load(self) -> InstalledChannelSupervisorConfig:
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelConfigConflict,
            busy_message="configuration is busy",
        ):
            if not self.path.exists():
                raise InstalledChannelConfigError("configuration is unavailable")
            key = self._load_or_create_key()
            return self._load_locked(key)

    def rotate_capabilities(
        self, *, expected_generation: int
    ) -> InstalledChannelSupervisorConfig:
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
        ):
            raise InstalledChannelConfigConflict("expected generation is invalid")
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelConfigConflict,
            busy_message="configuration is busy",
        ):
            if not self.path.exists():
                raise InstalledChannelConfigError("configuration is unavailable")
            key = self._load_or_create_key()
            current = self._load_locked(key)
            if current.generation != expected_generation:
                raise InstalledChannelConfigConflict("configuration generation changed")
            if current.generation >= 2**63 - 1:
                raise InstalledChannelConfigConflict("configuration generation exhausted")
            rotated = InstalledChannelSupervisorConfig(
                generation=current.generation + 1,
                engine_port=current.engine_port,
                feishu_app_id=current.feishu_app_id,
                feishu_app_secret=current.feishu_app_secret,
                **_new_capabilities(),
            )
            write_protected_json(
                self.path,
                _sealed_document(rotated, key),
                purpose=_CONFIG_PURPOSE,
            )
            return rotated

    def update_feishu_credentials(
        self,
        *,
        expected_generation: int,
        feishu_app_id: str,
        feishu_app_secret: str,
    ) -> InstalledChannelSupervisorConfig:
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
        ):
            raise InstalledChannelConfigConflict("expected generation is invalid")
        with _LOCK, InstalledChannelFileLock(
            self.lock_path,
            error_type=InstalledChannelConfigConflict,
            busy_message="configuration is busy",
        ):
            if not self.path.exists():
                raise InstalledChannelConfigError("configuration is unavailable")
            key = self._load_or_create_key()
            current = self._load_locked(key)
            if current.generation != expected_generation:
                raise InstalledChannelConfigConflict("configuration generation changed")
            if current.generation >= 2**63 - 1:
                raise InstalledChannelConfigConflict("configuration generation exhausted")
            updated = InstalledChannelSupervisorConfig(
                generation=current.generation + 1,
                engine_port=current.engine_port,
                feishu_app_id=feishu_app_id,
                feishu_app_secret=feishu_app_secret,
                **_new_capabilities(),
            )
            write_protected_json(
                self.path,
                _sealed_document(updated, key),
                purpose=_CONFIG_PURPOSE,
            )
            return updated

    def safe_status(self) -> dict[str, object]:
        config = self.load()
        return {
            "schema": _STATUS_SCHEMA,
            "generation": config.generation,
            "engine_port": config.engine_port,
            "capabilities_configured": True,
            "feishu_configured": True,
        }


__all__ = [
    "InstalledChannelConfigConflict",
    "InstalledChannelConfigError",
    "InstalledChannelSupervisorConfig",
    "InstalledChannelSupervisorConfigStore",
]
