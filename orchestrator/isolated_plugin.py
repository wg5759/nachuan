"""Signed third-party plugin bundles and the fail-closed isolated broker contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_KEY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_CAPABILITIES = frozenset({"transform.json"})
_BUNDLE_FILES = frozenset({"manifest.json", "plugin.py", "sbom.json"})
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_SBOM_BYTES = 256 * 1024
_MAX_ENTRYPOINT_BYTES = 1024 * 1024
_STATE_APPLICATION_ID = 1_313_034_313
_STATE_SCHEMA_VERSION = 1
_MAX_QUARANTINE_IDENTITIES = 10_000
_STATE_DDL = """CREATE TABLE isolated_plugin_quarantine (
                    plugin_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    quarantined_at INTEGER NOT NULL,
                    PRIMARY KEY (plugin_id, version, artifact_sha256)
                ) WITHOUT ROWID"""


class IsolatedPluginError(RuntimeError):
    pass


class IsolatedPluginContractError(IsolatedPluginError, ValueError):
    pass


class IsolatedPluginSignatureError(IsolatedPluginError):
    pass


class IsolatedPluginRevoked(IsolatedPluginError):
    pass


class IsolatedPluginQuarantined(IsolatedPluginError):
    pass


class IsolatedPluginWorkerError(IsolatedPluginError):
    pass


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise IsolatedPluginContractError("plugin document is not canonical JSON") from exc


def _parse_canonical_json(payload: bytes, label: str) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate field")
            result[name] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError("non-finite number")

    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise IsolatedPluginContractError(f"{label} JSON is invalid") from exc
    if _canonical_json(value) != payload:
        raise IsolatedPluginContractError(f"{label} JSON is not canonical")
    return value


def _is_reparse(info: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(info.st_mode)
        or int(getattr(info, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    )


def _regular(path: Path, maximum: int) -> bytes:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise IsolatedPluginContractError("plugin bundle file is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or _is_reparse(info)
        or info.st_size < 1
        or info.st_size > maximum
    ):
        raise IsolatedPluginContractError("plugin bundle file is invalid")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise IsolatedPluginContractError("plugin bundle file cannot be read") from exc
    if len(payload) != info.st_size:
        raise IsolatedPluginContractError("plugin bundle file changed while reading")
    return payload


def _directory(path: Path) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise IsolatedPluginContractError("plugin bundle root is unavailable") from exc
    if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
        raise IsolatedPluginContractError("plugin bundle root is invalid")


@dataclass(frozen=True, slots=True)
class IsolatedPluginLimits:
    timeout_ms: int
    cpu_time_ms: int
    memory_bytes: int
    max_request_bytes: int
    max_response_bytes: int

    @classmethod
    def from_mapping(cls, value: object) -> IsolatedPluginLimits:
        if not isinstance(value, Mapping) or set(value) != {
            "timeout_ms",
            "cpu_time_ms",
            "memory_bytes",
            "max_request_bytes",
            "max_response_bytes",
        }:
            raise IsolatedPluginContractError("plugin limits are not closed")

        def integer(name: str, minimum: int, maximum: int) -> int:
            raw = value[name]
            if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
                raise IsolatedPluginContractError("plugin limit is invalid")
            return raw

        return cls(
            timeout_ms=integer("timeout_ms", 100, 5_000),
            cpu_time_ms=integer("cpu_time_ms", 100, 5_000),
            memory_bytes=integer("memory_bytes", 32 * 1024 * 1024, 256 * 1024 * 1024),
            max_request_bytes=integer("max_request_bytes", 2, 64 * 1024),
            max_response_bytes=integer("max_response_bytes", 2, 64 * 1024),
        )


@dataclass(frozen=True, slots=True)
class IsolatedPluginManifestV1:
    plugin_id: str
    version: str
    api_version: str
    capabilities: frozenset[str]
    entrypoint: str
    artifact_sha256: str
    sbom_sha256: str
    publisher_key_id: str
    limits: IsolatedPluginLimits
    signature: str
    schema: str = "nachuan.isolated-plugin.v1"
    execution: str = "isolated_worker"

    @classmethod
    def from_mapping(cls, value: object) -> IsolatedPluginManifestV1:
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "id",
            "version",
            "api_version",
            "execution",
            "capabilities",
            "entrypoint",
            "artifact_sha256",
            "sbom_sha256",
            "publisher_key_id",
            "limits",
            "signature",
        }:
            raise IsolatedPluginContractError("plugin manifest is not closed")
        if value.get("schema") != "nachuan.isolated-plugin.v1":
            raise IsolatedPluginContractError("plugin manifest schema is unsupported")
        if value.get("execution") != "isolated_worker":
            raise IsolatedPluginContractError("plugin execution mode is invalid")
        plugin_id = value.get("id")
        version = value.get("version")
        api_version = value.get("api_version")
        entrypoint = value.get("entrypoint")
        artifact = value.get("artifact_sha256")
        sbom = value.get("sbom_sha256")
        key_id = value.get("publisher_key_id")
        signature = value.get("signature")
        if not isinstance(plugin_id, str) or _ID.fullmatch(plugin_id) is None:
            raise IsolatedPluginContractError("plugin id is invalid")
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise IsolatedPluginContractError("plugin version is invalid")
        if api_version != "1" or entrypoint != "plugin.py":
            raise IsolatedPluginContractError("plugin API or entrypoint is invalid")
        if not isinstance(artifact, str) or _SHA256.fullmatch(artifact) is None:
            raise IsolatedPluginContractError("plugin artifact digest is invalid")
        if not isinstance(sbom, str) or _SHA256.fullmatch(sbom) is None:
            raise IsolatedPluginContractError("plugin SBOM digest is invalid")
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise IsolatedPluginContractError("plugin publisher key id is invalid")
        if not isinstance(signature, str) or _HEX128.fullmatch(signature) is None:
            raise IsolatedPluginContractError("plugin signature is invalid")
        raw_capabilities = value.get("capabilities")
        if (
            not isinstance(raw_capabilities, list)
            or not raw_capabilities
            or len(raw_capabilities) > 16
            or any(not isinstance(item, str) for item in raw_capabilities)
            or len(set(raw_capabilities)) != len(raw_capabilities)
            or not set(raw_capabilities).issubset(_CAPABILITIES)
        ):
            raise IsolatedPluginContractError("plugin capabilities are invalid")
        return cls(
            plugin_id=plugin_id,
            version=version,
            api_version="1",
            capabilities=frozenset(raw_capabilities),
            entrypoint="plugin.py",
            artifact_sha256=artifact,
            sbom_sha256=sbom,
            publisher_key_id=key_id,
            limits=IsolatedPluginLimits.from_mapping(value.get("limits")),
            signature=signature,
        )

    def signing_document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "id": self.plugin_id,
            "version": self.version,
            "api_version": self.api_version,
            "execution": self.execution,
            "capabilities": sorted(self.capabilities),
            "entrypoint": self.entrypoint,
            "artifact_sha256": self.artifact_sha256,
            "sbom_sha256": self.sbom_sha256,
            "publisher_key_id": self.publisher_key_id,
            "limits": {
                "timeout_ms": self.limits.timeout_ms,
                "cpu_time_ms": self.limits.cpu_time_ms,
                "memory_bytes": self.limits.memory_bytes,
                "max_request_bytes": self.limits.max_request_bytes,
                "max_response_bytes": self.limits.max_response_bytes,
            },
        }

    def identity(self) -> tuple[str, str, str]:
        return (self.plugin_id, self.version, self.artifact_sha256)


def isolated_plugin_signing_payload(value: Mapping[str, object]) -> bytes:
    manifest = IsolatedPluginManifestV1.from_mapping({**value, "signature": "0" * 128})
    return _canonical_json(manifest.signing_document())


@dataclass(frozen=True, slots=True)
class VerifiedIsolatedPluginBundle:
    root: Path
    manifest: IsolatedPluginManifestV1
    entrypoint_bytes: bytes
    sbom_bytes: bytes


def _verify_sbom(payload: bytes, manifest: IsolatedPluginManifestV1) -> None:
    value = _parse_canonical_json(payload, "plugin SBOM")
    if not isinstance(value, dict) or set(value) != {"schema", "components"}:
        raise IsolatedPluginContractError("plugin SBOM is not closed")
    components = value.get("components")
    if value.get("schema") != "nachuan.isolated-plugin-sbom.v1" or not isinstance(components, list):
        raise IsolatedPluginContractError("plugin SBOM is invalid")
    if not 1 <= len(components) <= 128:
        raise IsolatedPluginContractError("plugin SBOM component count is invalid")
    entrypoint_seen = False
    for component in components:
        if not isinstance(component, dict) or set(component) != {"name", "version", "license", "sha256"}:
            raise IsolatedPluginContractError("plugin SBOM component is not closed")
        name = component.get("name")
        version = component.get("version")
        license_name = component.get("license")
        digest = component.get("sha256")
        if (
            not isinstance(name, str)
            or _ID.fullmatch(name) is None
            or not isinstance(version, str)
            or _VERSION.fullmatch(version) is None
            or not isinstance(license_name, str)
            or not 1 <= len(license_name) <= 128
            or any(ord(char) < 32 for char in license_name)
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise IsolatedPluginContractError("plugin SBOM component is invalid")
        if name == manifest.plugin_id and version == manifest.version and digest == manifest.artifact_sha256:
            entrypoint_seen = True
    if not entrypoint_seen:
        raise IsolatedPluginContractError("plugin SBOM does not bind the entrypoint")


def verify_isolated_plugin_bundle(
    root: str | Path,
    *,
    trusted_publishers: Mapping[str, bytes],
    revoked: frozenset[tuple[str, str, str]] = frozenset(),
) -> VerifiedIsolatedPluginBundle:
    bundle_root = Path(os.path.abspath(os.fspath(root)))
    _directory(bundle_root)
    try:
        names = {item.name for item in os.scandir(bundle_root)}
    except OSError as exc:
        raise IsolatedPluginContractError("plugin bundle cannot be enumerated") from exc
    if names != _BUNDLE_FILES:
        raise IsolatedPluginContractError("plugin bundle file set is not closed")
    manifest_bytes = _regular(bundle_root / "manifest.json", _MAX_MANIFEST_BYTES)
    entrypoint_bytes = _regular(bundle_root / "plugin.py", _MAX_ENTRYPOINT_BYTES)
    sbom_bytes = _regular(bundle_root / "sbom.json", _MAX_SBOM_BYTES)
    raw_manifest = _parse_canonical_json(manifest_bytes, "plugin manifest")
    manifest = IsolatedPluginManifestV1.from_mapping(raw_manifest)
    if manifest.identity() in revoked:
        raise IsolatedPluginRevoked("plugin identity is revoked")
    if hashlib.sha256(entrypoint_bytes).hexdigest() != manifest.artifact_sha256:
        raise IsolatedPluginContractError("plugin entrypoint digest does not match")
    if hashlib.sha256(sbom_bytes).hexdigest() != manifest.sbom_sha256:
        raise IsolatedPluginContractError("plugin SBOM digest does not match")
    _verify_sbom(sbom_bytes, manifest)
    key = trusted_publishers.get(manifest.publisher_key_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise IsolatedPluginSignatureError("plugin publisher is not trusted")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(manifest.signature),
            _canonical_json(manifest.signing_document()),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise IsolatedPluginSignatureError("plugin signature does not verify") from exc
    return VerifiedIsolatedPluginBundle(bundle_root, manifest, entrypoint_bytes, sbom_bytes)


class IsolatedPluginLauncher(Protocol):
    def execute(
        self,
        bundle: VerifiedIsolatedPluginBundle,
        request_json: bytes,
    ) -> bytes: ...


class SQLiteIsolatedPluginStateStore:
    """Durable fail-closed quarantine state keyed by an exact signed identity."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and (not self.path.is_file() or self.path.is_symlink()):
            raise IsolatedPluginContractError("plugin state store path is invalid")
        self._initialise()

    def _raw_connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    def _validate(self, connection: sqlite3.Connection) -> None:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        expected = [
            (
                "table",
                "isolated_plugin_quarantine",
                "isolated_plugin_quarantine",
                _STATE_DDL,
            )
        ]
        if (
            application_id != _STATE_APPLICATION_ID
            or user_version != _STATE_SCHEMA_VERSION
            or rows != expected
            or connection.execute("PRAGMA quick_check").fetchone()[0] != "ok"
        ):
            raise IsolatedPluginContractError("plugin state store authority is invalid")

    @contextmanager
    def _connect(self):
        connection = self._raw_connect()
        try:
            self._validate(connection)
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialise(self) -> None:
        connection = self._raw_connect()
        try:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            objects = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
            )
            if application_id == 0 and user_version == 0 and objects == 0:
                with connection:
                    connection.execute(_STATE_DDL)
                    connection.execute(f"PRAGMA application_id = {_STATE_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {_STATE_SCHEMA_VERSION}")
            self._validate(connection)
        finally:
            connection.close()

    def quarantine(self, identity: tuple[str, str, str], reason_code: str) -> None:
        if reason_code not in {"contract", "worker"}:
            raise IsolatedPluginContractError("plugin quarantine reason is invalid")
        with self._connect() as connection:
            known = connection.execute(
                """
                SELECT 1 FROM isolated_plugin_quarantine
                WHERE plugin_id = ? AND version = ? AND artifact_sha256 = ?
                """,
                identity,
            ).fetchone()
            if known is None:
                count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM isolated_plugin_quarantine"
                    ).fetchone()[0]
                )
                if count >= _MAX_QUARANTINE_IDENTITIES:
                    raise IsolatedPluginContractError(
                        "plugin quarantine capacity is exhausted"
                    )
            connection.execute(
                """
                INSERT INTO isolated_plugin_quarantine (
                    plugin_id, version, artifact_sha256, reason_code, quarantined_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(plugin_id, version, artifact_sha256) DO NOTHING
                """,
                (*identity, reason_code, int(time.time())),
            )

    def is_quarantined(self, identity: tuple[str, str, str]) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM isolated_plugin_quarantine
                WHERE plugin_id = ? AND version = ? AND artifact_sha256 = ?
                """,
                identity,
            ).fetchone()
        return row is not None

    def quarantined_identities(self) -> tuple[tuple[str, str, str], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT plugin_id, version, artifact_sha256
                FROM isolated_plugin_quarantine
                ORDER BY plugin_id, version, artifact_sha256
                """
            ).fetchall()
        return tuple((str(row[0]), str(row[1]), str(row[2])) for row in rows)


class IsolatedPluginBroker:
    def __init__(
        self,
        launcher: IsolatedPluginLauncher,
        state_store: SQLiteIsolatedPluginStateStore | None = None,
    ) -> None:
        if not hasattr(launcher, "execute"):
            raise TypeError("isolated plugin launcher is invalid")
        self._launcher = launcher
        self._state_store = state_store
        self._quarantined: set[tuple[str, str, str]] = set()

    def quarantined_identities(self) -> tuple[tuple[str, str, str], ...]:
        identities = set(self._quarantined)
        if self._state_store is not None:
            identities.update(self._state_store.quarantined_identities())
        return tuple(sorted(identities))

    def _quarantine(self, identity: tuple[str, str, str], reason_code: str) -> None:
        self._quarantined.add(identity)
        if self._state_store is not None:
            self._state_store.quarantine(identity, reason_code)

    def execute(
        self,
        bundle: VerifiedIsolatedPluginBundle,
        request: Mapping[str, object],
        *,
        output_validator: Callable[[object], object] | None = None,
    ) -> object:
        if output_validator is not None and not callable(output_validator):
            raise TypeError("plugin output validator is invalid")
        identity = bundle.manifest.identity()
        if identity in self._quarantined or (
            self._state_store is not None
            and self._state_store.is_quarantined(identity)
        ):
            raise IsolatedPluginQuarantined("plugin is quarantined")
        request_json = _canonical_json(
            {
                "schema": "nachuan.isolated-plugin.request.v1",
                "input": dict(request),
            }
        )
        if len(request_json) > bundle.manifest.limits.max_request_bytes:
            raise IsolatedPluginContractError("plugin request exceeds its limit")
        try:
            response_bytes = self._launcher.execute(bundle, request_json)
            if not isinstance(response_bytes, bytes) or not 1 <= len(response_bytes) <= bundle.manifest.limits.max_response_bytes:
                raise IsolatedPluginWorkerError("plugin worker response is invalid")
            try:
                response = _parse_canonical_json(
                    response_bytes,
                    "plugin worker response",
                )
            except IsolatedPluginContractError as exc:
                raise IsolatedPluginWorkerError(
                    "plugin worker response is invalid"
                ) from exc
            if not isinstance(response, dict) or set(response) != {"schema", "ok", "output"}:
                raise IsolatedPluginWorkerError("plugin worker response is not closed")
            if response.get("schema") != "nachuan.isolated-plugin.result.v1" or response.get("ok") is not True:
                raise IsolatedPluginWorkerError("plugin worker did not complete")
            output = response.get("output")
            _canonical_json(output)
            if output_validator is not None:
                try:
                    output = output_validator(output)
                except IsolatedPluginContractError:
                    raise
                except Exception as exc:
                    raise IsolatedPluginContractError(
                        "plugin worker output failed trusted validation"
                    ) from exc
                _canonical_json(output)
            return output
        except IsolatedPluginContractError:
            self._quarantine(identity, "contract")
            raise
        except IsolatedPluginWorkerError:
            self._quarantine(identity, "worker")
            raise
        except Exception as exc:
            self._quarantine(identity, "worker")
            raise IsolatedPluginWorkerError("plugin worker failed") from exc


__all__ = [
    "IsolatedPluginBroker",
    "IsolatedPluginContractError",
    "IsolatedPluginError",
    "IsolatedPluginLauncher",
    "IsolatedPluginLimits",
    "IsolatedPluginManifestV1",
    "IsolatedPluginQuarantined",
    "IsolatedPluginRevoked",
    "IsolatedPluginSignatureError",
    "IsolatedPluginWorkerError",
    "SQLiteIsolatedPluginStateStore",
    "VerifiedIsolatedPluginBundle",
    "isolated_plugin_signing_payload",
    "verify_isolated_plugin_bundle",
]
