"""Secret-free discovery for explicitly attested subscription CLI binaries.

This module does not search ``PATH``, inspect login stores, or launch a model.
It is deliberately usable through an injected version probe so that the
eventual isolated worker can own process execution.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from gateway.providers.attested_cli import matches_attestation


@dataclass(frozen=True)
class VersionProbeRequest:
    """Internal-only request handed to the isolated version-probe adapter."""

    connector_id: str
    executable_path: str = field(repr=False)
    executable_sha256: str = field(repr=False)
    argv: tuple[str, ...] = ("--version",)


@dataclass(frozen=True)
class VersionProbeResult:
    """Raw worker result; only a parsed semantic version may become public."""

    returncode: int
    stdout: str
    stderr: str


class VersionProbe(Protocol):
    def __call__(self, request: VersionProbeRequest) -> VersionProbeResult: ...


@dataclass(frozen=True)
class _ConnectorSpec:
    connector_id: str
    label: str
    path_variable: str
    hash_variable: str
    transport: str
    minimum_version: tuple[int, int, int]
    logout_supported: bool
    version_pattern: re.Pattern[str]


_CONNECTORS = (
    _ConnectorSpec(
        connector_id="codex",
        label="Codex",
        path_variable="CODEX_CLI_PATH",
        hash_variable="CODEX_CLI_SHA256",
        transport="stdio_jsonl",
        minimum_version=(0, 144, 0),
        logout_supported=True,
        version_pattern=re.compile(
            r"^\s*(?:codex-cli|codex)\s+(?:version\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)",
            re.IGNORECASE,
        ),
    ),
    _ConnectorSpec(
        connector_id="kimi-code",
        label="Kimi Code",
        path_variable="KIMI_CLI_PATH",
        hash_variable="KIMI_CLI_SHA256",
        transport="acp_stdio",
        minimum_version=(0, 27, 0),
        logout_supported=False,
        version_pattern=re.compile(
            r"^\s*(?:kimi(?:\s+code(?:\s+cli)?)?\s+(?:version\s+)?)?"
            r"v?([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)",
            re.IGNORECASE,
        ),
    ),
)
_SCRIPT_SUFFIXES = frozenset({".bat", ".cmd", ".ps1", ".py", ".js", ".sh"})


def _public_descriptor(
    spec: _ConnectorSpec,
    *,
    state: str,
    version: str | None,
) -> dict[str, object]:
    return {
        "id": spec.connector_id,
        "label": spec.label,
        "state": state,
        "auth": "device_code",
        "transport": spec.transport,
        "version": version,
        "capabilities": ["chat", "code"],
        "login_supported": True,
        "logout_supported": spec.logout_supported,
    }


def _is_native_executable(path: Path) -> bool:
    if path.suffix.lower() in _SCRIPT_SUFFIXES:
        return False
    if path.suffix.lower() != ".exe":
        return False
    try:
        with path.open("rb") as executable:
            dos_header = executable.read(64)
            if len(dos_header) != 64 or dos_header[:2] != b"MZ":
                return False
            pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
            if pe_offset < 64 or pe_offset > 16 * 1024 * 1024:
                return False
            executable.seek(pe_offset)
            return executable.read(4) == b"PE\0\0"
    except (OSError, struct.error):
        return False


def _parse_version(
    spec: _ConnectorSpec,
    result: VersionProbeResult,
) -> tuple[str, tuple[int, int, int]] | None:
    if not isinstance(result, VersionProbeResult) or result.returncode != 0:
        return None
    match = spec.version_pattern.search(str(result.stdout or "")[:4096])
    if match is None:
        return None
    public_version = match.group(1)
    parsed = tuple(int(part) for part in public_version.split("."))
    return public_version, parsed  # type: ignore[return-value]


class SubscriptionCliDiscovery:
    """List only public connector metadata from explicit binary attestations.

    ``environment`` is mandatory on purpose.  A caller must supply values from
    its protected launcher/configuration boundary; ambient user-controlled
    environment variables are not, by themselves, a formal trust root.
    """

    def __init__(
        self,
        *,
        environment: Mapping[str, str],
        version_probe: VersionProbe | None = None,
    ) -> None:
        self._environment = dict(environment)
        self._version_probe = version_probe

    def list_public(self) -> list[dict[str, object]]:
        return [self._discover(spec) for spec in _CONNECTORS]

    def _discover(self, spec: _ConnectorSpec) -> dict[str, object]:
        raw_path = str(self._environment.get(spec.path_variable) or "").strip()
        expected_sha256 = str(self._environment.get(spec.hash_variable) or "").strip().lower()
        if not raw_path and not expected_sha256:
            return _public_descriptor(spec, state="not_installed", version=None)
        if (
            not raw_path
            or not expected_sha256
            or not matches_attestation(raw_path, expected_sha256)
            or not _is_native_executable(Path(raw_path))
        ):
            return _public_descriptor(spec, state="untrusted_binary", version=None)
        if self._version_probe is None:
            return _public_descriptor(spec, state="installed_unprobed", version=None)
        request = VersionProbeRequest(
            connector_id=spec.connector_id,
            executable_path=str(Path(raw_path).resolve(strict=True)),
            executable_sha256=expected_sha256,
        )
        try:
            parsed = _parse_version(spec, self._version_probe(request))
        except Exception:
            parsed = None
        if parsed is None:
            return _public_descriptor(spec, state="unavailable", version=None)
        public_version, version_tuple = parsed
        if version_tuple < spec.minimum_version:
            return _public_descriptor(
                spec,
                state="version_unsupported",
                version=public_version,
            )
        return _public_descriptor(
            spec,
            state="installed_unprobed",
            version=public_version,
        )


__all__ = [
    "SubscriptionCliDiscovery",
    "VersionProbe",
    "VersionProbeRequest",
    "VersionProbeResult",
]
