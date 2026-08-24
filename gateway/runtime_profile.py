"""Versioned runtime capability profiles for source and frozen releases.

The profile is a product boundary, not a convenience feature flag.  A frozen
engine always resolves to ``store`` even if its parent process supplies a
different environment value.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Mapping


RUNTIME_PROFILE_SCHEMA = "nachuan.runtime-profile/v1"
RUNTIME_PROFILE_ENV = "NACHUAN_RUNTIME_PROFILE"
_STORE_PROFILE_MANIFEST_ENV = "NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST"
_STORE_PROFILE_SHA256_ENV = "NACHUAN_STORE_RUNTIME_PROFILE_SHA256"


class RuntimeCapability(StrEnum):
    HTTP_MODEL_PROVIDER = "http-model-provider"
    CONTROLLED_AGENT_EXECUTION = "controlled-agent-execution"
    STUDIO_EXECUTION = "studio-execution"
    HOST_CLI_PROVIDER = "host-cli-provider"
    MCP_PLUGIN_REGISTRY = "mcp-plugin-registry"
    PLUGIN_AUTO_DISCOVERY = "plugin-auto-discovery"
    FORMAL_XREVIEW = "formal-xreview"
    PAGE_AGENT_READ = "page-agent-read"
    PAGE_AGENT_WRITE = "page-agent-write"
    PACKAGED_MEDIA_PROGRAM = "packaged-media-program"
    PACKAGED_LOCAL_MODEL_PROGRAM = "packaged-local-model-program"
    WORKSPACE_FILE_TOOLS = "workspace-file-tools"


class ExternalProgramAuthority(StrEnum):
    FINAL_PAYLOAD_MANIFEST = "final-payload-manifest"
    ATTESTED_HOST_TOOL = "attested-host-tool"


@dataclass(frozen=True)
class RuntimeProfile:
    schema: str
    name: str
    capabilities: frozenset[RuntimeCapability]
    connection_types: frozenset[str]
    provider_types: frozenset[str]
    external_program_authorities: frozenset[ExternalProgramAuthority]
    external_program_roles: frozenset[str]
    frozen_python_excludes: tuple[str, ...]

    def allows(self, capability: RuntimeCapability) -> bool:
        return capability in self.capabilities

    def allows_connection_type(self, provider_type: object) -> bool:
        return str(provider_type or "").strip().casefold() in self.connection_types

    def allows_provider_type(self, provider_type: object) -> bool:
        return str(provider_type or "").strip().casefold() in self.provider_types

    def allows_external_program(
        self,
        *,
        authority: ExternalProgramAuthority,
        role: str,
        manifest_roles: frozenset[str] = frozenset(),
    ) -> bool:
        """Authorize a program only through a profile-owned authority.

        Store roles are additionally required to be present in the caller's
        already verified final payload manifest.  A role name alone never
        grants execution authority.
        """

        normalized_role = str(role or "").strip().casefold()
        if authority not in self.external_program_authorities:
            return False
        if normalized_role not in self.external_program_roles:
            return False
        if authority is ExternalProgramAuthority.FINAL_PAYLOAD_MANIFEST:
            normalized_manifest = frozenset(
                str(item or "").strip().casefold() for item in manifest_roles
            )
            return normalized_role in normalized_manifest
        return True


STORE_RUNTIME_PROFILE_MANIFEST_NAME = "store-runtime-profile.v1.json"
STORE_RUNTIME_PROFILE_MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "config"
    / STORE_RUNTIME_PROFILE_MANIFEST_NAME
)
_STORE_PROFILE_FIELDS = frozenset(
    {
        "capabilities",
        "connectionTypes",
        "externalProgramAuthorities",
        "externalProgramRoles",
        "frozenPythonExcludes",
        "name",
        "providerTypes",
        "schema",
    }
)


def _load_store_runtime_profile() -> RuntimeProfile:
    path = STORE_RUNTIME_PROFILE_MANIFEST_PATH
    try:
        info = path.stat()
        if (
            not path.is_file()
            or path.is_symlink()
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or info.st_size <= 0
            or info.st_size > 64 * 1024
        ):
            raise OSError("profile manifest is not a bounded regular file")
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        if text.startswith("\ufeff") or "\x00" in text:
            raise ValueError("profile manifest is not canonical UTF-8")
        payload = json.loads(text)
        if not isinstance(payload, dict) or set(payload) != _STORE_PROFILE_FIELDS:
            raise ValueError("profile manifest fields are not canonical")

        def strings(name: str) -> list[str]:
            values = payload.get(name)
            if (
                not isinstance(values, list)
                or any(not isinstance(value, str) or not value for value in values)
                or values != sorted(set(values))
            ):
                raise ValueError(f"profile manifest {name} is not a closed sorted set")
            return values

        schema = payload.get("schema")
        name = payload.get("name")
        if schema != RUNTIME_PROFILE_SCHEMA or name != "store":
            raise ValueError("profile manifest identity is unsupported")
        return RuntimeProfile(
            schema=schema,
            name=name,
            capabilities=frozenset(RuntimeCapability(value) for value in strings("capabilities")),
            connection_types=frozenset(strings("connectionTypes")),
            provider_types=frozenset(strings("providerTypes")),
            external_program_authorities=frozenset(
                ExternalProgramAuthority(value)
                for value in strings("externalProgramAuthorities")
            ),
            external_program_roles=frozenset(strings("externalProgramRoles")),
            frozen_python_excludes=tuple(strings("frozenPythonExcludes")),
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid store runtime profile manifest: {path}") from exc


STORE_RUNTIME_PROFILE = _load_store_runtime_profile()


DEVELOPMENT_RUNTIME_PROFILE = RuntimeProfile(
    schema=RUNTIME_PROFILE_SCHEMA,
    name="development",
    capabilities=frozenset(RuntimeCapability),
    connection_types=frozenset(
        {"codex", "kimi_code", "openai_compat", "perplexity", "volcano"}
    ),
    provider_types=frozenset(
        {
            "echo",
            "openai_compat",
            "perplexity",
            "volcano",
            "codex",
            "kimi_code",
        }
    ),
    external_program_authorities=frozenset(ExternalProgramAuthority),
    external_program_roles=frozenset(
        {"ffmpeg", "ffprobe", "llama-server", "host-ai-cli", "operator-tool"}
    ),
    frozen_python_excludes=(),
)


def resolve_runtime_profile(
    *,
    frozen: bool | None = None,
    environment: Mapping[str, str] | None = None,
) -> RuntimeProfile:
    """Resolve the active profile; frozen processes are unconditionally store."""

    is_frozen = bool(getattr(sys, "frozen", False)) if frozen is None else bool(frozen)
    if is_frozen:
        return STORE_RUNTIME_PROFILE
    source = os.environ if environment is None else environment
    selected = str(source.get(RUNTIME_PROFILE_ENV, "development") or "").strip().casefold()
    if selected in {"", "development", "dev", "source"}:
        return DEVELOPMENT_RUNTIME_PROFILE
    if selected == "store":
        return STORE_RUNTIME_PROFILE
    raise RuntimeError(f"unsupported Nachuan runtime profile: {selected}")


def current_runtime_profile() -> RuntimeProfile:
    return resolve_runtime_profile()


def _expected_packaged_profile_path() -> Path:
    return (
        Path(sys.executable).resolve().parent.parent
        / STORE_RUNTIME_PROFILE_MANIFEST_NAME
    ).resolve()


def _verify_frozen_store_profile_binding() -> None:
    raw_path = str(os.environ.get(_STORE_PROFILE_MANIFEST_ENV) or "").strip()
    expected_digest = str(os.environ.get(_STORE_PROFILE_SHA256_ENV) or "").strip().casefold()
    try:
        if not raw_path or not Path(raw_path).is_absolute() or not re.fullmatch(
            r"[0-9a-f]{64}", expected_digest
        ):
            raise OSError("profile binding environment is incomplete")
        packaged_path = Path(raw_path).resolve(strict=True)
        if packaged_path != _expected_packaged_profile_path():
            raise OSError("profile binding path is outside packaged resources")
        info = packaged_path.stat()
        if (
            not packaged_path.is_file()
            or packaged_path.is_symlink()
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or info.st_size <= 0
            or info.st_size > 64 * 1024
        ):
            raise OSError("profile binding is not a bounded regular file")
        packaged_bytes = packaged_path.read_bytes()
        internal_bytes = STORE_RUNTIME_PROFILE_MANIFEST_PATH.read_bytes()
        actual_digest = hashlib.sha256(packaged_bytes).hexdigest()
        if not (
            hmac.compare_digest(actual_digest, expected_digest)
            and hmac.compare_digest(packaged_bytes, internal_bytes)
        ):
            raise ValueError("profile binding bytes differ from the embedded engine policy")
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError(
            "store runtime profile ASAR binding is missing or invalid"
        ) from None


def enforce_frozen_store_profile() -> RuntimeProfile:
    """Pin the inherited environment for child modules and future subprocesses."""

    profile = current_runtime_profile()
    if bool(getattr(sys, "frozen", False)):
        _verify_frozen_store_profile_binding()
        os.environ[RUNTIME_PROFILE_ENV] = STORE_RUNTIME_PROFILE.name
        os.environ["YTDLP_NO_PLUGINS"] = "1"
    return profile


__all__ = [
    "DEVELOPMENT_RUNTIME_PROFILE",
    "ExternalProgramAuthority",
    "RUNTIME_PROFILE_ENV",
    "RUNTIME_PROFILE_SCHEMA",
    "RuntimeCapability",
    "RuntimeProfile",
    "STORE_RUNTIME_PROFILE",
    "STORE_RUNTIME_PROFILE_MANIFEST_NAME",
    "STORE_RUNTIME_PROFILE_MANIFEST_PATH",
    "current_runtime_profile",
    "enforce_frozen_store_profile",
    "resolve_runtime_profile",
]
