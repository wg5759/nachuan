"""Protected binding for user-owned official subscription CLIs.

The binding is deliberately separate from the CLI's login store.  Nachuan
stores only a native executable path, its SHA-256 digest, and the verified
Authenticode identity.  The official CLI remains the sole owner of login
credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from gateway.providers.attested_cli import (
    AttestedCliPinError,
    file_sha256,
    matches_attestation,
    pin_attested_cli,
)
from gateway.secure_store import (
    SecureStorageError,
    harden_restricted_windows_acl,
    read_protected_json,
    trusted_windows_system_executable,
    write_protected_json,
)
from gateway.subscription_cli_discovery import SubscriptionCliDiscovery


_SCHEMA = "nachuan.subscription-cli-attestations/v1"
_PURPOSE = "nachuan.subscription-cli-attestations/v1"
_FILENAME = "subscription-cli-attestations.json"
_RUNTIME_DIRECTORY = "subscription-cli-runtime"
_KIMI_HOME_DIRECTORY = "subscription-kimi-code-home"
_KIMI_CONNECTOR_ID = "kimi-code"
_KIMI_PLATFORM = "win32-x64"
_KIMI_PROVENANCE = "official_https_manifest_v1"
_KIMI_MANIFEST_MAX_BYTES = 64 * 1024
_KIMI_VERSION = re.compile(r"^0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_KIMI_CHECKSUM = re.compile(r"^[0-9a-f]{64}$")
_KIMI_PLATFORM_FILENAMES = {
    "darwin-arm64": "kimi-code-darwin-arm64",
    "darwin-x64": "kimi-code-darwin-x64",
    "linux-arm64": "kimi-code-linux-arm64",
    "linux-x64": "kimi-code-linux-x64",
    "win32-arm64": "kimi-code-win32-arm64.exe",
    "win32-x64": "kimi-code-win32-x64.exe",
}
_OFFICIAL_CODEX_PUBLISHERS = frozenset(
    {
        "OpenAI OpCo, LLC",
        "OpenAI, L.L.C.",
    }
)
_THUMBPRINT = re.compile(r"^[0-9A-F]{40,128}$")
_AUTHENTICODE_SCRIPT = (
    "& { param([string]$p) "
    "$ErrorActionPreference='Stop'; $PSModuleAutoLoadingPreference='None'; "
    "try {$s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop} "
    "catch {exit 20}; "
    "if($s.Status.ToString() -cne 'Valid' -or "
    "$null -eq $s.SignerCertificate -or "
    "$null -eq $s.TimeStamperCertificate){exit 21}; "
    "$publisher=$s.SignerCertificate.GetNameInfo("
    "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,"
    "$false); "
    "$signer=(([string]$s.SignerCertificate.Thumbprint) "
    "-replace '[^0-9A-Fa-f]','').ToUpperInvariant(); "
    "$timestamp=(([string]$s.TimeStamperCertificate.Thumbprint) "
    "-replace '[^0-9A-Fa-f]','').ToUpperInvariant(); "
    "[pscustomobject]@{publisher=$publisher;signer_thumbprint=$signer;"
    "timestamp_thumbprint=$timestamp} | ConvertTo-Json -Compress; exit 0 }"
)
_NPM_NATIVE_RELATIVE_PATHS = (
    Path(
        "node_modules/@openai/codex/node_modules/@openai/"
        "codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe"
    ),
    Path(
        "node_modules/@openai/codex/node_modules/@openai/"
        "codex-win32-x64/vendor/x86_64-pc-windows-msvc/codex/codex.exe"
    ),
)


class SubscriptionCliConfigError(RuntimeError):
    """Stable failure while binding or loading a subscription CLI."""


@dataclass(frozen=True)
class CodexAuthenticodeIdentity:
    publisher: str
    signer_thumbprint: str
    timestamp_thumbprint: str


@dataclass(frozen=True)
class CodexCliBinding:
    path: str
    sha256: str
    publisher: str
    signer_thumbprint: str
    timestamp_thumbprint: str


@dataclass(frozen=True)
class KimiManifestFetchResult:
    body: bytes
    final_url: str
    redirect_count: int


@dataclass(frozen=True)
class KimiCliBinding:
    path: str
    sha256: str
    provenance: str
    version: str
    platform: str
    filename: str
    manifest_sha256: str


AuthenticodeProbe = Callable[[Path], CodexAuthenticodeIdentity]
KimiManifestFetcher = Callable[[str], KimiManifestFetchResult]


def subscription_cli_config_path(data_dir: str | Path) -> Path:
    return Path(data_dir).expanduser() / _FILENAME


def _path_has_reparse(path: Path) -> bool:
    try:
        for component in reversed((path, *path.parents)):
            info = os.lstat(component)
            attributes = int(getattr(info, "st_file_attributes", 0))
            if component.is_symlink() or (
                attributes
                & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            ):
                return True
    except OSError:
        return True
    return False


def _trusted_powershell() -> tuple[Path, dict[str, str]]:
    if os.name != "nt":
        raise SubscriptionCliConfigError(
            "Codex Authenticode verification requires Windows"
        )
    system32 = trusted_windows_system_executable("whoami.exe").parent
    powershell = system32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    try:
        info = powershell.lstat()
    except OSError as exc:
        raise SubscriptionCliConfigError(
            "trusted Authenticode verifier is unavailable"
        ) from exc
    if (
        not powershell.is_file()
        or powershell.is_symlink()
        or int(getattr(info, "st_file_attributes", 0)) & 0x400
        or _path_has_reparse(powershell)
    ):
        raise SubscriptionCliConfigError(
            "trusted Authenticode verifier is unavailable"
        )
    system_root = str(system32.parent)
    environment = {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "ComSpec": str(trusted_windows_system_executable("cmd.exe")),
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        "POWERSHELL_UPDATECHECK": "Off",
    }
    return powershell, environment


def _default_authenticode_probe(path: Path) -> CodexAuthenticodeIdentity:
    powershell, environment = _trusted_powershell()
    try:
        result = subprocess.run(
            (
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _AUTHENTICODE_SCRIPT,
                str(path),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=60.0,
            check=False,
            shell=False,
            env=environment,
            creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise SubscriptionCliConfigError(
            "Codex Authenticode signature verification failed"
        ) from exc
    if (
        result.returncode != 0
        or result.stderr
        or not result.stdout
        or len(result.stdout.encode("utf-8")) > 4096
    ):
        raise SubscriptionCliConfigError(
            "Codex Authenticode signature verification failed"
        )
    try:
        document = json.loads(result.stdout)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SubscriptionCliConfigError(
            "Codex Authenticode signature verification failed"
        ) from exc
    if not isinstance(document, dict) or set(document) != {
        "publisher",
        "signer_thumbprint",
        "timestamp_thumbprint",
    }:
        raise SubscriptionCliConfigError(
            "Codex Authenticode signature verification failed"
        )
    return CodexAuthenticodeIdentity(
        publisher=str(document["publisher"]),
        signer_thumbprint=str(document["signer_thumbprint"]),
        timestamp_thumbprint=str(document["timestamp_thumbprint"]),
    )


def _validated_identity(identity: object) -> CodexAuthenticodeIdentity:
    if not isinstance(identity, CodexAuthenticodeIdentity):
        raise SubscriptionCliConfigError(
            "Codex Authenticode signature metadata is invalid"
        )
    publisher = identity.publisher.strip()
    signer = identity.signer_thumbprint.strip().upper()
    timestamp = identity.timestamp_thumbprint.strip().upper()
    if publisher not in _OFFICIAL_CODEX_PUBLISHERS:
        raise SubscriptionCliConfigError(
            "Codex Authenticode publisher is not an approved OpenAI identity"
        )
    if not _THUMBPRINT.fullmatch(signer) or not _THUMBPRINT.fullmatch(timestamp):
        raise SubscriptionCliConfigError(
            "Codex Authenticode signature metadata is invalid"
        )
    return CodexAuthenticodeIdentity(
        publisher=publisher,
        signer_thumbprint=signer,
        timestamp_thumbprint=timestamp,
    )


def _empty_document() -> dict[str, object]:
    return {"schema": _SCHEMA, "connectors": {}}


def _kimi_manifest_url(version: str, *, host: str = "code.kimi.com") -> str:
    return (
        f"https://{host}/kimi-code/binaries/{version}/manifest.json"
    )


def _validated_kimi_version(version: object) -> str:
    if not isinstance(version, str) or not _KIMI_VERSION.fullmatch(version):
        raise SubscriptionCliConfigError(
            "Kimi CLI version must be a strict 0.x.y semantic version"
        )
    return version


def _validated_kimi_receipt(receipt: object) -> dict[str, object]:
    expected = {
        "path",
        "sha256",
        "provenance",
        "version",
        "platform",
        "filename",
        "manifest_url",
        "manifest_final_url",
        "manifest_redirect_count",
        "manifest_sha256",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise SubscriptionCliConfigError(
            "protected Kimi CLI binding is malformed"
        )
    path = receipt.get("path")
    digest = receipt.get("sha256")
    provenance = receipt.get("provenance")
    version = _validated_kimi_version(receipt.get("version"))
    platform = receipt.get("platform")
    filename = receipt.get("filename")
    manifest_url = receipt.get("manifest_url")
    manifest_final_url = receipt.get("manifest_final_url")
    redirect_count = receipt.get("manifest_redirect_count")
    manifest_digest = receipt.get("manifest_sha256")
    expected_url = _kimi_manifest_url(version)
    expected_cdn_url = _kimi_manifest_url(version, host="cdn.kimi.com")
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or len(path) > 32_768
        or not isinstance(digest, str)
        or not _KIMI_CHECKSUM.fullmatch(digest)
        or provenance != _KIMI_PROVENANCE
        or platform != _KIMI_PLATFORM
        or filename != _KIMI_PLATFORM_FILENAMES[_KIMI_PLATFORM]
        or manifest_url != expected_url
        or not isinstance(redirect_count, int)
        or isinstance(redirect_count, bool)
        or (
            (manifest_final_url, redirect_count)
            not in {(expected_url, 0), (expected_cdn_url, 1)}
        )
        or not isinstance(manifest_digest, str)
        or not _KIMI_CHECKSUM.fullmatch(manifest_digest)
    ):
        raise SubscriptionCliConfigError(
            "protected Kimi CLI binding is malformed"
        )
    return {
        "path": path,
        "sha256": digest,
        "provenance": provenance,
        "version": version,
        "platform": platform,
        "filename": filename,
        "manifest_url": manifest_url,
        "manifest_final_url": manifest_final_url,
        "manifest_redirect_count": redirect_count,
        "manifest_sha256": manifest_digest,
    }


def _validated_document(document: object) -> dict[str, object]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "connectors"}
        or document.get("schema") != _SCHEMA
        or not isinstance(document.get("connectors"), dict)
    ):
        raise SubscriptionCliConfigError(
            "protected subscription CLI binding has an unsupported schema"
        )
    connectors = document["connectors"]
    assert isinstance(connectors, dict)
    if set(connectors) - {"codex", _KIMI_CONNECTOR_ID}:
        raise SubscriptionCliConfigError(
            "protected subscription CLI binding contains an unknown connector"
        )
    validated_connectors: dict[str, object] = {}
    codex = connectors.get("codex")
    if codex is not None:
        expected = {
            "path",
            "sha256",
            "publisher",
            "signer_thumbprint",
            "timestamp_thumbprint",
        }
        if not isinstance(codex, dict) or set(codex) != expected:
            raise SubscriptionCliConfigError(
                "protected Codex CLI binding is malformed"
            )
        path = str(codex.get("path") or "")
        digest = str(codex.get("sha256") or "").lower()
        identity = _validated_identity(
            CodexAuthenticodeIdentity(
                publisher=str(codex.get("publisher") or ""),
                signer_thumbprint=str(codex.get("signer_thumbprint") or ""),
                timestamp_thumbprint=str(codex.get("timestamp_thumbprint") or ""),
            )
        )
        if (
            not Path(path).is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or len(path) > 32_768
        ):
            raise SubscriptionCliConfigError(
                "protected Codex CLI binding is malformed"
            )
        validated_connectors["codex"] = {
            "path": path,
            "sha256": digest,
            "publisher": identity.publisher,
            "signer_thumbprint": identity.signer_thumbprint,
            "timestamp_thumbprint": identity.timestamp_thumbprint,
        }
    if _KIMI_CONNECTOR_ID in connectors:
        validated_connectors[_KIMI_CONNECTOR_ID] = _validated_kimi_receipt(
            connectors[_KIMI_CONNECTOR_ID]
        )
    return {"schema": _SCHEMA, "connectors": validated_connectors}


def _read_document(data_dir: str | Path) -> dict[str, object]:
    path = subscription_cli_config_path(data_dir)
    if not path.exists():
        return _empty_document()
    try:
        document = read_protected_json(path, purpose=_PURPOSE)
    except (OSError, SecureStorageError) as exc:
        raise SubscriptionCliConfigError(
            "protected subscription CLI binding cannot be read"
        ) from exc
    return _validated_document(document)


def bind_codex_subscription_cli(
    data_dir: str | Path,
    executable_path: str | Path,
    *,
    authenticode_probe: AuthenticodeProbe | None = None,
) -> CodexCliBinding:
    lead = Path(executable_path).expanduser()
    if not lead.is_absolute():
        raise SubscriptionCliConfigError("Codex CLI path must be absolute")
    try:
        executable = lead.resolve(strict=True)
        digest = file_sha256(executable)
    except OSError as exc:
        raise SubscriptionCliConfigError("Codex CLI executable is unavailable") from exc
    if not matches_attestation(str(executable), digest):
        raise SubscriptionCliConfigError(
            "Codex CLI executable is not a native non-reparse file"
        )
    descriptor = SubscriptionCliDiscovery(
        environment={
            "CODEX_CLI_PATH": str(executable),
            "CODEX_CLI_SHA256": digest,
        }
    ).list_public()[0]
    if descriptor.get("state") != "installed_unprobed":
        raise SubscriptionCliConfigError(
            "Codex CLI executable is not a supported native PE"
        )
    probe = authenticode_probe or _default_authenticode_probe
    try:
        with pin_attested_cli(executable, digest):
            identity = _validated_identity(probe(executable))
    except AttestedCliPinError as exc:
        raise SubscriptionCliConfigError(
            "Codex CLI executable changed during signature verification"
        ) from exc

    binding = CodexCliBinding(
        path=str(executable),
        sha256=digest,
        publisher=identity.publisher,
        signer_thumbprint=identity.signer_thumbprint,
        timestamp_thumbprint=identity.timestamp_thumbprint,
    )
    document = _read_document(data_dir)
    connectors = dict(document["connectors"])  # type: ignore[arg-type]
    connectors["codex"] = {
        "path": binding.path,
        "sha256": binding.sha256,
        "publisher": binding.publisher,
        "signer_thumbprint": binding.signer_thumbprint,
        "timestamp_thumbprint": binding.timestamp_thumbprint,
    }
    try:
        write_protected_json(
            subscription_cli_config_path(data_dir),
            {"schema": _SCHEMA, "connectors": connectors},
            purpose=_PURPOSE,
        )
    except (OSError, SecureStorageError) as exc:
        raise SubscriptionCliConfigError(
            "protected Codex CLI binding cannot be written"
        ) from exc
    return binding


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _reject_json_constant(_value: str) -> object:
    raise ValueError("non-standard JSON constant")


def _validated_kimi_manifest(
    result: object,
    *,
    requested_url: str,
    requested_version: str,
    executable_sha256: str,
) -> tuple[str, str, int, str]:
    if not isinstance(result, KimiManifestFetchResult):
        raise SubscriptionCliConfigError(
            "Kimi official manifest fetch result is invalid"
        )
    expected_cdn_url = _kimi_manifest_url(
        requested_version,
        host="cdn.kimi.com",
    )
    if (
        not isinstance(result.final_url, str)
        or not isinstance(result.redirect_count, int)
        or isinstance(result.redirect_count, bool)
        or (
            (result.final_url, result.redirect_count)
            not in {(requested_url, 0), (expected_cdn_url, 1)}
        )
    ):
        raise SubscriptionCliConfigError(
            "Kimi official manifest URL or redirect chain is untrusted"
        )
    body = result.body
    if (
        not isinstance(body, bytes)
        or not body
        or len(body) > _KIMI_MANIFEST_MAX_BYTES
        or body.startswith(b"\xef\xbb\xbf")
    ):
        raise SubscriptionCliConfigError(
            "Kimi official manifest body is invalid"
        )
    try:
        text = body.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SubscriptionCliConfigError(
            "Kimi official manifest is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(document, dict) or set(document) != {
        "version",
        "tag",
        "platforms",
    }:
        raise SubscriptionCliConfigError(
            "Kimi official manifest schema is invalid"
        )
    manifest_version = document.get("version")
    if (
        not isinstance(manifest_version, str)
        or manifest_version != requested_version
        or document.get("tag")
        != f"@moonshot-ai/kimi-code@{requested_version}"
    ):
        raise SubscriptionCliConfigError(
            "Kimi official manifest version or tag does not match"
        )
    platforms = document.get("platforms")
    if (
        not isinstance(platforms, dict)
        or set(platforms) != set(_KIMI_PLATFORM_FILENAMES)
    ):
        raise SubscriptionCliConfigError(
            "Kimi official manifest platform schema is invalid"
        )
    for platform, expected_filename in _KIMI_PLATFORM_FILENAMES.items():
        entry = platforms.get(platform)
        if (
            not isinstance(entry, dict)
            or set(entry) != {"filename", "checksum"}
            or entry.get("filename") != expected_filename
        ):
            raise SubscriptionCliConfigError(
                "Kimi official manifest platform entry is invalid"
            )
        checksum = entry.get("checksum")
        if not isinstance(checksum, str) or not _KIMI_CHECKSUM.fullmatch(checksum):
            raise SubscriptionCliConfigError(
                "Kimi official manifest checksum metadata is invalid"
            )
    selected = platforms[_KIMI_PLATFORM]
    assert isinstance(selected, dict)
    selected_checksum = str(selected["checksum"])
    if not hmac.compare_digest(selected_checksum, executable_sha256):
        raise SubscriptionCliConfigError(
            "Kimi CLI checksum does not match the official manifest"
        )
    return (
        result.final_url,
        result.redirect_count,
        hashlib.sha256(body).hexdigest(),
        str(selected["filename"]),
    )


def bind_kimi_subscription_cli(
    data_dir: str | Path,
    executable_path: str | Path,
    *,
    version: str,
    manifest_fetcher: KimiManifestFetcher,
) -> KimiCliBinding:
    requested_version = _validated_kimi_version(version)
    if not callable(manifest_fetcher):
        raise SubscriptionCliConfigError(
            "Kimi official manifest fetcher is required"
        )
    lead = Path(executable_path).expanduser()
    if not lead.is_absolute():
        raise SubscriptionCliConfigError("Kimi CLI path must be absolute")
    try:
        executable = lead.resolve(strict=True)
        digest = file_sha256(executable)
    except OSError as exc:
        raise SubscriptionCliConfigError("Kimi CLI executable is unavailable") from exc
    if not matches_attestation(str(executable), digest):
        raise SubscriptionCliConfigError(
            "Kimi CLI executable is not a native non-reparse file"
        )
    descriptor = next(
        item
        for item in SubscriptionCliDiscovery(
            environment={
                "KIMI_CLI_PATH": str(executable),
                "KIMI_CLI_SHA256": digest,
            }
        ).list_public()
        if item.get("id") == _KIMI_CONNECTOR_ID
    )
    if descriptor.get("state") != "installed_unprobed":
        raise SubscriptionCliConfigError(
            "Kimi CLI executable is not a supported native PE"
        )

    manifest_url = _kimi_manifest_url(requested_version)
    try:
        with pin_attested_cli(executable, digest):
            try:
                fetch_result = manifest_fetcher(manifest_url)
            except Exception as exc:
                raise SubscriptionCliConfigError(
                    "Kimi official manifest could not be fetched"
                ) from exc
            (
                manifest_final_url,
                manifest_redirect_count,
                manifest_digest,
                filename,
            ) = _validated_kimi_manifest(
                fetch_result,
                requested_url=manifest_url,
                requested_version=requested_version,
                executable_sha256=digest,
            )
    except AttestedCliPinError as exc:
        raise SubscriptionCliConfigError(
            "Kimi CLI executable changed during manifest verification"
        ) from exc

    binding = KimiCliBinding(
        path=str(executable),
        sha256=digest,
        provenance=_KIMI_PROVENANCE,
        version=requested_version,
        platform=_KIMI_PLATFORM,
        filename=filename,
        manifest_sha256=manifest_digest,
    )
    document = _read_document(data_dir)
    connectors = dict(document["connectors"])  # type: ignore[arg-type]
    connectors[_KIMI_CONNECTOR_ID] = {
        "path": binding.path,
        "sha256": binding.sha256,
        "provenance": binding.provenance,
        "version": binding.version,
        "platform": binding.platform,
        "filename": binding.filename,
        "manifest_url": manifest_url,
        "manifest_final_url": manifest_final_url,
        "manifest_redirect_count": manifest_redirect_count,
        "manifest_sha256": binding.manifest_sha256,
    }
    try:
        write_protected_json(
            subscription_cli_config_path(data_dir),
            {"schema": _SCHEMA, "connectors": connectors},
            purpose=_PURPOSE,
        )
    except (OSError, SecureStorageError) as exc:
        raise SubscriptionCliConfigError(
            "protected Kimi CLI binding cannot be written"
        ) from exc
    return binding


def _autodiscovery_leads(environment: Mapping[str, str]) -> list[Path]:
    leads: list[Path] = []
    explicit_lead = str(environment.get("CODEX_CLI_PATH") or "").strip()
    if explicit_lead:
        leads.append(Path(explicit_lead))
    app_data = str(environment.get("APPDATA") or "").strip()
    if app_data:
        npm_root = Path(app_data) / "npm"
        leads.extend(npm_root / relative for relative in _NPM_NATIVE_RELATIVE_PATHS)
    unique: list[Path] = []
    seen: set[str] = set()
    for lead in leads:
        key = os.path.normcase(os.path.abspath(str(lead)))
        if key not in seen:
            seen.add(key)
            unique.append(lead)
    return unique


def discover_and_bind_codex_subscription_cli(
    data_dir: str | Path,
    executable_path: str | Path | None,
    *,
    environment: Mapping[str, str],
    authenticode_probe: AuthenticodeProbe | None = None,
) -> CodexCliBinding:
    if executable_path is not None:
        return bind_codex_subscription_cli(
            data_dir,
            executable_path,
            authenticode_probe=authenticode_probe,
        )
    for lead in _autodiscovery_leads(environment):
        try:
            resolved = lead.expanduser().resolve(strict=True)
        except OSError:
            continue
        try:
            return bind_codex_subscription_cli(
                data_dir,
                resolved,
                authenticode_probe=authenticode_probe,
            )
        except SubscriptionCliConfigError:
            continue
    raise SubscriptionCliConfigError(
        "official Codex CLI was not found; install it or pass --path"
    )


def load_subscription_cli_environment(data_dir: str | Path) -> dict[str, str]:
    document = _read_document(data_dir)
    connectors = document["connectors"]
    assert isinstance(connectors, dict)
    codex = connectors.get("codex")
    kimi = connectors.get(_KIMI_CONNECTOR_ID)
    if not isinstance(codex, dict) and not isinstance(kimi, dict):
        return {}
    runtime_root = Path(data_dir).expanduser() / _RUNTIME_DIRECTORY
    try:
        runtime_root.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            harden_restricted_windows_acl(runtime_root, directory=True)
        runtime_root = runtime_root.resolve(strict=True)
    except (OSError, SecureStorageError) as exc:
        raise SubscriptionCliConfigError(
            "protected subscription CLI runtime directory is unavailable"
        ) from exc
    environment: dict[str, str] = {}
    if isinstance(codex, dict):
        environment.update(
            {
                "CODEX_CLI_PATH": str(codex["path"]),
                "CODEX_CLI_SHA256": str(codex["sha256"]),
                "CODEX_CLI_TEMP_ROOT": str(runtime_root),
            }
        )
    if isinstance(kimi, dict):
        kimi_temp_root = runtime_root / _KIMI_CONNECTOR_ID
        kimi_home = Path(data_dir).expanduser() / _KIMI_HOME_DIRECTORY
        try:
            kimi_temp_root.mkdir(parents=True, exist_ok=True)
            kimi_home.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                harden_restricted_windows_acl(kimi_temp_root, directory=True)
                harden_restricted_windows_acl(kimi_home, directory=True)
            kimi_temp_root = kimi_temp_root.resolve(strict=True)
            kimi_home = kimi_home.resolve(strict=True)
        except (OSError, SecureStorageError) as exc:
            raise SubscriptionCliConfigError(
                "protected Kimi CLI isolation directories are unavailable"
            ) from exc
        environment.update(
            {
                "KIMI_CLI_PATH": str(kimi["path"]),
                "KIMI_CLI_SHA256": str(kimi["sha256"]),
                "KIMI_CLI_VERSION": str(kimi["version"]),
                "KIMI_CLI_TEMP_ROOT": str(kimi_temp_root),
                "KIMI_CODE_HOME": str(kimi_home),
                "KIMI_DISABLE_TELEMETRY": "1",
                "KIMI_CODE_NO_AUTO_UPDATE": "1",
            }
        )
    return environment


def unbind_codex_subscription_cli(data_dir: str | Path) -> bool:
    document = _read_document(data_dir)
    connectors = dict(document["connectors"])  # type: ignore[arg-type]
    if "codex" not in connectors:
        return False
    del connectors["codex"]
    try:
        write_protected_json(
            subscription_cli_config_path(data_dir),
            {"schema": _SCHEMA, "connectors": connectors},
            purpose=_PURPOSE,
        )
    except (OSError, SecureStorageError) as exc:
        raise SubscriptionCliConfigError(
            "protected Codex CLI binding cannot be written"
        ) from exc
    return True


def unbind_kimi_subscription_cli(data_dir: str | Path) -> bool:
    document = _read_document(data_dir)
    connectors = dict(document["connectors"])  # type: ignore[arg-type]
    if _KIMI_CONNECTOR_ID not in connectors:
        return False
    del connectors[_KIMI_CONNECTOR_ID]
    try:
        write_protected_json(
            subscription_cli_config_path(data_dir),
            {"schema": _SCHEMA, "connectors": connectors},
            purpose=_PURPOSE,
        )
    except (OSError, SecureStorageError) as exc:
        raise SubscriptionCliConfigError(
            "protected Kimi CLI binding cannot be written"
        ) from exc
    return True


__all__ = [
    "CodexAuthenticodeIdentity",
    "CodexCliBinding",
    "KimiCliBinding",
    "KimiManifestFetchResult",
    "SubscriptionCliConfigError",
    "bind_codex_subscription_cli",
    "bind_kimi_subscription_cli",
    "discover_and_bind_codex_subscription_cli",
    "load_subscription_cli_environment",
    "subscription_cli_config_path",
    "unbind_codex_subscription_cli",
    "unbind_kimi_subscription_cli",
]
