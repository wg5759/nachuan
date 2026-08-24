"""One-command local Web bootstrap for the pip-installed Nachuan CLI.

The owner credentials are stable DPAPI-protected values.  They are injected
only into the in-process Engine and printed to the owner's interactive terminal
for the Web login gate; they never enter argv, a URL, or an application log.
"""

from __future__ import annotations

import os
import re
import secrets
import socket
import threading
import time
import webbrowser
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

import httpx

from gateway.secure_store import (
    SecureStorageError,
    read_protected_json,
    write_protected_json_if_absent,
)


_SCHEMA = "nachuan.local-owner-credentials/v1"
_PURPOSE = _SCHEMA
_FILENAME = "local-owner-credentials.json"
_PAID_SCHEMA = "nachuan.local-paid-media-capability/v1"
_PAID_PURPOSE = _PAID_SCHEMA
_PAID_FILENAME = "local-paid-media-capability.json"
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,86}")
_RUNTIME_PATTERN = re.compile(r"nc-runtime-v1-[A-Za-z0-9_-]{43,86}")
_APPROVAL_PATTERN = re.compile(r"nc-approval-v1-[A-Za-z0-9_-]{43,86}")
_PAID_PATTERN = re.compile(r"sk-paid-media-[0-9a-f]{64}")
_ENVIRONMENT_NAMES = (
    "GATEWAY_API_KEYS",
    "APPROVAL_ADMIN_KEY",
    "NACHUAN_PAID_MEDIA_API_KEY",
    "NACHUAN_GATEWAY_KEY",
    "GATEWAY_HOST",
    "GATEWAY_PORT",
)


class LocalOwnerCredentialError(RuntimeError):
    """The protected single-owner credential document is unavailable."""


class LocalWebStartError(RuntimeError):
    """The local Engine cannot be started safely."""


class LocalPaidMediaCapabilityError(RuntimeError):
    """The protected single-owner paid capability is unavailable."""


@dataclass(frozen=True)
class LocalOwnerCredentials:
    runtime_key: str
    approval_key: str
    created: bool


@dataclass(frozen=True)
class LocalPaidMediaCapability:
    key: str = field(repr=False)
    created: bool


ReadDocument = Callable[..., Mapping[str, Any]]
CreateDocument = Callable[..., bool]


def local_owner_credentials_path(data_dir: str | Path) -> Path:
    return Path(data_dir).expanduser() / _FILENAME


def local_paid_media_capability_path(data_dir: str | Path) -> Path:
    return Path(data_dir).expanduser() / _PAID_FILENAME


def _validate_document(
    document: Mapping[str, Any],
    *,
    created: bool,
) -> LocalOwnerCredentials:
    if not isinstance(document, Mapping) or set(document) != {
        "schema",
        "runtime_key",
        "approval_key",
    }:
        raise LocalOwnerCredentialError(
            "protected local owner credentials have an invalid field set"
        )
    if document.get("schema") != _SCHEMA:
        raise LocalOwnerCredentialError(
            "protected local owner credentials have an unsupported schema"
        )
    runtime_key = document.get("runtime_key")
    approval_key = document.get("approval_key")
    if (
        not isinstance(runtime_key, str)
        or _RUNTIME_PATTERN.fullmatch(runtime_key) is None
        or not isinstance(approval_key, str)
        or _APPROVAL_PATTERN.fullmatch(approval_key) is None
        or runtime_key == approval_key
    ):
        raise LocalOwnerCredentialError(
            "protected local owner credentials are malformed"
        )
    return LocalOwnerCredentials(
        runtime_key=runtime_key,
        approval_key=approval_key,
        created=created,
    )


def _read_document(
    path: Path,
    reader: ReadDocument,
) -> Mapping[str, Any]:
    try:
        return reader(path, purpose=_PURPOSE)
    except FileNotFoundError:
        raise
    except (SecureStorageError, OSError, TypeError, ValueError) as exc:
        raise LocalOwnerCredentialError(
            "protected local owner credentials cannot be read"
        ) from exc


def load_local_owner_credentials(
    data_dir: str | Path,
    *,
    read_document: ReadDocument = read_protected_json,
) -> LocalOwnerCredentials:
    document = _read_document(local_owner_credentials_path(data_dir), read_document)
    return _validate_document(document, created=False)


def load_or_create_local_owner_credentials(
    data_dir: str | Path,
    *,
    read_document: ReadDocument = read_protected_json,
    create_document: CreateDocument = write_protected_json_if_absent,
    token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
) -> LocalOwnerCredentials:
    """Load the stable owner credentials or atomically create them once."""

    path = local_owner_credentials_path(data_dir)
    try:
        return load_local_owner_credentials(data_dir, read_document=read_document)
    except FileNotFoundError:
        pass

    try:
        runtime_token = token_factory()
        approval_token = token_factory()
    except Exception as exc:  # noqa: BLE001 - entropy ambiguity fails closed
        raise LocalOwnerCredentialError(
            "local owner credential generation failed"
        ) from exc
    if (
        not isinstance(runtime_token, str)
        or _TOKEN_PATTERN.fullmatch(runtime_token) is None
        or not isinstance(approval_token, str)
        or _TOKEN_PATTERN.fullmatch(approval_token) is None
        or runtime_token == approval_token
    ):
        raise LocalOwnerCredentialError(
            "local owner credential generator returned invalid entropy"
        )

    candidate = {
        "schema": _SCHEMA,
        "runtime_key": f"nc-runtime-v1-{runtime_token}",
        "approval_key": f"nc-approval-v1-{approval_token}",
    }
    _validate_document(candidate, created=True)
    try:
        created = bool(create_document(path, candidate, purpose=_PURPOSE))
    except (SecureStorageError, OSError, TypeError, ValueError) as exc:
        raise LocalOwnerCredentialError(
            "protected local owner credentials cannot be created"
        ) from exc

    # The read-back is authoritative for both successful creation and a
    # concurrent create-if-absent winner.
    document = _read_document(path, read_document)
    return _validate_document(document, created=created)


def _validate_paid_document(
    document: Mapping[str, Any],
    *,
    created: bool,
) -> LocalPaidMediaCapability:
    if not isinstance(document, Mapping) or set(document) != {"schema", "key"}:
        raise LocalPaidMediaCapabilityError(
            "protected local paid capability has an invalid field set"
        )
    if document.get("schema") != _PAID_SCHEMA:
        raise LocalPaidMediaCapabilityError(
            "protected local paid capability has an unsupported schema"
        )
    key = document.get("key")
    if not isinstance(key, str) or _PAID_PATTERN.fullmatch(key) is None:
        raise LocalPaidMediaCapabilityError(
            "protected local paid capability is malformed"
        )
    return LocalPaidMediaCapability(key=key, created=created)


def _read_paid_document(
    path: Path,
    reader: ReadDocument,
) -> Mapping[str, Any]:
    try:
        return reader(path, purpose=_PAID_PURPOSE)
    except FileNotFoundError:
        raise
    except (SecureStorageError, OSError, TypeError, ValueError) as exc:
        raise LocalPaidMediaCapabilityError(
            "protected local paid capability cannot be read"
        ) from exc


def load_local_paid_media_capability(
    data_dir: str | Path,
    *,
    read_document: ReadDocument = read_protected_json,
) -> LocalPaidMediaCapability:
    document = _read_paid_document(
        local_paid_media_capability_path(data_dir),
        read_document,
    )
    return _validate_paid_document(document, created=False)


def load_or_create_local_paid_media_capability(
    data_dir: str | Path,
    *,
    read_document: ReadDocument = read_protected_json,
    create_document: CreateDocument = write_protected_json_if_absent,
    token_factory: Callable[[], str] = lambda: secrets.token_hex(32),
) -> LocalPaidMediaCapability:
    """Load the stable engine-only paid capability or atomically create it once."""

    path = local_paid_media_capability_path(data_dir)
    try:
        return load_local_paid_media_capability(
            data_dir,
            read_document=read_document,
        )
    except FileNotFoundError:
        pass

    try:
        token = token_factory()
    except Exception as exc:  # noqa: BLE001 - entropy ambiguity fails closed
        raise LocalPaidMediaCapabilityError(
            "local paid capability generation failed"
        ) from exc
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise LocalPaidMediaCapabilityError(
            "local paid capability generator returned invalid entropy"
        )

    candidate = {
        "schema": _PAID_SCHEMA,
        "key": f"sk-paid-media-{token}",
    }
    _validate_paid_document(candidate, created=True)
    try:
        created = bool(create_document(path, candidate, purpose=_PAID_PURPOSE))
    except (SecureStorageError, OSError, TypeError, ValueError) as exc:
        raise LocalPaidMediaCapabilityError(
            "protected local paid capability cannot be created"
        ) from exc

    document = _read_paid_document(path, read_document)
    return _validate_paid_document(document, created=created)


def _assert_loopback_port_available(port: int) -> None:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise LocalWebStartError("local Web port is invalid")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(("127.0.0.1", port))
    except OSError as exc:
        raise LocalWebStartError(
            f"127.0.0.1:{port} is already in use; refusing to start a second Engine"
        ) from exc
    finally:
        probe.close()


def _open_when_ready(base_url: str) -> None:
    health_url = f"{base_url}/health"
    with httpx.Client(timeout=1.0, trust_env=False) as client:
        for _attempt in range(120):
            try:
                response = client.get(health_url)
            except httpx.HTTPError:
                response = None
            if response is not None and response.status_code == 200:
                webbrowser.open(f"{base_url}/")
                return
            time.sleep(0.25)


def _restore_environment(
    environment: MutableMapping[str, str],
    previous: Mapping[str, tuple[bool, str]],
) -> None:
    for name, (present, value) in previous.items():
        if present:
            environment[name] = value
        else:
            environment.pop(name, None)


def serve_local_web(
    credentials: LocalOwnerCredentials,
    paid_capability: LocalPaidMediaCapability,
    *,
    data_dir: str | Path,
    port: int,
    open_browser: bool,
    out: TextIO,
    environment: MutableMapping[str, str] | None = None,
    engine_main: Callable[[], None] | None = None,
    port_guard: Callable[[int], None] = _assert_loopback_port_available,
) -> int:
    """Run the packaged Engine in-process until the user stops the command."""

    if not isinstance(credentials, LocalOwnerCredentials):
        raise LocalWebStartError("local owner credentials are invalid")
    if (
        not isinstance(paid_capability, LocalPaidMediaCapability)
        or _PAID_PATTERN.fullmatch(paid_capability.key) is None
        or paid_capability.key in {credentials.runtime_key, credentials.approval_key}
    ):
        raise LocalWebStartError("local paid capability is invalid")
    port_guard(port)
    target_environment = os.environ if environment is None else environment
    previous = {
        name: (name in target_environment, str(target_environment.get(name, "")))
        for name in _ENVIRONMENT_NAMES
    }
    target_environment.update(
        {
            "GATEWAY_API_KEYS": credentials.runtime_key,
            "APPROVAL_ADMIN_KEY": credentials.approval_key,
            "NACHUAN_PAID_MEDIA_API_KEY": paid_capability.key,
            "NACHUAN_GATEWAY_KEY": credentials.runtime_key,
            "GATEWAY_HOST": "127.0.0.1",
            "GATEWAY_PORT": str(port),
        }
    )
    base_url = f"http://127.0.0.1:{port}"
    credential_path = local_owner_credentials_path(data_dir)
    out.write(f"纳川本地 Web：{base_url}/\n")
    out.write(f"运行时 Key：{credentials.runtime_key}\n")
    out.write(f"审批 Key：{credentials.approval_key}\n")
    out.write(f"DPAPI 受保护凭据：{credential_path}\n")
    out.write("首次打开或新标签页时录入以上两项；密钥不会进入浏览器地址。\n")
    out.write("保持本窗口运行；按 Ctrl+C 停止纳川。\n")
    out.flush()

    if open_browser:
        threading.Thread(
            target=_open_when_ready,
            args=(base_url,),
            name="nachuan-local-web-opener",
            daemon=True,
        ).start()

    try:
        if engine_main is None:
            from cli.engine_entrypoint import main as engine_main

        engine_main()
    except KeyboardInterrupt:
        pass
    finally:
        _restore_environment(target_environment, previous)
    return 0


__all__ = [
    "LocalOwnerCredentialError",
    "LocalOwnerCredentials",
    "LocalPaidMediaCapability",
    "LocalPaidMediaCapabilityError",
    "LocalWebStartError",
    "load_local_paid_media_capability",
    "load_local_owner_credentials",
    "load_or_create_local_paid_media_capability",
    "load_or_create_local_owner_credentials",
    "local_paid_media_capability_path",
    "local_owner_credentials_path",
    "serve_local_web",
]
