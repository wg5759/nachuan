"""One-time import of the legacy Electron connection document.

The legacy Desktop app stored provider credentials under Roaming AppData.  The
pip/Web runtime owns a different Local AppData root.  This module bridges only
the connection document: it never imports usage or paid-media authority state.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from gateway.connections import mark_legacy_desktop_credential_for_reverification
from gateway.secure_store import (
    SecureStorageError,
    write_protected_json_if_absent,
)


_CONNECTIONS_PURPOSE = "nachuan/connections"
_MAX_LEGACY_DOCUMENT_BYTES = 4 * 1024 * 1024
_LEGACY_RELATIVE_PATH = Path("aggregator-desktop") / "data" / "connections.json"
_PROTECTED_ENVELOPE_FIELDS = frozenset({"schema", "protection", "ciphertext"})


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _read_legacy_plaintext_connections(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SecureStorageError("无法读取旧版连接文件元数据") from exc
    reparse_flag = int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    if stat.S_ISLNK(metadata.st_mode) or reparse_flag:
        raise SecureStorageError("拒绝从 reparse 旧版连接路径迁移")
    if not stat.S_ISREG(metadata.st_mode):
        raise SecureStorageError("旧版连接路径不是普通文件")
    if metadata.st_size > _MAX_LEGACY_DOCUMENT_BYTES:
        raise SecureStorageError("旧版连接文件超过安全大小上限")

    try:
        with path.open("rb") as handle:
            opened_before = os.fstat(handle.fileno())
            if _file_identity(opened_before) != _file_identity(metadata):
                raise SecureStorageError("旧版连接路径在打开期间被替换")
            raw = handle.read(_MAX_LEGACY_DOCUMENT_BYTES + 1)
            opened_after = os.fstat(handle.fileno())
    except SecureStorageError:
        raise
    except OSError as exc:
        raise SecureStorageError("无法读取旧版连接文件") from exc
    if len(raw) > _MAX_LEGACY_DOCUMENT_BYTES:
        raise SecureStorageError("旧版连接文件超过安全大小上限")

    try:
        final_metadata = path.lstat()
    except OSError as exc:
        raise SecureStorageError("旧版连接路径在读取期间被替换") from exc
    if (
        _file_identity(opened_after) != _file_identity(opened_before)
        or _file_identity(final_metadata) != _file_identity(opened_before)
        or opened_after.st_size != opened_before.st_size
        or opened_after.st_mtime_ns != opened_before.st_mtime_ns
    ):
        raise SecureStorageError("旧版连接路径在读取期间被替换")

    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SecureStorageError("旧版连接文件损坏，拒绝迁移") from exc
    if not isinstance(document, dict):
        raise SecureStorageError("旧版连接文件根节点必须是 JSON 对象")
    if _PROTECTED_ENVELOPE_FIELDS.intersection(document):
        raise SecureStorageError("旧版连接文件保护格式不受迁移器支持")
    return document


def migrate_legacy_desktop_connections(
    data_dir: str | Path,
    *,
    roaming_app_data: str | Path | None,
) -> bool:
    """Import a legacy plaintext document once into the DPAPI destination.

    Returns ``True`` only when this call created the new protected document.
    Existing destinations are authoritative and are never opened or replaced.
    """

    destination = Path(data_dir) / "connections.json"
    if destination.exists() or roaming_app_data is None:
        return False
    roaming_text = str(roaming_app_data).strip()
    if not roaming_text:
        return False
    source = Path(roaming_text) / _LEGACY_RELATIVE_PATH
    try:
        source.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SecureStorageError("无法检查旧版连接文件") from exc

    document = _read_legacy_plaintext_connections(source)
    migrated: dict[str, Any] = {}
    for provider, connection in document.items():
        if isinstance(provider, str) and isinstance(connection, dict):
            migrated[provider] = mark_legacy_desktop_credential_for_reverification(
                provider,
                connection,
            )
        else:
            migrated[provider] = connection
    return write_protected_json_if_absent(
        destination,
        migrated,
        purpose=_CONNECTIONS_PURPOSE,
    )
