"""Durable, principal-owned byte archive for pure-Web paid-media delivery.

The provider asset store is an execution authority with a deliberately large
per-operation reservation.  Browser delivery must therefore copy the complete
closed result into this smaller content-addressed archive before ACKing that
authority.  Raw capability tokens are never persisted here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from gateway.paid_media_asset_protocol import (
    MAX_ASSET_BYTES,
    PaidMediaAssetDescriptor,
    PaidMediaAssetResult,
)
from gateway.installation_root import DEFAULT_DEPENDENCIES


DEFAULT_WEB_ARCHIVE_CAPACITY_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_WEB_ARCHIVE_MAX_DOCUMENTS = 100_000
DEFAULT_WEB_ARCHIVE_MAX_MEMBERS = 400_000
_SQLITE_PAGE_SIZE = 4_096
_SQLITE_MAX_PAGE_COUNT = 131_072
_SQLITE_MAX_DATABASE_BYTES = _SQLITE_PAGE_SIZE * _SQLITE_MAX_PAGE_COUNT
_APPLICATION_ID = 0x4E435741  # "NCWA"
_SCHEMA_VERSION = 3
_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-paid-media-web-byte-archive-schema-v3-metadata-capacity"
).hexdigest()
_V2_SCHEMA_VERSION = 2
_V2_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-paid-media-web-byte-archive-schema-v2-cleanup-pending"
).hexdigest()
_LEGACY_SCHEMA_VERSION = 1
_LEGACY_SCHEMA_FINGERPRINT = hashlib.sha256(
    b"nachuan-paid-media-web-byte-archive-schema-v1"
).hexdigest()
_RECEIPT_DOMAIN = b"nachuan-paid-media-web-byte-archive-receipt-v1\x00"
_OBJECT_DOMAIN = b"nachuan-paid-media-web-byte-archive-object-v1\x00"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_INSTALLATION_ID_RE = _DIGEST_RE
_OPERATIONS = frozenset({"images.create", "videos.create"})
_MEDIA_TYPES = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp", "video/mp4", "video/webm"}
)
_OBJECT_RE = re.compile(r"^[0-9a-f]{64}\.asset$")
_LOCK_MAGIC = b"nachuan-paid-media-web-archive-lock-v1\r\n"
_LOCK_WAIT_SECONDS = 120.0
_SQLITE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")

_META_DDL = """
CREATE TABLE web_asset_archive_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=3),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64),
    stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),
    max_capacity_bytes INTEGER NOT NULL CHECK(max_capacity_bytes>=1),
    document_count INTEGER NOT NULL CHECK(document_count>=0),
    max_documents INTEGER NOT NULL CHECK(max_documents>=1),
    member_count INTEGER NOT NULL CHECK(member_count>=0),
    max_members INTEGER NOT NULL CHECK(max_members>=1),
    cleanup_pending INTEGER NOT NULL CHECK(cleanup_pending IN (0,1))
) WITHOUT ROWID
"""

_V2_META_DDL = """
CREATE TABLE web_asset_archive_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=2),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64),
    stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),
    max_capacity_bytes INTEGER NOT NULL CHECK(max_capacity_bytes>=1),
    cleanup_pending INTEGER NOT NULL CHECK(cleanup_pending IN (0,1))
) WITHOUT ROWID
"""

_LEGACY_META_DDL = """
CREATE TABLE web_asset_archive_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    schema_fingerprint TEXT NOT NULL CHECK(length(schema_fingerprint)=64),
    stored_bytes INTEGER NOT NULL CHECK(stored_bytes>=0),
    max_capacity_bytes INTEGER NOT NULL CHECK(max_capacity_bytes>=1)
) WITHOUT ROWID
"""

_OBJECTS_DDL = """
CREATE TABLE web_asset_archive_objects (
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    asset_sha256 TEXT NOT NULL CHECK(
        length(asset_sha256)=64 AND asset_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    media_type TEXT NOT NULL CHECK(media_type IN (
        'image/png','image/jpeg','image/gif','image/webp','video/mp4','video/webm'
    )),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 25165824),
    object_leaf TEXT NOT NULL UNIQUE CHECK(length(object_leaf)=70),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
    PRIMARY KEY(principal_hash,asset_sha256)
) WITHOUT ROWID
"""

_DOCUMENTS_DDL = """
CREATE TABLE web_asset_archive_documents (
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    installation_id TEXT NOT NULL CHECK(
        length(installation_id)=64 AND installation_id NOT GLOB '*[^0-9a-f]*'
    ),
    installation_epoch INTEGER NOT NULL CHECK(installation_epoch>=1),
    archive_receipt_sha256 TEXT NOT NULL CHECK(
        length(archive_receipt_sha256)=64
        AND archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    completed_at_ms INTEGER NOT NULL CHECK(completed_at_ms>=0),
    PRIMARY KEY(principal_hash,turn_id)
) WITHOUT ROWID
"""

_MEMBERS_DDL = """
CREATE TABLE web_asset_archive_members (
    principal_hash TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
    asset_sha256 TEXT NOT NULL,
    PRIMARY KEY(principal_hash,turn_id,ordinal),
    FOREIGN KEY(principal_hash,turn_id)
        REFERENCES web_asset_archive_documents(principal_hash,turn_id)
        ON DELETE CASCADE,
    FOREIGN KEY(principal_hash,asset_sha256)
        REFERENCES web_asset_archive_objects(principal_hash,asset_sha256)
) WITHOUT ROWID
"""

_EXPECTED_SCHEMA = {
    ("table", "web_asset_archive_documents"): _DOCUMENTS_DDL,
    ("table", "web_asset_archive_members"): _MEMBERS_DDL,
    ("table", "web_asset_archive_meta"): _META_DDL,
    ("table", "web_asset_archive_objects"): _OBJECTS_DDL,
}
_LEGACY_EXPECTED_SCHEMA = {
    **_EXPECTED_SCHEMA,
    ("table", "web_asset_archive_meta"): _LEGACY_META_DDL,
}
_V2_EXPECTED_SCHEMA = {
    **_EXPECTED_SCHEMA,
    ("table", "web_asset_archive_meta"): _V2_META_DDL,
}


class PaidMediaWebArchiveUnavailable(RuntimeError):
    """The Web byte archive cannot prove an exact durable result."""


@dataclass(frozen=True, slots=True)
class ArchivedPaidMediaWebAsset:
    payload: bytes
    media_type: str
    byte_length: int
    sha256: str


@dataclass(slots=True)
class _PaidMediaWebDocumentBatch:
    archive: "PaidMediaWebAssetArchive"
    principal_hash: str
    result: PaidMediaAssetResult
    installation_id: str
    installation_epoch: int
    now_ms: int
    committed_receipt: str | None = None

    def store_asset(self, *, asset: PaidMediaAssetDescriptor, payload: bytes) -> None:
        if self.committed_receipt is not None or asset not in self.result.assets:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive document batch asset is invalid"
            )
        self.archive._store_asset_locked(
            principal_hash=self.principal_hash,
            asset=asset,
            payload=payload,
            now_ms=self.now_ms,
            preserve_cleanup_pending=True,
        )

    def commit(self) -> str:
        if self.committed_receipt is not None:
            return self.committed_receipt
        self.committed_receipt = self.archive._commit_document_locked(
            principal_hash=self.principal_hash,
            result=self.result,
            installation_id=self.installation_id,
            installation_epoch=self.installation_epoch,
            now_ms=self.now_ms,
        )
        return self.committed_receipt


def _normalized_sql(value: object) -> str:
    return " ".join(str(value or "").split())


def _digest(value: object, label: str) -> str:
    result = str(value or "")
    if _DIGEST_RE.fullmatch(result) is None or result == "0" * 64:
        raise PaidMediaWebArchiveUnavailable(f"{label} is invalid")
    return result


def _operation_for(result: PaidMediaAssetResult) -> str:
    return "images.create" if result.kind == "image" else "videos.create"


def _receipt_document(
    *,
    principal_hash: str,
    result: PaidMediaAssetResult,
    installation_id: str,
    installation_epoch: int,
) -> dict[str, object]:
    return {
        "schema": "nachuan.paid-media-web-byte-archive.v1",
        "principalHash": principal_hash,
        "turnId": result.turn_id,
        "operation": _operation_for(result),
        "installationId": installation_id,
        "installationEpoch": installation_epoch,
        "assets": [
            {
                "ordinal": ordinal,
                "mediaType": asset.media_type,
                "byteLength": asset.byte_length,
                "sha256": asset.sha256,
            }
            for ordinal, asset in enumerate(result.assets)
        ],
    }


def _receipt_digest(**kwargs: object) -> str:
    encoded = json.dumps(
        _receipt_document(**kwargs),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(_RECEIPT_DOMAIN + encoded).hexdigest()


def paid_media_web_archive_receipt_sha256(
    *,
    principal_hash: str,
    result: PaidMediaAssetResult,
    installation_id: str,
    installation_epoch: int,
) -> str:
    """Return the exact validated receipt later committed by the archive."""

    principal = _digest(principal_hash, "principal_hash")
    installation = _digest(installation_id, "installation_id")
    if (
        isinstance(installation_epoch, bool)
        or not isinstance(installation_epoch, int)
        or installation_epoch < 1
    ):
        raise PaidMediaWebArchiveUnavailable("installation_epoch is invalid")
    if not isinstance(result, PaidMediaAssetResult):
        raise PaidMediaWebArchiveUnavailable("Web archive result is invalid")
    return _receipt_digest(
        principal_hash=principal,
        result=result,
        installation_id=installation,
        installation_epoch=installation_epoch,
    )


class PaidMediaWebAssetArchive:
    """SQLite receipt authority plus atomically committed content objects."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        max_capacity_bytes: int = DEFAULT_WEB_ARCHIVE_CAPACITY_BYTES,
        max_documents: int = DEFAULT_WEB_ARCHIVE_MAX_DOCUMENTS,
        max_members: int = DEFAULT_WEB_ARCHIVE_MAX_MEMBERS,
    ) -> None:
        if (
            isinstance(max_capacity_bytes, bool)
            or not isinstance(max_capacity_bytes, int)
            or max_capacity_bytes < MAX_ASSET_BYTES
        ):
            raise ValueError("Web archive capacity is invalid")
        for value, label in (
            (max_documents, "document"),
            (max_members, "member"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
                or value > 2_147_483_647
            ):
                raise ValueError(f"Web archive {label} capacity is invalid")
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.object_directory = self.root / "objects"
        self.database_path = self.root / "archive.db"
        self.lock_path = self.root / ".archive-authority.lock"
        self._lock = threading.RLock()
        self._fence_lock = threading.RLock()
        self._fence_local = threading.local()
        self._cleanup_debt = False
        self._closed = False
        self._assert_existing_ancestor_chain(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_existing_ancestor_chain(self.root)
        self._assert_directory(self.root)
        self._prepare_lock_file()
        with self._authority_fence():
            self._harden_directory(self.root)
            self.object_directory.mkdir(parents=True, exist_ok=True)
            self._harden_directory(self.object_directory)
            with self._connect() as connection:
                self._initialize(
                    connection,
                    max_capacity_bytes=max_capacity_bytes,
                    max_documents=max_documents,
                    max_members=max_members,
                )
            self._recover_uncommitted_objects_locked()

    def _prepare_lock_file(self) -> None:
        if os.name == "nt":
            descriptor = self._create_windows_lock_descriptor()
            if descriptor is None:
                return
        else:
            try:
                descriptor = os.open(
                    self.lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                return
            except OSError as exc:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive authority lock cannot be created"
                ) from exc
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except BaseException:
                os.close(descriptor)
                raise
        try:
            if os.name == "nt":
                from gateway.secure_store import (
                    assert_restricted_windows_handle_acl,
                    harden_restricted_windows_handle_acl,
                )

                harden_restricted_windows_handle_acl(descriptor, directory=False)
                assert_restricted_windows_handle_acl(descriptor, directory=False)
            else:
                os.fchmod(descriptor, 0o600)
            view = memoryview(_LOCK_MAGIC)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Web archive lock receipt write failed")
                view = view[written:]
            os.fsync(descriptor)
        except Exception as exc:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive authority lock initialization failed"
            ) from exc
        finally:
            os.close(descriptor)

    def _create_windows_lock_descriptor(self) -> int | None:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        invalid = ctypes.c_void_p(-1).value
        handle = kernel32.CreateFileW(
            str(self.lock_path),
            0x80000000  # GENERIC_READ
            | 0x40000000  # GENERIC_WRITE
            | 0x00020000  # READ_CONTROL
            | 0x00040000  # WRITE_DAC
            | 0x00080000,  # WRITE_OWNER
            0,
            None,
            1,  # CREATE_NEW
            0x80 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
            None,
        )
        if handle in (None, invalid):
            error = ctypes.get_last_error()
            if error in {32, 33, 80, 183}:
                # Existing receipt may be share-none owned.  All validation is
                # deferred to the common acquire loop and its exact handle.
                return None
            raise PaidMediaWebArchiveUnavailable(
                "Web archive authority lock cannot be created"
            ) from ctypes.WinError(error)
        try:
            return msvcrt.open_osfhandle(
                int(handle), os.O_RDWR | int(getattr(os, "O_BINARY", 0))
            )
        except BaseException:
            kernel32.CloseHandle(handle)
            raise

    @contextmanager
    def _authority_fence(self) -> Iterator[None]:
        """Cross-process, crash-released fence for recovery and archive I/O."""

        with self._fence_lock:
            self._assert_existing_ancestor_chain(self.root)
            self._assert_directory(self.root)
            depth = int(getattr(self._fence_local, "depth", 0))
            if depth:
                self._fence_local.depth = depth + 1
                try:
                    yield
                finally:
                    self._fence_local.depth = depth
                return
            try:
                descriptor = self._acquire_lock_descriptor()
            except PaidMediaWebArchiveUnavailable:
                raise
            except Exception as exc:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive authority lock is unavailable"
                ) from exc
            self._fence_local.depth = 1
            try:
                yield
                try:
                    path_info = self._assert_plain_file(self.lock_path)
                    handle_info = os.fstat(descriptor)
                    replaced = (
                        path_info.st_dev != handle_info.st_dev
                        or path_info.st_ino != handle_info.st_ino
                    )
                except Exception as exc:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive authority lock identity is unavailable"
                    ) from exc
                if replaced:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive authority lock was replaced"
                    )
            finally:
                self._fence_local.depth = 0
                os.close(descriptor)

    def _acquire_lock_descriptor(self) -> int:
        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            kernel32.CreateFileW.restype = wintypes.HANDLE
            invalid = ctypes.c_void_p(-1).value
            while True:
                handle = kernel32.CreateFileW(
                    str(self.lock_path),
                    0x80000000  # GENERIC_READ
                    | 0x40000000  # GENERIC_WRITE
                    | 0x00020000  # READ_CONTROL
                    | 0x00040000  # WRITE_DAC
                    | 0x00080000,  # WRITE_OWNER
                    0,  # no sharing: mandatory across processes and aliases
                    None,
                    3,  # OPEN_EXISTING
                    0x80 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
                    None,
                )
                if handle not in (None, invalid):
                    try:
                        descriptor = msvcrt.open_osfhandle(
                            int(handle), os.O_RDWR | int(getattr(os, "O_BINARY", 0))
                        )
                    except BaseException:
                        kernel32.CloseHandle(handle)
                        raise
                    break
                error = ctypes.get_last_error()
                if error not in {32, 33} or time.monotonic() >= deadline:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive authority lock is unavailable"
                    )
                time.sleep(0.01)
        else:
            import fcntl

            flags = os.O_RDWR | int(getattr(os, "O_NOFOLLOW", 0))
            descriptor = os.open(self.lock_path, flags)
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        os.close(descriptor)
                        raise PaidMediaWebArchiveUnavailable(
                            "Web archive authority lock timed out"
                        )
                    time.sleep(0.01)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or self._is_reparse(info)
                or info.st_nlink != 1
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive authority lock handle is unsafe"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            receipt = os.read(descriptor, len(_LOCK_MAGIC) + 1)
            if receipt != _LOCK_MAGIC:
                if not self._repair_torn_lock_for_empty_archive(descriptor):
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive authority lock receipt is invalid"
                    )
            DEFAULT_DEPENDENCIES.assert_acl(self.lock_path, False)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _repair_torn_lock_for_empty_archive(self, descriptor: int) -> bool:
        """Repair only a first-create crash with no archive authority yet."""

        if self._entry_exists(self.database_path):
            return False
        if self._entry_exists(self.object_directory):
            self._assert_directory(self.object_directory)
            if next(self.object_directory.iterdir(), None) is not None:
                return False
        if os.name == "nt":
            from gateway.secure_store import (
                assert_restricted_windows_handle_acl,
                harden_restricted_windows_handle_acl,
            )

            harden_restricted_windows_handle_acl(descriptor, directory=False)
            assert_restricted_windows_handle_acl(descriptor, directory=False)
        else:
            os.fchmod(descriptor, 0o600)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        view = memoryview(_LOCK_MAGIC)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive authority lock repair failed"
                )
            view = view[written:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.read(descriptor, len(_LOCK_MAGIC) + 1) != _LOCK_MAGIC:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive authority lock repair was not durable"
            )
        return True

    @staticmethod
    def _is_reparse(info: os.stat_result) -> bool:
        flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return bool(int(getattr(info, "st_file_attributes", 0)) & flag)

    @staticmethod
    def _entry_exists(path: Path) -> bool:
        """Directory-entry existence that does not follow dangling links."""

        try:
            path.lstat()
            return True
        except FileNotFoundError:
            return False

    @classmethod
    def _assert_existing_ancestor_chain(cls, path: Path) -> None:
        """Reject link/reparse traversal from the absolute volume anchor."""

        absolute = Path(os.path.abspath(os.fspath(path)))
        anchor = Path(absolute.anchor)
        if not absolute.is_absolute() or not anchor.anchor:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive path has no trusted volume anchor"
            )
        current = anchor
        for component in absolute.parts[len(anchor.parts) :]:
            current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                return
            if (
                stat.S_ISLNK(info.st_mode)
                or cls._is_reparse(info)
                or not stat.S_ISDIR(info.st_mode)
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive ancestor chain is unsafe"
                )

    @classmethod
    def _assert_directory(cls, path: Path) -> None:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or cls._is_reparse(info)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_nlink < 1
        ):
            raise PaidMediaWebArchiveUnavailable("Web archive directory is unsafe")

    @classmethod
    def _harden_directory(cls, path: Path) -> None:
        cls._assert_directory(path)
        if os.name != "nt":
            os.chmod(path, 0o700)
        DEFAULT_DEPENDENCIES.harden_acl(path, True)
        DEFAULT_DEPENDENCIES.assert_acl(path, True)

    @classmethod
    def _assert_plain_file(cls, path: Path) -> os.stat_result:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or cls._is_reparse(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise PaidMediaWebArchiveUnavailable("Web archive object is unsafe")
        return info

    @classmethod
    def _harden_file(cls, path: Path) -> os.stat_result:
        info = cls._assert_plain_file(path)
        if os.name != "nt":
            os.chmod(path, 0o600)
        DEFAULT_DEPENDENCIES.harden_acl(path, False)
        DEFAULT_DEPENDENCIES.assert_acl(path, False)
        return cls._assert_plain_file(path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._closed:
            raise PaidMediaWebArchiveUnavailable("Web archive is closed")
        try:
            self._assert_existing_ancestor_chain(self.root)
            self._assert_directory(self.root)
            self._assert_directory(self.object_directory)
            self._preflight_sqlite_family()
            database_identity = self._ensure_database_placeholder()
            connection = sqlite3.connect(str(self.database_path), timeout=10.0)
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            if page_count == 0:
                connection.execute(f"PRAGMA page_size={_SQLITE_PAGE_SIZE}")
                page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
                if page_size != _SQLITE_PAGE_SIZE:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive database page size is unavailable"
                    )
            elif page_size > _SQLITE_PAGE_SIZE:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive database page size exceeds its byte capacity"
                )
            if page_count > _SQLITE_MAX_PAGE_COUNT:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive database page capacity is exceeded"
                )
            applied_page_cap = connection.execute(
                f"PRAGMA max_page_count={_SQLITE_MAX_PAGE_COUNT}"
            ).fetchone()
            if (
                applied_page_cap is None
                or int(applied_page_cap[0]) != _SQLITE_MAX_PAGE_COUNT
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive database page capacity is unavailable"
                )
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
            connection.commit()
        except PaidMediaWebArchiveUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaWebArchiveUnavailable("Web archive transaction failed") from exc
        finally:
            if "connection" in locals():
                connection.close()
            if "database_identity" in locals():
                after = self._harden_file(self.database_path)
                if (
                    after.st_dev != database_identity.st_dev
                    or after.st_ino != database_identity.st_ino
                ):
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive database identity changed"
                    )
                self._preflight_sqlite_sidecars()

    def _sqlite_sidecar_paths(self) -> tuple[Path, ...]:
        return tuple(
            Path(str(self.database_path) + suffix)
            for suffix in _SQLITE_SIDECAR_SUFFIXES
        )

    def _preflight_sqlite_sidecars(self) -> None:
        for path in self._sqlite_sidecar_paths():
            if self._entry_exists(path):
                self._harden_file(path)

    def _preflight_sqlite_family(self) -> None:
        if self._entry_exists(self.database_path):
            self._harden_file(self.database_path)
        self._preflight_sqlite_sidecars()

    def _ensure_database_placeholder(self) -> os.stat_result:
        if self._entry_exists(self.database_path):
            return self._harden_file(self.database_path)
        descriptor = self._create_secure_plain_file(self.database_path)
        if descriptor is None:
            # CREATE_NEW reported an existing directory entry.  lstat must now
            # classify it; a dangling link never reaches sqlite3.connect.
            return self._harden_file(self.database_path)
        try:
            os.fsync(descriptor)
            return os.fstat(descriptor)
        finally:
            os.close(descriptor)

    def _create_secure_plain_file(self, path: Path) -> int | None:
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes
            from gateway.secure_store import (
                assert_restricted_windows_handle_acl,
                harden_restricted_windows_handle_acl,
            )

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            kernel32.CreateFileW.restype = wintypes.HANDLE
            invalid = ctypes.c_void_p(-1).value
            handle = kernel32.CreateFileW(
                str(path),
                0x80000000
                | 0x40000000
                | 0x00020000
                | 0x00040000
                | 0x00080000,
                0,
                None,
                1,  # CREATE_NEW
                0x80 | 0x00200000,
                None,
            )
            if handle in (None, invalid):
                error = ctypes.get_last_error()
                if error in {80, 183}:
                    return None
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive database placeholder cannot be created"
                ) from ctypes.WinError(error)
            try:
                descriptor = msvcrt.open_osfhandle(
                    int(handle), os.O_RDWR | int(getattr(os, "O_BINARY", 0))
                )
            except BaseException:
                kernel32.CloseHandle(handle)
                raise
            try:
                harden_restricted_windows_handle_acl(descriptor, directory=False)
                assert_restricted_windows_handle_acl(descriptor, directory=False)
                return descriptor
            except BaseException:
                os.close(descriptor)
                raise
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | int(getattr(os, "O_NOFOLLOW", 0))
        )
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return None
        os.fchmod(descriptor, 0o600)
        return descriptor

    def _initialize(
        self,
        connection: sqlite3.Connection,
        *,
        max_capacity_bytes: int,
        max_documents: int,
        max_members: int,
    ) -> None:
        connection.execute("BEGIN IMMEDIATE")
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        objects = connection.execute(
            "SELECT type,name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        if not objects:
            if application_id != 0 or user_version != 0:
                raise PaidMediaWebArchiveUnavailable("Web archive identity conflicts")
            for ddl in (_META_DDL, _OBJECTS_DDL, _DOCUMENTS_DDL, _MEMBERS_DDL):
                connection.execute(ddl)
            connection.execute(
                "INSERT INTO web_asset_archive_meta "
                "VALUES(1,3,?,0,?,0,?,0,?,0)",
                (
                    _SCHEMA_FINGERPRINT,
                    max_capacity_bytes,
                    max_documents,
                    max_members,
                ),
            )
            connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive foreign keys are corrupt"
                )
            return
        actual = {
            (str(kind), str(name)): _normalized_sql(sql)
            for kind, name, sql in objects
        }
        expected = {key: _normalized_sql(sql) for key, sql in _EXPECTED_SCHEMA.items()}
        legacy_expected = {
            key: _normalized_sql(sql) for key, sql in _LEGACY_EXPECTED_SCHEMA.items()
        }
        v2_expected = {
            key: _normalized_sql(sql) for key, sql in _V2_EXPECTED_SCHEMA.items()
        }
        stored_recorded = int(
            connection.execute(
                "SELECT COALESCE(SUM(byte_length),0) "
                "FROM web_asset_archive_objects"
            ).fetchone()[0]
        )
        document_recorded = int(
            connection.execute(
                "SELECT COUNT(*) FROM web_asset_archive_documents"
            ).fetchone()[0]
        )
        member_recorded = int(
            connection.execute(
                "SELECT COUNT(*) FROM web_asset_archive_members"
            ).fetchone()[0]
        )
        foreign_key_failure = (
            connection.execute("PRAGMA foreign_key_check").fetchone() is not None
        )
        if (
            application_id == _APPLICATION_ID
            and user_version == _LEGACY_SCHEMA_VERSION
            and actual == legacy_expected
        ):
            legacy_meta = connection.execute(
                "SELECT schema_version,schema_fingerprint,stored_bytes,"
                "max_capacity_bytes FROM web_asset_archive_meta WHERE singleton=1"
            ).fetchone()
            if (
                legacy_meta is None
                or legacy_meta[0:2]
                != (_LEGACY_SCHEMA_VERSION, _LEGACY_SCHEMA_FINGERPRINT)
                or int(legacy_meta[2]) != stored_recorded
                or int(legacy_meta[3]) != max_capacity_bytes
                or document_recorded > max_documents
                or member_recorded > max_members
                or foreign_key_failure
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Legacy Web archive schema is not exact"
                )
            connection.execute(
                "ALTER TABLE web_asset_archive_meta "
                "RENAME TO web_asset_archive_meta_v1"
            )
            connection.execute(_META_DDL)
            connection.execute(
                "INSERT INTO web_asset_archive_meta "
                "VALUES(1,3,?,?,?,?,?,?,?,?)",
                (
                    _SCHEMA_FINGERPRINT,
                    int(legacy_meta[2]),
                    int(legacy_meta[3]),
                    document_recorded,
                    max_documents,
                    member_recorded,
                    max_members,
                    1,
                ),
            )
            connection.execute("DROP TABLE web_asset_archive_meta_v1")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            return
        if (
            application_id == _APPLICATION_ID
            and user_version == _V2_SCHEMA_VERSION
            and actual == v2_expected
        ):
            v2_meta = connection.execute(
                "SELECT schema_version,schema_fingerprint,stored_bytes,"
                "max_capacity_bytes,cleanup_pending "
                "FROM web_asset_archive_meta WHERE singleton=1"
            ).fetchone()
            if (
                v2_meta is None
                or v2_meta[0:2] != (_V2_SCHEMA_VERSION, _V2_SCHEMA_FINGERPRINT)
                or int(v2_meta[2]) != stored_recorded
                or int(v2_meta[3]) != max_capacity_bytes
                or int(v2_meta[4]) not in (0, 1)
                or document_recorded > max_documents
                or member_recorded > max_members
                or foreign_key_failure
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Version 2 Web archive schema is not exact"
                )
            connection.execute(
                "ALTER TABLE web_asset_archive_meta "
                "RENAME TO web_asset_archive_meta_v2"
            )
            connection.execute(_META_DDL)
            connection.execute(
                "INSERT INTO web_asset_archive_meta "
                "VALUES(1,3,?,?,?,?,?,?,?,?)",
                (
                    _SCHEMA_FINGERPRINT,
                    stored_recorded,
                    max_capacity_bytes,
                    document_recorded,
                    max_documents,
                    member_recorded,
                    max_members,
                    int(v2_meta[4]),
                ),
            )
            connection.execute("DROP TABLE web_asset_archive_meta_v2")
            connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            return
        meta = connection.execute(
            "SELECT schema_version,schema_fingerprint,stored_bytes,max_capacity_bytes,"
            "document_count,max_documents,member_count,max_members,cleanup_pending "
            "FROM web_asset_archive_meta WHERE singleton=1"
        ).fetchone()
        if (
            application_id != _APPLICATION_ID
            or user_version != _SCHEMA_VERSION
            or actual != expected
            or meta is None
            or meta[0:2] != (_SCHEMA_VERSION, _SCHEMA_FINGERPRINT)
            or int(meta[3]) != max_capacity_bytes
            or int(meta[5]) != max_documents
            or int(meta[7]) != max_members
            or int(meta[8]) not in (0, 1)
        ):
            raise PaidMediaWebArchiveUnavailable("Web archive schema is not exact")
        if int(meta[2]) != stored_recorded:
            raise PaidMediaWebArchiveUnavailable("Web archive capacity receipt is corrupt")
        if int(meta[4]) != document_recorded or int(meta[6]) != member_recorded:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive metadata capacity receipt is corrupt"
            )
        if document_recorded > max_documents or member_recorded > max_members:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive metadata capacity is exhausted"
            )
        if foreign_key_failure:
            raise PaidMediaWebArchiveUnavailable("Web archive foreign keys are corrupt")

    def _recover_uncommitted_objects(self) -> None:
        with self._authority_fence():
            self._recover_uncommitted_objects_locked()

    def _cleanup_pending_locked(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cleanup_pending FROM web_asset_archive_meta WHERE singleton=1"
            ).fetchone()
        if row is None or int(row[0]) not in (0, 1):
            raise PaidMediaWebArchiveUnavailable(
                "Web archive cleanup receipt is corrupt"
            )
        return bool(row[0])

    def _set_cleanup_pending_locked(self, pending: bool) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE web_asset_archive_meta SET cleanup_pending=? WHERE singleton=1",
                (1 if pending else 0,),
            )
            if updated.rowcount != 1:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive cleanup receipt is missing"
                )
        self._cleanup_debt = pending

    def _recover_uncommitted_objects_locked(self) -> None:
        try:
            # Persist the dirty receipt before recovery changes either database
            # authority or object files.  A crash leaves the next instance a
            # shared signal to repeat the idempotent recovery.
            self._set_cleanup_pending_locked(True)
            self._recover_uncommitted_objects_once()
            self._set_cleanup_pending_locked(False)
        except PaidMediaWebArchiveUnavailable:
            self._cleanup_debt = True
            raise
        except Exception as exc:
            self._cleanup_debt = True
            raise PaidMediaWebArchiveUnavailable(
                "Web archive cleanup debt could not be recovered"
            ) from exc

    def _recover_uncommitted_objects_once(self) -> None:
        """Discard only partial objects that no complete document owns.

        Database authority is reduced before file deletion.  A crash between
        those steps therefore leaves an unknown file that the next startup can
        safely remove, never an accounted row whose bytes have disappeared.
        """

        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            orphan_rows = connection.execute(
                "SELECT o.object_leaf,o.byte_length "
                "FROM web_asset_archive_objects o "
                "LEFT JOIN web_asset_archive_members m "
                "ON m.principal_hash=o.principal_hash "
                "AND m.asset_sha256=o.asset_sha256 "
                "WHERE m.asset_sha256 IS NULL"
            ).fetchall()
            if orphan_rows:
                connection.execute(
                    "DELETE FROM web_asset_archive_objects WHERE NOT EXISTS ("
                    "SELECT 1 FROM web_asset_archive_members m "
                    "WHERE m.principal_hash=web_asset_archive_objects.principal_hash "
                    "AND m.asset_sha256=web_asset_archive_objects.asset_sha256)"
                )
                connection.execute(
                    "UPDATE web_asset_archive_meta SET stored_bytes=stored_bytes-? "
                    "WHERE singleton=1",
                    (sum(int(row[1]) for row in orphan_rows),),
                )
            known = {
                str(row[0]): (str(row[1]), int(row[2]), str(row[3]))
                for row in connection.execute(
                    "SELECT object_leaf,media_type,byte_length,asset_sha256 "
                    "FROM web_asset_archive_objects"
                ).fetchall()
            }
        for path in self.object_directory.iterdir():
            if path.name in known:
                continue
            if _OBJECT_RE.fullmatch(path.name) is None:
                raise PaidMediaWebArchiveUnavailable("Web archive contains an unknown object")
            self._assert_plain_file(path)
            path.unlink()
        for leaf, (media_type, byte_length, digest) in known.items():
            descriptor = PaidMediaAssetDescriptor(
                token="nma1_" + "A" * 43,
                media_type=media_type,
                byte_length=byte_length,
                sha256=digest,
                validation_receipt_sha256="1" * 64,
            )
            self._read_verified_file(self.object_directory / leaf, descriptor)

    def _ensure_cleanup_ready_locked(self) -> None:
        # This O(1) shared receipt closes cross-process debt without re-reading
        # and hashing the whole (potentially 8 GiB) archive on the clean path.
        if self._cleanup_debt or self._cleanup_pending_locked():
            self._recover_uncommitted_objects_locked()
        if self._cleanup_debt:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive cleanup debt blocks new admission"
            )

    @staticmethod
    def _object_leaf(principal_hash: str, asset_sha256: str) -> str:
        return hashlib.sha256(
            _OBJECT_DOMAIN
            + principal_hash.encode("ascii")
            + b"\x00"
            + asset_sha256.encode("ascii")
        ).hexdigest() + ".asset"

    @staticmethod
    def _verify_payload(asset: PaidMediaAssetDescriptor, payload: bytes) -> None:
        if not isinstance(payload, bytes):
            raise PaidMediaWebArchiveUnavailable("Web archive payload is invalid")
        if len(payload) != asset.byte_length:
            raise PaidMediaWebArchiveUnavailable("Web archive asset length differs")
        if hashlib.sha256(payload).hexdigest() != asset.sha256:
            raise PaidMediaWebArchiveUnavailable("Web archive asset digest differs")
        if asset.media_type not in _MEDIA_TYPES:
            raise PaidMediaWebArchiveUnavailable("Web archive media type is invalid")

    def store_asset(
        self,
        **kwargs: object,
    ) -> None:
        del kwargs
        raise PaidMediaWebArchiveUnavailable(
            "Web archive assets require a document batch"
        )

    def _store_asset_locked(
        self,
        *,
        principal_hash: str,
        asset: PaidMediaAssetDescriptor,
        payload: bytes,
        now_ms: int,
        preserve_cleanup_pending: bool = False,
    ) -> None:
        if preserve_cleanup_pending:
            if not self._cleanup_pending_locked():
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive document batch receipt is missing"
                )
        else:
            self._ensure_cleanup_ready_locked()
        principal = _digest(principal_hash, "principal_hash")
        self._verify_payload(asset, payload)
        leaf = self._object_leaf(principal, asset.sha256)
        destination = self.object_directory / leaf
        with self._lock:
            with self._connect() as connection:
                existing = connection.execute(
                    "SELECT media_type,byte_length,object_leaf "
                    "FROM web_asset_archive_objects "
                    "WHERE principal_hash=? AND asset_sha256=?",
                    (principal, asset.sha256),
                ).fetchone()
                if existing is not None:
                    if existing != (asset.media_type, asset.byte_length, leaf):
                        raise PaidMediaWebArchiveUnavailable(
                            "Web archive content metadata conflicts"
                        )
                    self._read_verified_file(destination, asset)
                    return
                capacity = connection.execute(
                    "SELECT stored_bytes,max_capacity_bytes "
                    "FROM web_asset_archive_meta WHERE singleton=1"
                ).fetchone()
                if capacity is None or int(capacity[0]) + asset.byte_length > int(capacity[1]):
                    raise PaidMediaWebArchiveUnavailable("Web archive capacity is exhausted")

            # Commit the shared dirty receipt before the first possible file
            # creation.  It remains set until file and database authority have
            # converged, so another instance cannot take a clean fast path.
            if not preserve_cleanup_pending:
                self._set_cleanup_pending_locked(True)
            destination_is_unindexed = False
            try:
                if self._entry_exists(destination):
                    self._read_verified_file(destination, asset)
                    destination_is_unindexed = True
                else:
                    temporary = self.object_directory / f"{secrets.token_hex(32)}.asset"
                    try:
                        with temporary.open("xb") as handle:
                            handle.write(payload)
                            handle.flush()
                            os.fsync(handle.fileno())
                        self._harden_file(temporary)
                        os.replace(temporary, destination)
                        destination_is_unindexed = True
                        self._harden_file(destination)
                        try:
                            directory_fd = os.open(self.object_directory, os.O_RDONLY)
                            try:
                                os.fsync(directory_fd)
                            finally:
                                os.close(directory_fd)
                        except OSError:
                            if os.name != "nt":
                                raise
                    finally:
                        temporary.unlink(missing_ok=True)

                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    capacity = connection.execute(
                        "SELECT stored_bytes,max_capacity_bytes "
                        "FROM web_asset_archive_meta WHERE singleton=1"
                    ).fetchone()
                    existing = connection.execute(
                        "SELECT media_type,byte_length,object_leaf "
                        "FROM web_asset_archive_objects "
                        "WHERE principal_hash=? AND asset_sha256=?",
                        (principal, asset.sha256),
                    ).fetchone()
                    if existing is None:
                        if capacity is None or int(capacity[0]) + asset.byte_length > int(capacity[1]):
                            raise PaidMediaWebArchiveUnavailable("Web archive capacity is exhausted")
                        connection.execute(
                            "INSERT INTO web_asset_archive_objects VALUES(?,?,?,?,?,?)",
                            (principal, asset.sha256, asset.media_type, asset.byte_length, leaf, now_ms),
                        )
                        connection.execute(
                            "UPDATE web_asset_archive_meta SET stored_bytes=stored_bytes+? "
                            "WHERE singleton=1",
                            (asset.byte_length,),
                        )
                    elif existing != (asset.media_type, asset.byte_length, leaf):
                        raise PaidMediaWebArchiveUnavailable(
                            "Web archive content metadata conflicts"
                        )
                destination_is_unindexed = False
                if not preserve_cleanup_pending:
                    self._set_cleanup_pending_locked(False)
            except BaseException as exc:
                if destination_is_unindexed:
                    try:
                        self._cleanup_unindexed_destination_locked(
                            principal_hash=principal,
                            asset_sha256=asset.sha256,
                            destination=destination,
                            preserve_cleanup_pending=preserve_cleanup_pending,
                        )
                    except Exception as cleanup_exc:
                        self._cleanup_debt = True
                        raise PaidMediaWebArchiveUnavailable(
                            "Web archive orphan cleanup failed; admission is blocked"
                        ) from cleanup_exc
                else:
                    # A failure while creating/removing the random temporary
                    # file may have left bytes which have no database row.
                    self._cleanup_debt = True
                raise exc

    def _cleanup_unindexed_destination_locked(
        self,
        *,
        principal_hash: str,
        asset_sha256: str,
        destination: Path,
        preserve_cleanup_pending: bool = False,
    ) -> None:
        with self._connect() as connection:
            indexed = connection.execute(
                "SELECT object_leaf FROM web_asset_archive_objects "
                "WHERE principal_hash=? AND asset_sha256=?",
                (principal_hash, asset_sha256),
            ).fetchone()
            leaf_owner = connection.execute(
                "SELECT principal_hash,asset_sha256 "
                "FROM web_asset_archive_objects WHERE object_leaf=?",
                (destination.name,),
            ).fetchone()
        if indexed is not None:
            if indexed != (destination.name,):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive object index conflicts during cleanup"
                )
            return
        if leaf_owner is not None:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive object leaf is owned by another content receipt"
            )
        if self._entry_exists(destination):
            self._assert_plain_file(destination)
            destination.unlink()
        if not preserve_cleanup_pending:
            self._set_cleanup_pending_locked(False)

    def _prune_unreferenced_assets(
        self,
        *,
        principal_hash: str,
        asset_sha256s: set[str],
    ) -> None:
        if not asset_sha256s:
            return
        placeholders = ",".join("?" for _ in asset_sha256s)
        parameters = (principal_hash, *sorted(asset_sha256s))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT o.object_leaf,o.byte_length "
                "FROM web_asset_archive_objects o "
                "WHERE o.principal_hash=? "
                f"AND o.asset_sha256 IN ({placeholders}) "
                "AND NOT EXISTS (SELECT 1 FROM web_asset_archive_members m "
                "WHERE m.principal_hash=o.principal_hash "
                "AND m.asset_sha256=o.asset_sha256)",
                parameters,
            ).fetchall()
            if rows:
                connection.execute(
                    "UPDATE web_asset_archive_meta SET cleanup_pending=1 "
                    "WHERE singleton=1"
                )
                connection.execute(
                    "DELETE FROM web_asset_archive_objects "
                    "WHERE principal_hash=? "
                    f"AND asset_sha256 IN ({placeholders}) "
                    "AND NOT EXISTS (SELECT 1 FROM web_asset_archive_members m "
                    "WHERE m.principal_hash=web_asset_archive_objects.principal_hash "
                    "AND m.asset_sha256=web_asset_archive_objects.asset_sha256)",
                    parameters,
                )
                connection.execute(
                    "UPDATE web_asset_archive_meta SET stored_bytes=stored_bytes-? "
                    "WHERE singleton=1",
                    (sum(int(row[1]) for row in rows),),
                )
        try:
            for leaf, _length in rows:
                path = self.object_directory / str(leaf)
                if self._entry_exists(path):
                    self._assert_plain_file(path)
                    path.unlink()
            if rows:
                self._set_cleanup_pending_locked(False)
        except BaseException:
            # Database authority was intentionally reduced before unlink.
            # Mark this instance immediately; every other instance discovers
            # the same unindexed file in its mandatory admission scan.
            self._cleanup_debt = True
            raise

    @contextmanager
    def document_batch(
        self,
        *,
        principal_hash: str,
        result: PaidMediaAssetResult,
        installation_id: str,
        installation_epoch: int,
        now_ms: int,
    ) -> Iterator[_PaidMediaWebDocumentBatch]:
        """Keep one durable dirty receipt across every asset and document commit."""

        principal = _digest(principal_hash, "principal_hash")
        with self._authority_fence():
            self._ensure_cleanup_ready_locked()
            self._preflight_document_admission_locked(
                principal_hash=principal,
                result=result,
                installation_id=installation_id,
                installation_epoch=installation_epoch,
            )
            self._set_cleanup_pending_locked(True)
            batch = _PaidMediaWebDocumentBatch(
                archive=self,
                principal_hash=principal,
                result=result,
                installation_id=installation_id,
                installation_epoch=installation_epoch,
                now_ms=now_ms,
            )
            try:
                yield batch
                if batch.committed_receipt is None:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive document batch was not committed"
                    )
                self._set_cleanup_pending_locked(False)
            except BaseException:
                try:
                    # The failed step may have left either an indexed partial,
                    # an unindexed destination, or a random temporary file.
                    # Only the shared full recovery can prove all three forms
                    # converged before clearing the persistent dirty receipt.
                    self._recover_uncommitted_objects_locked()
                except BaseException:
                    self._cleanup_debt = True
                    raise
                raise

    def store_document_payloads(
        self,
        *,
        principal_hash: str,
        result: PaidMediaAssetResult,
        payloads: tuple[bytes, ...],
        installation_id: str,
        installation_epoch: int,
        now_ms: int,
    ) -> str:
        """Commit one complete document or remove its runtime partials."""

        if len(payloads) != len(result.assets):
            raise PaidMediaWebArchiveUnavailable(
                "Web archive payload set is incomplete"
            )
        for asset, payload in zip(result.assets, payloads, strict=True):
            self._verify_payload(asset, payload)
        with self.document_batch(
            principal_hash=principal_hash,
            result=result,
            installation_id=installation_id,
            installation_epoch=installation_epoch,
            now_ms=now_ms,
        ) as batch:
            for asset, payload in zip(result.assets, payloads, strict=True):
                batch.store_asset(asset=asset, payload=payload)
            return batch.commit()

    def _read_verified_file(
        self, path: Path, asset: PaidMediaAssetDescriptor
    ) -> bytes:
        before = self._assert_plain_file(path)
        if before.st_size != asset.byte_length:
            raise PaidMediaWebArchiveUnavailable("Web archive object length is corrupt")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if opened.st_ino != before.st_ino or opened.st_dev != before.st_dev:
                raise PaidMediaWebArchiveUnavailable("Web archive object was substituted")
            payload = handle.read(MAX_ASSET_BYTES + 1)
        self._verify_payload(asset, payload)
        after = self._assert_plain_file(path)
        if after.st_ino != before.st_ino or after.st_dev != before.st_dev:
            raise PaidMediaWebArchiveUnavailable("Web archive object changed while reading")
        return payload

    def commit_document(
        self,
        **kwargs: object,
    ) -> str:
        with self._authority_fence():
            return self._commit_document_locked(**kwargs)

    def _preflight_document_admission_locked(
        self,
        *,
        principal_hash: str,
        result: PaidMediaAssetResult,
        installation_id: str,
        installation_epoch: int,
    ) -> None:
        """Reserve no bytes; prove one document fits before object-file writes."""

        principal = _digest(principal_hash, "principal_hash")
        installation = _digest(installation_id, "installation_id")
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise PaidMediaWebArchiveUnavailable("installation_epoch is invalid")
        receipt = paid_media_web_archive_receipt_sha256(
            principal_hash=principal,
            result=result,
            installation_id=installation,
            installation_epoch=installation_epoch,
        )
        expected = (_operation_for(result), installation, installation_epoch, receipt)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT operation,installation_id,installation_epoch,"
                "archive_receipt_sha256 FROM web_asset_archive_documents "
                "WHERE principal_hash=? AND turn_id=?",
                (principal, result.turn_id),
            ).fetchone()
            if existing is not None:
                if existing != expected:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive document receipt conflicts"
                    )
                self._verify_document_members(connection, principal, result)
                return
            capacity = connection.execute(
                "SELECT document_count,max_documents,member_count,max_members "
                "FROM web_asset_archive_meta WHERE singleton=1"
            ).fetchone()
            if (
                capacity is None
                or int(capacity[0]) >= int(capacity[1])
                or int(capacity[2]) + len(result.assets) > int(capacity[3])
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive metadata capacity is exhausted"
                )

    def _commit_document_locked(
        self,
        *,
        principal_hash: str,
        result: PaidMediaAssetResult,
        installation_id: str,
        installation_epoch: int,
        now_ms: int,
    ) -> str:
        principal = _digest(principal_hash, "principal_hash")
        installation = _digest(installation_id, "installation_id")
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise PaidMediaWebArchiveUnavailable("installation_epoch is invalid")
        receipt = paid_media_web_archive_receipt_sha256(
            principal_hash=principal,
            result=result,
            installation_id=installation,
            installation_epoch=installation_epoch,
        )
        operation = _operation_for(result)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT operation,installation_id,installation_epoch,"
                "archive_receipt_sha256 FROM web_asset_archive_documents "
                "WHERE principal_hash=? AND turn_id=?",
                (principal, result.turn_id),
            ).fetchone()
            expected = (operation, installation, installation_epoch, receipt)
            if existing is not None:
                if existing != expected:
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive document receipt conflicts"
                    )
                self._verify_document_members(connection, principal, result)
                return receipt
            capacity = connection.execute(
                "SELECT document_count,max_documents,member_count,max_members "
                "FROM web_asset_archive_meta WHERE singleton=1"
            ).fetchone()
            if (
                capacity is None
                or int(capacity[0]) >= int(capacity[1])
                or int(capacity[2]) + len(result.assets) > int(capacity[3])
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive metadata capacity is exhausted"
                )
            for asset in result.assets:
                row = connection.execute(
                    "SELECT media_type,byte_length,object_leaf "
                    "FROM web_asset_archive_objects "
                    "WHERE principal_hash=? AND asset_sha256=?",
                    (principal, asset.sha256),
                ).fetchone()
                if row != (
                    asset.media_type,
                    asset.byte_length,
                    self._object_leaf(principal, asset.sha256),
                ):
                    raise PaidMediaWebArchiveUnavailable(
                        "Web archive document is missing a verified asset"
                    )
                self._read_verified_file(self.object_directory / str(row[2]), asset)
            connection.execute(
                "INSERT INTO web_asset_archive_documents VALUES(?,?,?,?,?,?,?)",
                (
                    principal,
                    result.turn_id,
                    operation,
                    installation,
                    installation_epoch,
                    receipt,
                    now_ms,
                ),
            )
            for ordinal, asset in enumerate(result.assets):
                connection.execute(
                    "INSERT INTO web_asset_archive_members VALUES(?,?,?,?)",
                    (principal, result.turn_id, ordinal, asset.sha256),
                )
            updated = connection.execute(
                "UPDATE web_asset_archive_meta SET "
                "document_count=document_count+1,member_count=member_count+? "
                "WHERE singleton=1 AND document_count<max_documents "
                "AND member_count+?<=max_members",
                (len(result.assets), len(result.assets)),
            )
            if updated.rowcount != 1:
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive metadata capacity is exhausted"
                )
        return receipt

    def _verify_document_members(
        self,
        connection: sqlite3.Connection,
        principal_hash: str,
        result: PaidMediaAssetResult,
    ) -> None:
        members = connection.execute(
            "SELECT m.ordinal,m.asset_sha256,o.media_type,o.byte_length,o.object_leaf "
            "FROM web_asset_archive_members m "
            "JOIN web_asset_archive_objects o "
            "ON o.principal_hash=m.principal_hash "
            "AND o.asset_sha256=m.asset_sha256 "
            "WHERE m.principal_hash=? AND m.turn_id=? ORDER BY m.ordinal",
            (principal_hash, result.turn_id),
        ).fetchall()
        expected = [
            (
                ordinal,
                asset.sha256,
                asset.media_type,
                asset.byte_length,
                self._object_leaf(principal_hash, asset.sha256),
            )
            for ordinal, asset in enumerate(result.assets)
        ]
        if members != expected:
            raise PaidMediaWebArchiveUnavailable(
                "Web archive document members are corrupt"
            )
        for row, asset in zip(members, result.assets, strict=True):
            self._read_verified_file(self.object_directory / str(row[4]), asset)

    def receipt_for_document(
        self,
        **kwargs: object,
    ) -> str | None:
        with self._authority_fence():
            return self._receipt_for_document_locked(**kwargs)

    def _receipt_for_document_locked(
        self,
        *,
        principal_hash: str,
        result: PaidMediaAssetResult,
        installation_id: str,
        installation_epoch: int,
    ) -> str | None:
        """Return a verified complete receipt, never a partial archive."""

        principal = _digest(principal_hash, "principal_hash")
        installation = _digest(installation_id, "installation_id")
        if (
            isinstance(installation_epoch, bool)
            or not isinstance(installation_epoch, int)
            or installation_epoch < 1
        ):
            raise PaidMediaWebArchiveUnavailable("installation_epoch is invalid")
        expected_receipt = paid_media_web_archive_receipt_sha256(
            principal_hash=principal,
            result=result,
            installation_id=installation,
            installation_epoch=installation_epoch,
        )
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT operation,installation_id,installation_epoch,"
                "archive_receipt_sha256 FROM web_asset_archive_documents "
                "WHERE principal_hash=? AND turn_id=?",
                (principal, result.turn_id),
            ).fetchone()
            if row is None:
                return None
            if row != (
                _operation_for(result),
                installation,
                installation_epoch,
                expected_receipt,
            ):
                raise PaidMediaWebArchiveUnavailable(
                    "Web archive document receipt conflicts"
                )
            self._verify_document_members(connection, principal, result)
        return expected_receipt

    def read(
        self,
        **kwargs: object,
    ) -> ArchivedPaidMediaWebAsset | None:
        with self._authority_fence():
            return self._read_locked(**kwargs)

    def _read_locked(
        self, *, principal_hash: str, asset_sha256: str
    ) -> ArchivedPaidMediaWebAsset | None:
        principal = _digest(principal_hash, "principal_hash")
        digest = _digest(asset_sha256, "asset_sha256")
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT o.media_type,o.byte_length,o.object_leaf "
                "FROM web_asset_archive_objects o "
                "JOIN web_asset_archive_members m "
                "ON m.principal_hash=o.principal_hash "
                "AND m.asset_sha256=o.asset_sha256 "
                "JOIN web_asset_archive_documents d "
                "ON d.principal_hash=m.principal_hash AND d.turn_id=m.turn_id "
                "WHERE o.principal_hash=? AND o.asset_sha256=? LIMIT 1",
                (principal, digest),
            ).fetchone()
        if row is None:
            return None
        descriptor = PaidMediaAssetDescriptor(
            token="nma1_" + "A" * 43,
            media_type=str(row[0]),
            byte_length=int(row[1]),
            sha256=digest,
            validation_receipt_sha256="1" * 64,
        )
        payload = self._read_verified_file(
            self.object_directory / str(row[2]), descriptor
        )
        return ArchivedPaidMediaWebAsset(
            payload=payload,
            media_type=descriptor.media_type,
            byte_length=descriptor.byte_length,
            sha256=descriptor.sha256,
        )

    def close(self) -> None:
        with self._lock:
            self._closed = True


__all__ = [
    "ArchivedPaidMediaWebAsset",
    "DEFAULT_WEB_ARCHIVE_CAPACITY_BYTES",
    "PaidMediaWebArchiveUnavailable",
    "PaidMediaWebAssetArchive",
]
