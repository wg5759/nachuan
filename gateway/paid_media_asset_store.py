"""Private, durable paid-media asset store for protocol v2.

The request ledger remains the authorization source.  This module stores only
token hashes and bounded file metadata; callers must re-read and parse the
immutable durable success document before :meth:`pin_authorized` can grant a
streaming lease.
"""

from __future__ import annotations

import base64
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
from threading import RLock
import time
from typing import BinaryIO, Callable, Iterable, Iterator, Literal
from urllib.parse import urlsplit

from gateway.installation_root import DEFAULT_DEPENDENCIES
from gateway.paid_media_asset_protocol import (
    ACK_SCHEMA,
    MAX_ASSET_BYTES,
    MAX_ASSETS,
    SUPPORTED_MEDIA_TYPES,
    PaidMediaAssetAck,
    PaidMediaAssetDescriptor,
    PaidMediaAssetProtocolError,
    PaidMediaAssetResult,
    asset_token_hash,
    asset_result_document,
    canonical_token_set_digest,
    create_asset_token,
    parse_asset_ack,
    parse_asset_result,
)
from gateway.public_media import download_public_file
from gateway.secure_store import SecureStorageError
from gateway.trusted_media_probe import (
    TRUSTED_MEDIA_CACHE_MARKER_NAME,
    TRUSTED_MEDIA_CACHE_MARKER_SCHEMA,
    TrustedMediaProbeResult,
    TrustedMediaScratchOwner,
    probe_trusted_media_staged_file,
)


ASSET_STORE_DIRECTORY_NAME = "paid-media-assets"
ASSET_STORE_DATABASE_NAME = "asset-store.db"
ASSET_STORE_SCHEMA = "nachuan.paid-media-asset-store.v2"
DEFAULT_STORE_CAPACITY_BYTES = 8 * 1024 * 1024 * 1024
_MAX_STORE_CAPACITY_BYTES = 1 << 40
_MAX_DATABASE_BYTES = 64 * 1024 * 1024
_MAX_WAL_BYTES = 2 * _MAX_DATABASE_BYTES
_MAX_SHM_BYTES = 8 * 1024 * 1024
_MAX_ROLLBACK_JOURNAL_BYTES = _MAX_DATABASE_BYTES
# One operation keeps enough logical and physical headroom for four maximum
# assets plus a second full-size staging/atomic-commit closure.
OPERATION_RESERVATION_BYTES = 2 * MAX_ASSETS * MAX_ASSET_BYTES
_PHYSICAL_SAFETY_BYTES = 32 * 1024 * 1024
_APPLICATION_ID = 0x4E434153  # NCAS
_SCHEMA_VERSION = 2
_MAX_MUTATION_SEQUENCE = (1 << 63) - 1
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_RE = re.compile(r"^(images|videos)\.create$")
_LEAF_RE = re.compile(r"^[0-9a-f]{64}\.asset$")
_STAGING_LEAF_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PROBE_CACHE_LEAF_RE = re.compile(r"^nachuan-media-cache-[A-Za-z0-9_-]{8,64}$")
_PROBE_CACHE_RESERVED_PREFIX = "nachuan-media-cache-"
_PROBE_CACHE_MARKER_MAX_BYTES = 1024
_PROBE_CACHE_MAX_ENTRIES = 16
_VALIDATION_RECEIPT_DOMAIN = b"nachuan-paid-media-validation-receipt-v1\x00"
_HASH_CHUNK_BYTES = 1024 * 1024
_STREAM_CHUNK_BYTES = 256 * 1024
_PENDING_COMMIT_LEASE_SECONDS = 15 * 60.0
_AUTHORITY_STATE_DOMAIN = b"nachuan-paid-media-asset-authority-v2\x00"
_AUTHORITY_PROJECTION_DOMAIN = b"nachuan-paid-media-asset-projection-v2\x00"
_ANCHOR_FORMAT = 1
_ANCHOR_MAX_BYTES = 1024
_ANCHOR_NONE_COUNTER = "-" * 16
_ANCHOR_NONE_DIGEST = "-" * 64
_ROLLBACK_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"


def _agnes_media_utf8_identity_url(candidate: str) -> bool:
    """Recognize the exact Agnes image/video CDN surfaces with the live header bug."""

    try:
        parsed = urlsplit(candidate)
        path = parsed.path
        return bool(
            parsed.scheme.casefold() == "https"
            and (parsed.hostname or "").casefold()
            == "platform-outputs.agnes-ai.space"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and (
                path.startswith("/images/")
                or path.startswith("/videos/")
            )
            # This is a vendor-quirk exception, not a general URL policy.
            # Generated Agnes media paths are plain ASCII; reject every
            # alternate path spelling that could be decoded or normalized
            # outside the exact /images/ or /videos/ subtrees.
            and "%" not in path
            and "\\" not in path
            and all(segment not in {".", ".."} for segment in path.split("/"))
        )
    except (UnicodeError, ValueError):
        return False


class PaidMediaAssetStoreError(RuntimeError):
    """The private asset store could not prove a safe transition."""


class PaidMediaAssetCapacityError(PaidMediaAssetStoreError):
    """Persistent logical or physical capacity is unavailable."""


class PaidMediaAssetAuthorizationError(PaidMediaAssetStoreError):
    """A token is absent, acknowledged, or outside the caller's authority."""


class PaidMediaAssetConflictError(PaidMediaAssetStoreError):
    """An idempotent reservation/commit/ACK disagrees with durable state."""


class PaidMediaAssetRootCommitPending(PaidMediaAssetStoreError):
    """Local authority committed, but independent Root confirmation did not."""


class _DatabaseFamilyChanged(RuntimeError):
    """A read-only SQLite family snapshot changed while it was classified."""


@dataclass(frozen=True, slots=True)
class PaidMediaAssetRootState:
    """Frozen non-secret proof intended for the Installation Epoch Root."""

    database_identity: str
    installation_id: str
    epoch: int
    mutation_sequence: int
    state_digest: str
    authority_mode: Literal["normal", "manual_only"] = "normal"
    recovery_floor: int | None = None
    recovery_state_digest: str | None = None


@dataclass(frozen=True, slots=True)
class PaidMediaAssetRootTransition:
    before: PaidMediaAssetRootState
    after: PaidMediaAssetRootState


@dataclass(frozen=True, slots=True)
class PaidMediaAssetStoreDependencies:
    assert_acl: Callable[[Path, bool], None]
    harden_acl: Callable[[Path, bool], None]
    disk_free: Callable[[Path], int]
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    after_object_replace: Callable[[Path], None] = lambda _path: None


DEFAULT_ASSET_STORE_DEPENDENCIES = PaidMediaAssetStoreDependencies(
    assert_acl=DEFAULT_DEPENDENCIES.assert_acl,
    harden_acl=DEFAULT_DEPENDENCIES.harden_acl,
    disk_free=lambda path: int(shutil.disk_usage(path).free),
)


@dataclass(frozen=True, slots=True)
class PaidMediaAssetReservation:
    turn_id: str
    principal_hash: str
    epoch: int
    operation: str
    reserved_bytes: int


@dataclass(frozen=True, slots=True)
class PaidMediaAssetLocator:
    turn_id: str
    operation: str


@dataclass(frozen=True, slots=True)
class PaidMediaAssetAckResult:
    replayed: bool
    cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    attributes: int


class PinnedPaidMediaAsset:
    """Identity-checked read handle whose DB lease lives until ``close``."""

    def __init__(
        self,
        *,
        store: "PaidMediaAssetStore",
        token_hash: str,
        lease_id: str,
        handle: BinaryIO,
        media_type: str,
        byte_length: int,
        sha256: str,
    ) -> None:
        self._store = store
        self._token_hash = token_hash
        self._lease_id = lease_id
        self._handle = handle
        self.media_type = media_type
        self.byte_length = byte_length
        self.sha256 = sha256
        self._closed = False

    def iter_chunks(self) -> Iterator[bytes]:
        total = 0
        try:
            while total < self.byte_length:
                chunk = self._handle.read(
                    min(_STREAM_CHUNK_BYTES, self.byte_length - total)
                )
                if not chunk:
                    raise PaidMediaAssetAuthorizationError(
                        "pinned paid-media asset ended before its receipt"
                    )
                total += len(chunk)
                yield chunk
            if self._handle.read(1):
                raise PaidMediaAssetAuthorizationError(
                    "pinned paid-media asset exceeds its receipt"
                )
        finally:
            self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._handle.close()
        finally:
            self._store._release_lease(self._token_hash, self._lease_id)

    def __enter__(self) -> "PinnedPaidMediaAsset":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


_META_DDL = """
CREATE TABLE asset_store_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema TEXT NOT NULL CHECK(schema='nachuan.paid-media-asset-store.v2'),
    installation_id TEXT NOT NULL CHECK(
        length(installation_id)=64 AND installation_id NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    database_identity TEXT NOT NULL CHECK(
        length(database_identity)=64 AND
        database_identity NOT GLOB '*[^0-9a-f]*' AND
        database_identity<>'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    mutation_sequence INTEGER NOT NULL CHECK(
        mutation_sequence BETWEEN 0 AND 9223372036854775807
    ),
    authority_state_digest TEXT NOT NULL CHECK(
        length(authority_state_digest)=64 AND
        authority_state_digest NOT GLOB '*[^0-9a-f]*' AND
        authority_state_digest<>'0000000000000000000000000000000000000000000000000000000000000000'
    ),
    authority_mode TEXT NOT NULL CHECK(
        authority_mode IN ('normal','manual_only')
    ),
    recovery_floor INTEGER,
    recovery_state_digest TEXT,
    max_capacity_bytes INTEGER NOT NULL CHECK(
        max_capacity_bytes BETWEEN 201326592 AND 1099511627776
    ),
    reserved_total_bytes INTEGER NOT NULL CHECK(reserved_total_bytes>=0),
    CHECK(
        (authority_mode='normal' AND recovery_floor IS NULL
            AND recovery_state_digest IS NULL)
        OR
        (authority_mode='manual_only' AND recovery_floor>=0
            AND length(recovery_state_digest)=64
            AND recovery_state_digest NOT GLOB '*[^0-9a-f]*'
            AND recovery_state_digest<>'0000000000000000000000000000000000000000000000000000000000000000'
            AND mutation_sequence=recovery_floor+1)
    )
) WITHOUT ROWID
"""

_RESERVATION_DDL = """
CREATE TABLE asset_reservations (
    turn_id TEXT PRIMARY KEY CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=201326592),
    actual_bytes INTEGER NOT NULL DEFAULT 0 CHECK(actual_bytes>=0),
    state TEXT NOT NULL CHECK(state IN ('active','committed','acked')),
    token_set_digest TEXT,
    created_at REAL NOT NULL CHECK(created_at>=0),
    CHECK(
        (state='active' AND token_set_digest IS NULL) OR
        (state IN ('committed','acked') AND length(token_set_digest)=64
            AND token_set_digest NOT GLOB '*[^0-9a-f]*')
    )
) WITHOUT ROWID
"""

_ASSET_DDL = """
CREATE TABLE paid_media_assets (
    token_hash TEXT PRIMARY KEY CHECK(
        length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL REFERENCES asset_reservations(turn_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
    media_type TEXT NOT NULL CHECK(media_type IN (
        'image/png','image/jpeg','image/gif','image/webp','video/mp4','video/webm'
    )),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 25165824),
    sha256 TEXT NOT NULL CHECK(
        length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    validation_receipt_sha256 TEXT NOT NULL CHECK(
        length(validation_receipt_sha256)=64 AND
        validation_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    object_leaf TEXT NOT NULL UNIQUE CHECK(length(object_leaf)=70),
    UNIQUE(turn_id, ordinal)
) WITHOUT ROWID
"""

_LEASE_DDL = """
CREATE TABLE asset_read_leases (
    token_hash TEXT NOT NULL REFERENCES paid_media_assets(token_hash) ON DELETE CASCADE,
    lease_id TEXT NOT NULL CHECK(
        length(lease_id)=64 AND lease_id NOT GLOB '*[^0-9a-f]*'
    ),
    expires_at REAL NOT NULL CHECK(expires_at>=0),
    PRIMARY KEY(token_hash, lease_id)
) WITHOUT ROWID
"""

_PENDING_COMMIT_DDL = """
CREATE TABLE asset_pending_commits (
    token_hash TEXT PRIMARY KEY CHECK(
        length(token_hash)=64 AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    turn_id TEXT NOT NULL REFERENCES asset_reservations(turn_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
    media_type TEXT NOT NULL CHECK(media_type IN (
        'image/png','image/jpeg','image/gif','image/webp','video/mp4','video/webm'
    )),
    byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 25165824),
    sha256 TEXT NOT NULL CHECK(
        length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    validation_receipt_sha256 TEXT NOT NULL CHECK(
        length(validation_receipt_sha256)=64 AND
        validation_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    staging_leaf TEXT NOT NULL CHECK(length(staging_leaf) BETWEEN 1 AND 128),
    object_leaf TEXT NOT NULL UNIQUE CHECK(length(object_leaf)=70),
    lease_expires_at REAL NOT NULL CHECK(lease_expires_at>=0),
    UNIQUE(turn_id, ordinal)
) WITHOUT ROWID
"""

_ACK_DDL = """
CREATE TABLE asset_ack_receipts (
    turn_id TEXT PRIMARY KEY CHECK(
        length(turn_id)=64 AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    principal_hash TEXT NOT NULL CHECK(
        length(principal_hash)=64 AND principal_hash NOT GLOB '*[^0-9a-f]*'
    ),
    epoch INTEGER NOT NULL CHECK(epoch>=1),
    operation TEXT NOT NULL CHECK(operation IN ('images.create','videos.create')),
    token_set_digest TEXT NOT NULL CHECK(
        length(token_set_digest)=64 AND token_set_digest NOT GLOB '*[^0-9a-f]*'
    ),
    archive_receipt_sha256 TEXT NOT NULL CHECK(
        length(archive_receipt_sha256)=64 AND
        archive_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    acked_at REAL NOT NULL CHECK(acked_at>=0)
) WITHOUT ROWID
"""

_EXPECTED_DDL = {
    ("table", "asset_store_meta"): _META_DDL,
    ("table", "asset_reservations"): _RESERVATION_DDL,
    ("table", "paid_media_assets"): _ASSET_DDL,
    ("table", "asset_read_leases"): _LEASE_DDL,
    ("table", "asset_pending_commits"): _PENDING_COMMIT_DDL,
    ("table", "asset_ack_receipts"): _ACK_DDL,
}


@lru_cache(maxsize=1)
def _expected_schema_sql() -> dict[tuple[str, str], tuple[str, object]]:
    """Materialize the module DDL and freeze SQLite's exact stored SQL."""

    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        for ddl in _EXPECTED_DDL.values():
            connection.execute(ddl)
        objects = {
            (str(kind), str(name)): (str(tbl_name), sql)
            for kind, name, tbl_name, sql in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
        }
    if not set(_EXPECTED_DDL).issubset(objects) or any(
        not isinstance(objects[identity][1], str) or not objects[identity][1]
        for identity in _EXPECTED_DDL
    ):
        raise sqlite3.DatabaseError(
            "paid-media expected schema could not be materialized exactly"
        )
    return objects

_AUTHORITY_PROJECTION_SPEC = (
    (
        "asset_store_meta",
        (
            "schema",
            "installation_id",
            "epoch",
            "database_identity",
            "authority_mode",
            "recovery_floor",
            "recovery_state_digest",
            "max_capacity_bytes",
            "reserved_total_bytes",
        ),
        "singleton",
    ),
    (
        "asset_reservations",
        (
            "turn_id",
            "principal_hash",
            "epoch",
            "operation",
            "reserved_bytes",
            "actual_bytes",
            "state",
            "token_set_digest",
            "created_at",
        ),
        "turn_id",
    ),
    (
        "paid_media_assets",
        (
            "token_hash",
            "turn_id",
            "ordinal",
            "media_type",
            "byte_length",
            "sha256",
            "validation_receipt_sha256",
            "object_leaf",
        ),
        "token_hash",
    ),
    (
        "asset_pending_commits",
        (
            "token_hash",
            "turn_id",
            "ordinal",
            "media_type",
            "byte_length",
            "sha256",
            "validation_receipt_sha256",
            "staging_leaf",
            "object_leaf",
            "lease_expires_at",
        ),
        "token_hash",
    ),
    (
        "asset_ack_receipts",
        (
            "turn_id",
            "principal_hash",
            "epoch",
            "operation",
            "token_set_digest",
            "archive_receipt_sha256",
            "acked_at",
        ),
        "turn_id",
    ),
)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    if value == "0" * 64:
        raise ValueError(f"{label} must not be the zero digest")
    return value


def _authority_projection_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256(_AUTHORITY_PROJECTION_DOMAIN)
    for table, columns, order_by in _AUTHORITY_PROJECTION_SPEC:
        heading = json.dumps(
            [table, *columns],
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        digest.update(len(heading).to_bytes(4, "big"))
        digest.update(heading)
        query = f"SELECT {','.join(columns)} FROM {table} ORDER BY {order_by}"
        for row in connection.execute(query):
            encoded = json.dumps(
                list(row),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("ascii")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        digest.update(b"\x00")
    return digest.hexdigest()


def _authority_state_digest(
    database_identity: str,
    installation_id: str,
    epoch: int,
    mutation_sequence: int,
    projection_digest: str,
) -> str:
    identity = _digest(database_identity, "database_identity")
    installation = _digest(installation_id, "installation_id")
    projection = _digest(projection_digest, "authority_projection_digest")
    normalized_epoch = _epoch(epoch)
    if (
        not isinstance(mutation_sequence, int)
        or isinstance(mutation_sequence, bool)
        or not 0 <= mutation_sequence <= _MAX_MUTATION_SEQUENCE
    ):
        raise ValueError("asset-store mutation sequence is invalid")
    return hashlib.sha256(
        _AUTHORITY_STATE_DOMAIN
        + identity.encode("ascii")
        + b"\x00"
        + installation.encode("ascii")
        + b"\x00"
        + f"{normalized_epoch:016x}".encode("ascii")
        + b"\x00"
        + f"{mutation_sequence:016x}".encode("ascii")
        + b"\x00"
        + projection.encode("ascii")
    ).hexdigest()


def _epoch(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("installation epoch must be a positive integer")
    return value


def _operation(value: object) -> str:
    if not isinstance(value, str) or _OPERATION_RE.fullmatch(value) is None:
        raise ValueError("paid-media operation is invalid")
    return value


def _prepared_token(value: object | None) -> str | None:
    if value is None:
        return None
    asset_token_hash(value)
    assert isinstance(value, str)
    return value


def _is_reparse(info: os.stat_result) -> bool:
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & flag
    )


def _assert_plain(path: Path, *, directory: bool) -> os.stat_result:
    info = os.lstat(path)
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or _is_reparse(info):
        raise OSError("paid-media asset path is not a plain local object")
    if not directory and int(getattr(info, "st_nlink", 1)) != 1:
        raise OSError("paid-media asset file has multiple hard links")
    return info


def _identity_from_stat(info: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=int(getattr(info, "st_dev", 0)),
        inode=int(getattr(info, "st_ino", 0)),
        mode=int(info.st_mode),
        links=int(getattr(info, "st_nlink", 1)),
        size=int(info.st_size),
        modified_ns=int(
            getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))
        ),
        changed_ns=int(
            getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000))
        ),
        attributes=int(getattr(info, "st_file_attributes", 0)),
    )


def _file_identity(path: Path) -> _FileIdentity:
    return _identity_from_stat(_assert_plain(path, directory=False))


def _require_same_file(path: Path, expected: _FileIdentity) -> None:
    if _file_identity(path) != expected:
        raise PaidMediaAssetAuthorizationError(
            "paid-media staging identity changed during validation"
        )


def _same_open_identity(current: _FileIdentity, expected: _FileIdentity) -> bool:
    """Compare only fields stable across Windows path-stat and CRT fstat."""

    return (
        current.device == expected.device
        and current.inode == expected.inode
        and stat.S_IFMT(current.mode) == stat.S_IFMT(expected.mode)
        and current.links == expected.links
        and current.size == expected.size
        and not (current.attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
    )


def _canonical_sql(value: object) -> str:
    return value if isinstance(value, str) and value else ""


def _hash_file(handle: BinaryIO, expected_length: int) -> str:
    digest = hashlib.sha256()
    total = 0
    handle.seek(0)
    while total < expected_length:
        chunk = handle.read(min(_HASH_CHUNK_BYTES, expected_length - total))
        if not chunk:
            raise OSError("paid-media asset ended before its recorded length")
        digest.update(chunk)
        total += len(chunk)
    if handle.read(1):
        raise OSError("paid-media asset exceeds its recorded length")
    handle.seek(0)
    return digest.hexdigest()


def _validation_receipt_digest(receipt: TrustedMediaProbeResult) -> str:
    encoded = json.dumps(
        asdict(receipt),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(_VALIDATION_RECEIPT_DOMAIN + encoded).hexdigest()


class PaidMediaAssetStore:
    """Cross-process SQLite index plus private file-backed byte store."""

    def __init__(
        self,
        root: Path,
        *,
        installation_id: str,
        epoch: int,
        expected_database_identity: str | None,
        max_capacity_bytes: int,
        dependencies: PaidMediaAssetStoreDependencies,
        pre_mutation_hook: Callable[[], None] | None,
        root_commit_hook: Callable[[PaidMediaAssetRootTransition], None] | None,
    ) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.database_path = self.root / ASSET_STORE_DATABASE_NAME
        self.anchor_path = Path(f"{self.database_path}.rollback-anchor")
        self.staging_directory = self.root / "staging"
        self.object_directory = self.root / "objects"
        self.installation_id = _digest(installation_id, "installation_id")
        self.epoch = _epoch(epoch)
        self._expected_database_identity = (
            None
            if expected_database_identity is None
            else _digest(expected_database_identity, "expected_database_identity")
        )
        if isinstance(max_capacity_bytes, bool) or not isinstance(
            max_capacity_bytes, int
        ):
            raise ValueError("paid-media asset capacity must be an integer")
        self.max_capacity_bytes = max_capacity_bytes
        if not (
            OPERATION_RESERVATION_BYTES
            <= self.max_capacity_bytes
            <= _MAX_STORE_CAPACITY_BYTES
        ):
            raise ValueError("paid-media asset capacity is outside hard limits")
        self.dependencies = dependencies
        if pre_mutation_hook is not None and not callable(pre_mutation_hook):
            raise ValueError("pre_mutation_hook must be callable")
        if root_commit_hook is not None and not callable(root_commit_hook):
            raise ValueError("root_commit_hook must be callable")
        self._pre_mutation_hook = pre_mutation_hook
        self._root_commit_hook = root_commit_hook
        self._pre_mutation_hook_active = False
        self._root_commit_hook_active = False
        self._root_commit_pending: PaidMediaAssetRootTransition | None = None
        self._transaction_lock = RLock()
        self._trusted_clean_schema_signature: tuple[int, int, bytes] | None = None
        self._probe_cache_generation = secrets.token_hex(32)
        self._probe_cache_owner: TrustedMediaScratchOwner | None = None
        self._closed = False

    @classmethod
    def provision(
        cls,
        root: str | os.PathLike[str],
        *,
        installation_id: str,
        epoch: int,
        expected_database_identity: str | None = None,
        max_capacity_bytes: int = DEFAULT_STORE_CAPACITY_BYTES,
        dependencies: PaidMediaAssetStoreDependencies = DEFAULT_ASSET_STORE_DEPENDENCIES,
        pre_mutation_hook: Callable[[], None] | None = None,
        root_commit_hook: Callable[[PaidMediaAssetRootTransition], None] | None = None,
    ) -> "PaidMediaAssetStore":
        database_identity = (
            secrets.token_hex(32)
            if expected_database_identity is None
            else _digest(expected_database_identity, "expected_database_identity")
        )
        store = cls(
            Path(root),
            installation_id=installation_id,
            epoch=epoch,
            expected_database_identity=database_identity,
            max_capacity_bytes=max_capacity_bytes,
            dependencies=dependencies,
            pre_mutation_hook=pre_mutation_hook,
            root_commit_hook=root_commit_hook,
        )
        if store.root.exists():
            raise PaidMediaAssetStoreError("asset store provision target already exists")
        try:
            os.mkdir(store.root, 0o700)
            dependencies.harden_acl(store.root, True)
            for directory in (store.staging_directory, store.object_directory):
                os.mkdir(directory, 0o700)
                dependencies.harden_acl(directory, True)
            with store._connect(create=True) as connection:
                for ddl in _EXPECTED_DDL.values():
                    connection.execute(ddl)
                assert store._expected_database_identity is not None
                connection.execute(
                    "INSERT INTO asset_store_meta "
                    "(singleton,schema,installation_id,epoch,database_identity,"
                    "mutation_sequence,authority_state_digest,authority_mode,"
                    "recovery_floor,recovery_state_digest,max_capacity_bytes,"
                    "reserved_total_bytes) "
                    "VALUES(1,?,?,?,?,?,?,'normal',NULL,NULL,?,0)",
                    (
                        ASSET_STORE_SCHEMA,
                        store.installation_id,
                        store.epoch,
                        store._expected_database_identity,
                        0,
                        "f" * 64,
                        store.max_capacity_bytes,
                    ),
                )
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                projection_digest = _authority_projection_digest(connection)
                authority_state_digest = _authority_state_digest(
                    store._expected_database_identity,
                    store.installation_id,
                    store.epoch,
                    0,
                    projection_digest,
                )
                connection.execute(
                    "UPDATE asset_store_meta SET authority_state_digest=? "
                    "WHERE singleton=1",
                    (authority_state_digest,),
                )
                store._write_anchor(
                    PaidMediaAssetRootState(
                        database_identity=store._expected_database_identity,
                        installation_id=store.installation_id,
                        epoch=store.epoch,
                        mutation_sequence=0,
                        state_digest=authority_state_digest,
                    ),
                    create_only=True,
                )
                connection.commit()
            dependencies.harden_acl(store.database_path, False)
            store._validate_layout()
            with store._connect() as connection:
                store._validate_schema(connection)
            store._bind_probe_cache_owner(store.inspect_root_state())
            return store
        except BaseException as exc:
            if isinstance(exc, PaidMediaAssetStoreError):
                raise
            raise PaidMediaAssetStoreError(
                "paid-media asset store provisioning failed closed"
            ) from exc

    @classmethod
    def open_bound(
        cls,
        root: str | os.PathLike[str],
        *,
        installation_id: str,
        epoch: int,
        expected_database_identity: str | None = None,
        max_capacity_bytes: int = DEFAULT_STORE_CAPACITY_BYTES,
        dependencies: PaidMediaAssetStoreDependencies = DEFAULT_ASSET_STORE_DEPENDENCIES,
        pre_mutation_hook: Callable[[], None] | None = None,
        root_commit_hook: Callable[[PaidMediaAssetRootTransition], None] | None = None,
    ) -> "PaidMediaAssetStore":
        store = cls(
            Path(root),
            installation_id=installation_id,
            epoch=epoch,
            expected_database_identity=expected_database_identity,
            max_capacity_bytes=max_capacity_bytes,
            dependencies=dependencies,
            pre_mutation_hook=pre_mutation_hook,
            root_commit_hook=root_commit_hook,
        )
        try:
            store._validate_layout()
            with store._connect() as connection:
                store._validate_schema(connection)
            store._bind_probe_cache_owner(store.inspect_root_state())
            return store
        except BaseException as exc:
            if isinstance(exc, PaidMediaAssetStoreError):
                raise
            raise PaidMediaAssetStoreError(
                "paid-media asset store open failed closed"
            ) from exc

    def _validate_layout(self) -> None:
        for directory in (self.root, self.staging_directory, self.object_directory):
            _assert_plain(directory, directory=True)
            self.dependencies.assert_acl(directory, True)
        for path in (self.database_path, self.anchor_path):
            _assert_plain(path, directory=False)
            self.dependencies.assert_acl(path, False)

    def _database_family_presence(
        self, *, assert_acl: bool = True
    ) -> dict[str, bool]:
        presence: dict[str, bool] = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(f"{self.database_path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                presence[suffix] = False
                continue
            if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
                raise sqlite3.DatabaseError(
                    "paid-media database family contains an unsafe object"
                )
            if assert_acl:
                self.dependencies.assert_acl(candidate, False)
            presence[suffix] = True
        return presence

    def _database_path_identity(self) -> tuple[int, int]:
        info = _assert_plain(self.database_path, directory=False)
        return int(info.st_dev), int(info.st_ino)

    def _assert_database_family_bounds(self) -> None:
        limits = {
            "": _MAX_DATABASE_BYTES,
            "-wal": _MAX_WAL_BYTES,
            "-shm": _MAX_SHM_BYTES,
            "-journal": _MAX_ROLLBACK_JOURNAL_BYTES,
        }
        for suffix, limit in limits.items():
            candidate = Path(f"{self.database_path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or _is_reparse(info)
                or int(info.st_size) > limit
            ):
                raise sqlite3.DatabaseError(
                    "paid-media database family exceeds its bounded profile"
                )

    def _database_header_mode(self) -> str:
        with self.database_path.open("rb") as handle:
            header = handle.read(20)
        if len(header) < 20 or not header.startswith(b"SQLite format 3\x00"):
            raise sqlite3.DatabaseError("paid-media database header is invalid")
        if header[18:20] == b"\x01\x01":
            return "rollback"
        if header[18:20] == b"\x02\x02":
            return "wal"
        raise sqlite3.DatabaseError("paid-media database journal header is invalid")

    def _database_schema_signature(
        self, identity: tuple[int, int]
    ) -> tuple[int, int, bytes]:
        with self.database_path.open("rb") as handle:
            header = handle.read(72)
        if len(header) < 72 or not header.startswith(b"SQLite format 3\x00"):
            raise sqlite3.DatabaseError("paid-media database header is invalid")
        # Page size, schema cookie/format, text encoding, user_version and
        # application_id are stable across data-only commits but change for an
        # honest schema generation transition.  The inode pair forces a fresh
        # read-only classification after pathname replacement.
        schema_header = header[16:18] + header[40:48] + header[52:72]
        return identity[0], identity[1], schema_header

    def _rollback_journal_state(self) -> str:
        journal = Path(f"{self.database_path}-journal")
        if not journal.exists():
            return "absent"
        with journal.open("rb") as handle:
            header = handle.read(8)
        if not header or header == b"\x00" * len(header):
            return "clean"
        if header == _ROLLBACK_JOURNAL_MAGIC:
            return "hot"
        raise sqlite3.DatabaseError(
            "paid-media rollback journal requires explicit forensic recovery"
        )

    def _classify_schema_generation(self, connection: sqlite3.Connection) -> str:
        if (
            int(connection.execute("PRAGMA application_id").fetchone()[0])
            != _APPLICATION_ID
            or int(connection.execute("PRAGMA user_version").fetchone()[0])
            != _SCHEMA_VERSION
        ):
            raise sqlite3.DatabaseError("paid-media asset schema identity is invalid")
        objects = {
            (str(kind), str(name)): (str(tbl_name), sql)
            for kind, name, tbl_name, sql in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
        }
        expected_objects = _expected_schema_sql()
        if set(objects) != set(expected_objects):
            raise sqlite3.DatabaseError("paid-media asset schema set is incompatible")
        for identity, (expected_table, expected_sql) in expected_objects.items():
            actual_table, actual_sql = objects[identity]
            if actual_table != expected_table or _canonical_sql(
                actual_sql
            ) != _canonical_sql(expected_sql):
                raise sqlite3.DatabaseError(
                    f"paid-media asset schema {identity[1]} is incompatible"
                )
        return "current"

    def _preflight_database_family_once(self) -> tuple[dict[str, bool], tuple[int, int]]:
        # _connect already validated the main file ACL through _validate_layout.
        # Sidecars are the only newly discovered authority objects here.
        presence = self._database_family_presence(assert_acl=False)
        for suffix in ("-wal", "-shm", "-journal"):
            if presence[suffix]:
                self.dependencies.assert_acl(
                    Path(f"{self.database_path}{suffix}"), False
                )
        if not presence[""]:
            raise sqlite3.DatabaseError("paid-media asset database is missing")
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "paid-media WAL and SHM sidecars must be present together"
            )
        identity = self._database_path_identity()
        self._assert_database_family_bounds()
        header_mode = self._database_header_mode()
        journal_state = self._rollback_journal_state()
        clean_signature: tuple[int, int, bytes] | None = None
        if not presence["-wal"]:
            if header_mode != "rollback":
                raise sqlite3.DatabaseError(
                    "paid-media WAL header is missing its complete sidecars"
                )
            if journal_state in {"absent", "clean"}:
                clean_signature = self._database_schema_signature(identity)
                if self._trusted_clean_schema_signature == clean_signature:
                    presence_after = self._database_family_presence(assert_acl=False)
                    if presence_after != presence:
                        raise _DatabaseFamilyChanged(
                            "paid-media database family changed during fast preflight"
                        )
                    if self._database_path_identity() != identity:
                        raise sqlite3.DatabaseError(
                            "paid-media database path changed during fast preflight"
                        )
                    return presence_after, identity
        immutable_uri = f"{self.database_path.as_uri()}?mode=ro&immutable=1"
        with closing(
            sqlite3.connect(immutable_uri, uri=True, isolation_level=None, timeout=10.0)
        ) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            self._classify_schema_generation(connection)
        presence_after = self._database_family_presence(assert_acl=False)
        if presence_after != presence:
            raise _DatabaseFamilyChanged(
                "paid-media database family changed during immutable preflight"
            )
        if self._database_path_identity() != identity:
            raise sqlite3.DatabaseError(
                "paid-media database path changed during immutable preflight"
            )
        if clean_signature is not None:
            if self._database_schema_signature(identity) != clean_signature:
                raise _DatabaseFamilyChanged(
                    "paid-media schema signature changed during immutable preflight"
                )
            self._trusted_clean_schema_signature = clean_signature
        if presence_after["-wal"]:
            wal_uri = f"{self.database_path.as_uri()}?mode=ro"
            with closing(
                sqlite3.connect(wal_uri, uri=True, isolation_level=None, timeout=10.0)
            ) as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("BEGIN")
                try:
                    self._classify_schema_generation(connection)
                finally:
                    connection.rollback()
            wal_presence = self._database_family_presence(assert_acl=False)
            if wal_presence != presence_after:
                raise _DatabaseFamilyChanged(
                    "paid-media database family changed during WAL-aware preflight"
                )
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "paid-media database path changed during WAL-aware preflight"
                )
            presence_after = wal_presence
        return presence_after, identity

    def _preflight_database_family(self) -> tuple[dict[str, bool], tuple[int, int]]:
        last_change: _DatabaseFamilyChanged | None = None
        for _attempt in range(4):
            try:
                return self._preflight_database_family_once()
            except _DatabaseFamilyChanged as exc:
                last_change = exc
                self.dependencies.sleep(0)
        raise sqlite3.DatabaseError(
            "paid-media database family did not stabilize during preflight"
        ) from last_change

    @contextmanager
    def _connect(
        self, *, create: bool = False, validate: bool = True
    ) -> Iterator[sqlite3.Connection]:
        with self._transaction_lock:
            if self._closed:
                raise PaidMediaAssetStoreError(
                    "paid-media asset store instance is closed"
                )
        if not create:
            self._validate_layout()
            preflight_presence, preflight_identity = self._preflight_database_family()
            if (
                self._database_family_presence(assert_acl=False)
                != preflight_presence
            ):
                preflight_presence, preflight_identity = (
                    self._preflight_database_family()
                )
        connection = sqlite3.connect(
            self.database_path,
            timeout=10.0,
            isolation_level=None,
        )
        try:
            if not create and self._database_path_identity() != preflight_identity:
                raise sqlite3.DatabaseError(
                    "paid-media database path changed before read-write open"
                )
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA busy_timeout=10000")
            if create:
                self._configure_page_budget(connection)
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
            elif preflight_presence["-wal"] or self._rollback_journal_state() == "hot":
                self._configure_page_budget(connection)
                mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
                if not mode or str(mode[0]).casefold() != "delete":
                    raise sqlite3.DatabaseError(
                        "paid-media asset store requires DELETE journal mode"
                    )
            if not create and validate:
                pending_observation: (
                    tuple[PaidMediaAssetRootState, PaidMediaAssetRootState] | None
                ) = None
                while True:
                    connection.execute("BEGIN")
                    try:
                        self._validate_schema(connection)
                        try:
                            self._validate_anchor_against_database(connection)
                        except sqlite3.DatabaseError:
                            pending = self._pending_anchor_successor(connection)
                            if pending is None or pending == pending_observation:
                                raise
                            pending_observation = pending
                            connection.rollback()
                            # Wait for a live anchor-first writer.  With no
                            # writer this barrier succeeds immediately, and
                            # the identical mismatch is rejected next loop.
                            connection.execute("BEGIN IMMEDIATE")
                            connection.rollback()
                            continue
                        break
                    except BaseException:
                        if connection.in_transaction:
                            connection.rollback()
                        raise
                # max_page_count is connection-local.  Re-apply the hard cap only
                # after the exact schema and anchor have been accepted, so an
                # unknown family never reaches a mutating/configuring pragma.
                self._configure_page_budget(connection)
                if self._trusted_clean_schema_signature is None:
                    current_presence = self._database_family_presence(assert_acl=False)
                    if (
                        not current_presence["-wal"]
                        and not current_presence["-shm"]
                        and self._rollback_journal_state() in {"absent", "clean"}
                    ):
                        current_identity = self._database_path_identity()
                        self._trusted_clean_schema_signature = (
                            self._database_schema_signature(current_identity)
                        )
            yield connection
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    @staticmethod
    def _page_budget(
        connection: sqlite3.Connection, *, configure: bool
    ) -> None:
        page_size_row = connection.execute("PRAGMA page_size").fetchone()
        page_count_row = connection.execute("PRAGMA page_count").fetchone()
        if page_size_row is None or page_count_row is None:
            raise sqlite3.DatabaseError("paid-media database page budget is unavailable")
        page_size = int(page_size_row[0])
        page_count = int(page_count_row[0])
        if page_size <= 0 or page_count < 0:
            raise sqlite3.DatabaseError("paid-media database page budget is invalid")
        max_pages = _MAX_DATABASE_BYTES // page_size
        configured = connection.execute(
            f"PRAGMA max_page_count={max_pages}"
            if configure
            else "PRAGMA max_page_count"
        ).fetchone()
        if (
            configured is None
            or int(configured[0]) != max_pages
            or page_count > max_pages
        ):
            raise sqlite3.DatabaseError(
                "paid-media database exceeds its hard page budget"
            )

    @staticmethod
    def _configure_page_budget(connection: sqlite3.Connection) -> None:
        PaidMediaAssetStore._page_budget(connection, configure=True)

    @staticmethod
    def _validate_page_budget(connection: sqlite3.Connection) -> None:
        PaidMediaAssetStore._page_budget(connection, configure=False)

    @contextmanager
    def _write(
        self, *, authoritative: bool = True
    ) -> Iterator[sqlite3.Connection]:
        transition: PaidMediaAssetRootTransition | None = None
        with self._transaction_lock:
            if self._closed:
                raise PaidMediaAssetStoreError(
                    "paid-media asset store instance is closed"
                )
            if self._pre_mutation_hook_active:
                raise PaidMediaAssetStoreError(
                    "paid-media asset mutation gate is already active"
                )
            if self._root_commit_hook_active:
                raise PaidMediaAssetStoreError(
                    "paid-media asset mutation is unavailable during root confirmation"
                )
            if authoritative and self._root_commit_pending is not None:
                raise PaidMediaAssetRootCommitPending(
                    "installation-root commit confirmation is pending"
                )
            with self._connect(validate=False) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._validate_schema(connection)
                    self._validate_anchor_against_database(connection)
                    self._configure_page_budget(connection)
                    before = self._root_state_from_connection(connection)
                    if authoritative and before.authority_mode != "normal":
                        raise PaidMediaAssetStoreError(
                            "paid-media authority is restricted to manual recovery"
                        )
                    if authoritative and self._pre_mutation_hook is not None:
                        self._pre_mutation_hook_active = True
                        try:
                            self._pre_mutation_hook()
                        finally:
                            self._pre_mutation_hook_active = False
                    before_projection = _authority_projection_digest(connection)
                    yield connection
                    after_projection = _authority_projection_digest(connection)
                    if after_projection != before_projection:
                        if not authoritative:
                            raise sqlite3.DatabaseError(
                                "lease-only transaction changed asset authority"
                            )
                        current = self._root_state_from_connection(connection)
                        if current != before:
                            raise sqlite3.DatabaseError(
                                "paid-media asset authority changed during mutation"
                            )
                        if before.mutation_sequence >= _MAX_MUTATION_SEQUENCE:
                            raise sqlite3.DatabaseError(
                                "paid-media asset mutation sequence is exhausted"
                            )
                        next_sequence = before.mutation_sequence + 1
                        next_state_digest = _authority_state_digest(
                            before.database_identity,
                            before.installation_id,
                            before.epoch,
                            next_sequence,
                            after_projection,
                        )
                        after = PaidMediaAssetRootState(
                            database_identity=before.database_identity,
                            installation_id=before.installation_id,
                            epoch=before.epoch,
                            mutation_sequence=next_sequence,
                            state_digest=next_state_digest,
                        )
                        self._write_anchor(after)
                        cursor = connection.execute(
                            "UPDATE asset_store_meta SET mutation_sequence=?,"
                            "authority_state_digest=? WHERE singleton=1 "
                            "AND database_identity=? AND mutation_sequence=? "
                            "AND authority_state_digest=?",
                            (
                                next_sequence,
                                next_state_digest,
                                before.database_identity,
                                before.mutation_sequence,
                                before.state_digest,
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise sqlite3.DatabaseError(
                                "paid-media asset mutation sequence changed concurrently"
                            )
                        self._validate_schema(connection)
                        self._validate_anchor_against_database(connection)
                        transition = PaidMediaAssetRootTransition(
                            before=before,
                            after=after,
                        )
                    connection.commit()
                except BaseException:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
            if transition is not None and self._root_commit_hook is not None:
                self._root_commit_hook_active = True
                try:
                    self._root_commit_hook(transition)
                except BaseException:
                    self._root_commit_pending = transition
                    raise PaidMediaAssetRootCommitPending(
                        "installation-root commit confirmation is pending"
                    ) from None
                finally:
                    self._root_commit_hook_active = False

    def _assert_physical_headroom(
        self,
        connection: sqlite3.Connection,
        *,
        additional_reserved_bytes: int = 0,
    ) -> None:
        row = connection.execute(
            "SELECT reserved_total_bytes FROM asset_store_meta WHERE singleton=1"
        ).fetchone()
        if row is None or not isinstance(row[0], int) or isinstance(row[0], bool):
            raise sqlite3.DatabaseError("paid-media physical reservation is corrupt")
        required = int(row[0]) + int(additional_reserved_bytes) + _PHYSICAL_SAFETY_BYTES
        if int(self.dependencies.disk_free(self.root)) < required:
            raise PaidMediaAssetCapacityError(
                "paid-media asset volume cannot cover durable reservations"
            )

    def _validate_schema(self, connection: sqlite3.Connection) -> None:
        self._classify_schema_generation(connection)
        meta = connection.execute(
            "SELECT schema,installation_id,epoch,database_identity,"
            "mutation_sequence,authority_state_digest,authority_mode,"
            "recovery_floor,recovery_state_digest,max_capacity_bytes,"
            "reserved_total_bytes FROM asset_store_meta WHERE singleton=1"
        ).fetchone()
        if (
            meta is None
            or tuple(meta[:3])
            != (ASSET_STORE_SCHEMA, self.installation_id, self.epoch)
            or not isinstance(meta[3], str)
            or _DIGEST_RE.fullmatch(meta[3]) is None
            or meta[3] == "0" * 64
            or (
                self._expected_database_identity is not None
                and meta[3] != self._expected_database_identity
            )
            or not isinstance(meta[4], int)
            or isinstance(meta[4], bool)
            or not 0 <= int(meta[4]) <= _MAX_MUTATION_SEQUENCE
            or not isinstance(meta[5], str)
            or _DIGEST_RE.fullmatch(meta[5]) is None
            or meta[5] == "0" * 64
            or meta[6] not in {"normal", "manual_only"}
            or (
                meta[6] == "normal"
                and (meta[7] is not None or meta[8] is not None)
            )
            or (
                meta[6] == "manual_only"
                and (
                    not isinstance(meta[7], int)
                    or isinstance(meta[7], bool)
                    or not 0 <= int(meta[7]) < _MAX_MUTATION_SEQUENCE
                    or not isinstance(meta[8], str)
                    or _DIGEST_RE.fullmatch(meta[8]) is None
                    or meta[8] == "0" * 64
                    or int(meta[4]) != int(meta[7]) + 1
                )
            )
            or int(meta[9]) != self.max_capacity_bytes
            or not isinstance(meta[10], int)
            or isinstance(meta[10], bool)
            or not 0 <= int(meta[10]) <= self.max_capacity_bytes
        ):
            raise sqlite3.DatabaseError("paid-media asset metadata is invalid")
        usage = connection.execute(
            "SELECT COALESCE(SUM(reserved_bytes),0) FROM asset_reservations"
        ).fetchone()
        if usage is None or int(usage[0]) != int(meta[10]):
            raise sqlite3.DatabaseError("paid-media asset reservation counter is corrupt")
        pending_mismatch = connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits p "
            "LEFT JOIN asset_reservations r ON r.turn_id=p.turn_id "
            "WHERE r.turn_id IS NULL OR r.state<>'active'"
        ).fetchone()
        if pending_mismatch != (0,):
            raise sqlite3.DatabaseError("paid-media pending commit is inconsistent")
        projection_digest = _authority_projection_digest(connection)
        expected_state_digest = _authority_state_digest(
            str(meta[3]),
            self.installation_id,
            self.epoch,
            int(meta[4]),
            projection_digest,
        )
        if meta[5] != expected_state_digest:
            raise sqlite3.DatabaseError(
                "paid-media asset authority projection is inconsistent"
            )

    @staticmethod
    def _root_state_from_connection(
        connection: sqlite3.Connection,
    ) -> PaidMediaAssetRootState:
        row = connection.execute(
            "SELECT database_identity,installation_id,epoch,mutation_sequence,"
            "authority_state_digest,authority_mode,recovery_floor,"
            "recovery_state_digest FROM asset_store_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("paid-media asset authority state is missing")
        return PaidMediaAssetRootState(
            database_identity=str(row[0]),
            installation_id=str(row[1]),
            epoch=int(row[2]),
            mutation_sequence=int(row[3]),
            state_digest=str(row[4]),
            authority_mode=str(row[5]),  # type: ignore[arg-type]
            recovery_floor=None if row[6] is None else int(row[6]),
            recovery_state_digest=None if row[7] is None else str(row[7]),
        )

    @staticmethod
    def _anchor_bytes(state: PaidMediaAssetRootState) -> bytes:
        if not isinstance(state, PaidMediaAssetRootState):
            raise sqlite3.DatabaseError("paid-media rollback anchor state is invalid")
        database_identity = _digest(
            state.database_identity, "database_identity"
        )
        installation_id = _digest(state.installation_id, "installation_id")
        epoch = _epoch(state.epoch)
        state_digest = _digest(state.state_digest, "authority_state_digest")
        if (
            not isinstance(state.mutation_sequence, int)
            or isinstance(state.mutation_sequence, bool)
            or not 0 <= state.mutation_sequence <= _MAX_MUTATION_SEQUENCE
        ):
            raise sqlite3.DatabaseError(
                "paid-media rollback anchor sequence is invalid"
            )
        if state.authority_mode == "normal":
            if (
                state.recovery_floor is not None
                or state.recovery_state_digest is not None
            ):
                raise sqlite3.DatabaseError(
                    "normal paid-media authority has a recovery receipt"
                )
            anchor_mode = "normal"
            recovery_floor = _ANCHOR_NONE_COUNTER
            recovery_state_digest = _ANCHOR_NONE_DIGEST
        elif state.authority_mode == "manual_only":
            if (
                not isinstance(state.recovery_floor, int)
                or isinstance(state.recovery_floor, bool)
                or not 0 <= state.recovery_floor < _MAX_MUTATION_SEQUENCE
                or state.mutation_sequence != state.recovery_floor + 1
            ):
                raise sqlite3.DatabaseError(
                    "manual-only paid-media recovery floor is invalid"
                )
            anchor_mode = "manual"
            recovery_floor = f"{state.recovery_floor:016x}"
            recovery_state_digest = _digest(
                state.recovery_state_digest,
                "recovery_state_digest",
            )
        else:
            raise sqlite3.DatabaseError(
                "paid-media rollback anchor authority mode is invalid"
            )
        return json.dumps(
            {
                "authority_mode": anchor_mode,
                "authority_state_digest": state_digest,
                "database_identity": database_identity,
                "epoch": f"{epoch:016x}",
                "format": _ANCHOR_FORMAT,
                "installation_id": installation_id,
                "mutation_sequence": f"{state.mutation_sequence:016x}",
                "recovery_floor": recovery_floor,
                "recovery_state_digest": recovery_state_digest,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _read_anchor(self) -> PaidMediaAssetRootState:
        try:
            _assert_plain(self.anchor_path, directory=False)
            self.dependencies.assert_acl(self.anchor_path, False)
            with self.anchor_path.open("rb") as stream:
                raw = stream.read(_ANCHOR_MAX_BYTES + 1)
            _assert_plain(self.anchor_path, directory=False)
            if not raw or len(raw) > _ANCHOR_MAX_BYTES:
                raise ValueError("paid-media rollback anchor size is invalid")
            decoded = json.loads(raw.decode("ascii"))
            if not isinstance(decoded, dict) or set(decoded) != {
                "authority_mode",
                "authority_state_digest",
                "database_identity",
                "epoch",
                "format",
                "installation_id",
                "mutation_sequence",
                "recovery_floor",
                "recovery_state_digest",
            }:
                raise ValueError("paid-media rollback anchor fields are invalid")
            if decoded.get("format") != _ANCHOR_FORMAT:
                raise ValueError("paid-media rollback anchor format is invalid")
            epoch_text = decoded.get("epoch")
            sequence_text = decoded.get("mutation_sequence")
            authority_mode_text = decoded.get("authority_mode")
            recovery_floor_text = decoded.get("recovery_floor")
            recovery_state_digest_text = decoded.get(
                "recovery_state_digest"
            )
            if (
                not isinstance(epoch_text, str)
                or re.fullmatch(r"[0-9a-f]{16}", epoch_text) is None
                or not isinstance(sequence_text, str)
                or re.fullmatch(r"[0-9a-f]{16}", sequence_text) is None
            ):
                raise ValueError("paid-media rollback anchor counters are invalid")
            if authority_mode_text == "normal":
                if (
                    recovery_floor_text != _ANCHOR_NONE_COUNTER
                    or recovery_state_digest_text != _ANCHOR_NONE_DIGEST
                ):
                    raise ValueError(
                        "normal paid-media rollback anchor receipt is invalid"
                    )
                authority_mode: Literal["normal", "manual_only"] = "normal"
                recovery_floor = None
                recovery_state_digest = None
            elif authority_mode_text == "manual":
                if (
                    not isinstance(recovery_floor_text, str)
                    or re.fullmatch(r"[0-9a-f]{16}", recovery_floor_text) is None
                ):
                    raise ValueError(
                        "manual paid-media rollback anchor floor is invalid"
                    )
                authority_mode = "manual_only"
                recovery_floor = int(recovery_floor_text, 16)
                recovery_state_digest = _digest(
                    recovery_state_digest_text,
                    "recovery_state_digest",
                )
            else:
                raise ValueError(
                    "paid-media rollback anchor authority mode is invalid"
                )
            state = PaidMediaAssetRootState(
                database_identity=_digest(
                    decoded.get("database_identity"), "database_identity"
                ),
                installation_id=_digest(
                    decoded.get("installation_id"), "installation_id"
                ),
                epoch=_epoch(int(epoch_text, 16)),
                mutation_sequence=int(sequence_text, 16),
                state_digest=_digest(
                    decoded.get("authority_state_digest"),
                    "authority_state_digest",
                ),
                authority_mode=authority_mode,
                recovery_floor=recovery_floor,
                recovery_state_digest=recovery_state_digest,
            )
            if raw != self._anchor_bytes(state):
                raise ValueError("paid-media rollback anchor encoding is invalid")
            return state
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise OSError("paid-media rollback anchor is unavailable") from exc

    def _write_anchor(
        self,
        state: PaidMediaAssetRootState,
        *,
        create_only: bool = False,
    ) -> None:
        encoded = self._anchor_bytes(state)
        flags = os.O_RDWR | os.O_CREAT
        flags |= os.O_EXCL if create_only else 0
        flags |= int(getattr(os, "O_BINARY", 0))
        if not create_only:
            _assert_plain(self.anchor_path, directory=False)
            self.dependencies.assert_acl(self.anchor_path, False)
        descriptor: int | None = None
        try:
            descriptor = os.open(self.anchor_path, flags, 0o600)
            existing_size = int(os.fstat(descriptor).st_size)
            if not create_only and existing_size != len(encoded):
                raise OSError("paid-media rollback anchor size changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("paid-media rollback anchor write was incomplete")
                offset += written
            os.ftruncate(descriptor, len(encoded))
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            if create_only:
                self.dependencies.harden_acl(self.anchor_path, False)
            if self._read_anchor() != state:
                raise OSError("paid-media rollback anchor verification failed")
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _validate_anchor_against_database(
        self, connection: sqlite3.Connection
    ) -> PaidMediaAssetRootState:
        database_state = self._root_state_from_connection(connection)
        try:
            anchor_state = self._read_anchor()
        except OSError as exc:
            raise sqlite3.DatabaseError(
                "paid-media rollback anchor cannot be verified"
            ) from exc
        if anchor_state != database_state:
            raise sqlite3.DatabaseError(
                "paid-media asset database rollback or replacement detected"
            )
        return database_state

    def _pending_anchor_successor(
        self, connection: sqlite3.Connection
    ) -> tuple[PaidMediaAssetRootState, PaidMediaAssetRootState] | None:
        """Recognize only one structurally exact anchor-first generation."""

        database_state = self._root_state_from_connection(connection)
        try:
            anchor_state = self._read_anchor()
        except OSError:
            return None
        if (
            database_state.mutation_sequence >= _MAX_MUTATION_SEQUENCE
            or anchor_state.database_identity != database_state.database_identity
            or anchor_state.installation_id != database_state.installation_id
            or anchor_state.epoch != database_state.epoch
            or anchor_state.mutation_sequence
            != database_state.mutation_sequence + 1
            or anchor_state.state_digest == database_state.state_digest
        ):
            return None
        return database_state, anchor_state

    def inspect_root_state(self) -> PaidMediaAssetRootState:
        """Return the exact frozen local authority proof without mutating it."""

        try:
            with self._connect() as connection:
                return self._root_state_from_connection(connection)
        except PaidMediaAssetStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError(
                "paid-media asset authority inspection failed closed"
            ) from exc

    def _assert_authoritative_entry(self) -> None:
        """Reject byte-producing work before it starts under a local fence."""

        with self._transaction_lock:
            if self._closed:
                raise PaidMediaAssetStoreError(
                    "paid-media asset store instance is closed"
                )
            if self._root_commit_pending is not None:
                raise PaidMediaAssetRootCommitPending(
                    "installation-root commit confirmation is pending"
                )
            with self._connect() as connection:
                current = self._root_state_from_connection(connection)
            if current.authority_mode != "normal":
                raise PaidMediaAssetStoreError(
                    "paid-media authority is restricted to manual recovery"
                )

    def resume_after_root_reconcile(
        self,
        expected_current_proof: PaidMediaAssetRootState,
    ) -> PaidMediaAssetRootState:
        """Clear an in-memory pending transition only after exact Root proof."""

        if not isinstance(expected_current_proof, PaidMediaAssetRootState):
            raise ValueError("expected current asset-store root proof is invalid")
        with self._transaction_lock:
            current = self.inspect_root_state()
            if current != expected_current_proof:
                raise PaidMediaAssetStoreError(
                    "paid-media asset root reconciliation proof does not match"
                )
            if (
                self._root_commit_pending is not None
                and self._root_commit_pending.after != expected_current_proof
            ):
                raise PaidMediaAssetStoreError(
                    "paid-media asset root reconciliation proof is stale"
                )
            # This method is reached by the packaged controller only after it
            # has attached the store beneath its crash-released, cross-process
            # writer ownership.  Development stores have no pre-mutation hook
            # and therefore never infer an exclusive cleanup boundary.
            if self._pre_mutation_hook is not None:
                self._reconcile_abandoned_probe_cache(expected_current_proof)
            self._root_commit_pending = None
            return current

    def _probe_cache_marker_document(
        self,
        proof: PaidMediaAssetRootState,
        *,
        generation: str,
    ) -> dict[str, object]:
        return {
            "database_identity": proof.database_identity,
            "epoch": proof.epoch,
            "generation": generation,
            "installation_id": proof.installation_id,
            "schema": TRUSTED_MEDIA_CACHE_MARKER_SCHEMA,
        }

    def _bind_probe_cache_owner(self, proof: PaidMediaAssetRootState) -> None:
        if (
            proof.installation_id != self.installation_id
            or proof.epoch != self.epoch
            or (
                self._expected_database_identity is not None
                and proof.database_identity != self._expected_database_identity
            )
        ):
            raise PaidMediaAssetStoreError(
                "trusted media cache owner proof does not match the store"
            )
        self._probe_cache_owner = TrustedMediaScratchOwner(
            installation_id=proof.installation_id,
            epoch=proof.epoch,
            database_identity=proof.database_identity,
            generation=self._probe_cache_generation,
        )

    def _parse_probe_cache_marker(
        self,
        marker_path: Path,
        proof: PaidMediaAssetRootState,
    ) -> tuple[str, _FileIdentity]:
        marker_identity = _file_identity(marker_path)
        self.dependencies.assert_acl(marker_path, False)
        with marker_path.open("rb") as handle:
            if not _same_open_identity(
                _identity_from_stat(os.fstat(handle.fileno())),
                marker_identity,
            ):
                raise PaidMediaAssetStoreError(
                    "trusted media cache owner marker handle was substituted"
                )
            raw = handle.read(_PROBE_CACHE_MARKER_MAX_BYTES + 1)
            if not _same_open_identity(
                _identity_from_stat(os.fstat(handle.fileno())),
                marker_identity,
            ):
                raise PaidMediaAssetStoreError(
                    "trusted media cache owner marker changed while reading"
                )
        _require_same_file(marker_path, marker_identity)
        if not 1 <= len(raw) <= _PROBE_CACHE_MARKER_MAX_BYTES:
            raise PaidMediaAssetStoreError(
                "trusted media cache owner marker is outside its byte bound"
            )
        try:
            decoded = json.loads(raw.decode("ascii", "strict"))
        except (UnicodeError, ValueError) as exc:
            raise PaidMediaAssetStoreError(
                "trusted media cache owner marker is invalid"
            ) from exc
        if not isinstance(decoded, dict) or set(decoded) != {
            "database_identity",
            "epoch",
            "generation",
            "installation_id",
            "schema",
        }:
            raise PaidMediaAssetStoreError(
                "trusted media cache owner marker shape is invalid"
            )
        generation = decoded.get("generation")
        if (
            decoded.get("schema") != TRUSTED_MEDIA_CACHE_MARKER_SCHEMA
            or decoded.get("installation_id") != proof.installation_id
            or decoded.get("epoch") != proof.epoch
            or decoded.get("database_identity") != proof.database_identity
            or not isinstance(generation, str)
            or _DIGEST_RE.fullmatch(generation) is None
        ):
            raise PaidMediaAssetStoreError(
                "trusted media cache owner marker authority does not match"
            )
        canonical = json.dumps(
            self._probe_cache_marker_document(proof, generation=generation),
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        if not hmac.compare_digest(raw, canonical):
            raise PaidMediaAssetStoreError(
                "trusted media cache owner marker is not canonical"
            )
        return generation, marker_identity

    def _reconcile_abandoned_probe_cache(
        self,
        proof: PaidMediaAssetRootState,
    ) -> int:
        """Remove only identity-bound cache dirs from an older store generation."""

        if (
            proof.installation_id != self.installation_id
            or proof.epoch != self.epoch
            or (
                self._expected_database_identity is not None
                and proof.database_identity != self._expected_database_identity
            )
        ):
            raise PaidMediaAssetStoreError(
                "trusted media cache cleanup proof does not match the store"
            )
        try:
            entries = sorted(
                os.scandir(self.staging_directory),
                key=lambda item: item.name,
            )
            cleanup_plan: list[
                tuple[
                    Path,
                    tuple[int, int],
                    Path,
                    tuple[tuple[Path, _FileIdentity], ...],
                ]
            ] = []
            for entry in entries:
                leaf = entry.name
                if not leaf.startswith(_PROBE_CACHE_RESERVED_PREFIX):
                    continue
                if _PROBE_CACHE_LEAF_RE.fullmatch(leaf) is None:
                    raise PaidMediaAssetStoreError(
                        "trusted media cache directory name is invalid"
                    )
                directory = self.staging_directory / leaf
                directory_info = _assert_plain(directory, directory=True)
                directory_identity = (
                    int(directory_info.st_dev),
                    int(directory_info.st_ino),
                )
                self.dependencies.assert_acl(directory, True)
                children = sorted(os.scandir(directory), key=lambda item: item.name)
                if not 1 <= len(children) <= _PROBE_CACHE_MAX_ENTRIES:
                    raise PaidMediaAssetStoreError(
                        "trusted media cache directory shape is invalid"
                )
                marker = directory / TRUSTED_MEDIA_CACHE_MARKER_NAME
                generation, marker_identity = self._parse_probe_cache_marker(
                    marker,
                    proof,
                )
                if hmac.compare_digest(generation, self._probe_cache_generation):
                    continue
                total_bytes = 0
                child_paths: list[tuple[Path, _FileIdentity]] = []
                for child in children:
                    child_path = directory / child.name
                    identity = _file_identity(child_path)
                    self.dependencies.assert_acl(child_path, False)
                    total_bytes += identity.size
                    if total_bytes > MAX_ASSET_BYTES:
                        raise PaidMediaAssetStoreError(
                            "trusted media cache directory exceeds its byte bound"
                        )
                    child_paths.append((child_path, identity))
                if not any(
                    child_path.name == TRUSTED_MEDIA_CACHE_MARKER_NAME
                    and identity == marker_identity
                    for child_path, identity in child_paths
                ):
                    raise PaidMediaAssetStoreError(
                        "trusted media cache marker identity changed during preflight"
                    )
                cleanup_plan.append(
                    (
                        directory,
                        directory_identity,
                        marker,
                        tuple(child_paths),
                    )
                )

            cleaned = 0
            for directory, directory_identity, marker, child_paths in cleanup_plan:
                current_directory = _assert_plain(directory, directory=True)
                if (
                    int(current_directory.st_dev),
                    int(current_directory.st_ino),
                ) != directory_identity:
                    raise PaidMediaAssetStoreError(
                        "trusted media cache directory changed before cleanup"
                    )
                for child_path, identity in child_paths:
                    if child_path.name != TRUSTED_MEDIA_CACHE_MARKER_NAME:
                        _require_same_file(child_path, identity)
                        child_path.unlink()
                marker_identity = next(
                    identity
                    for child_path, identity in child_paths
                    if child_path.name == TRUSTED_MEDIA_CACHE_MARKER_NAME
                )
                _require_same_file(marker, marker_identity)
                marker.unlink()
                final_directory = _assert_plain(directory, directory=True)
                if (
                    int(final_directory.st_dev),
                    int(final_directory.st_ino),
                ) != directory_identity:
                    raise PaidMediaAssetStoreError(
                        "trusted media cache directory changed during cleanup"
                    )
                directory.rmdir()
                cleaned += 1
            return cleaned
        except PaidMediaAssetStoreError:
            raise
        except (OSError, SecureStorageError) as exc:
            raise PaidMediaAssetStoreError(
                "trusted media cache startup cleanup failed closed"
            ) from exc

    def enter_authority_manual_only(
        self,
        *,
        installation_id: str,
        epoch: int,
        recovery_floor: int,
        recovery_state_digest: str,
    ) -> PaidMediaAssetRootTransition:
        """Persist one privileged no-mutation receipt for an exact Root fence."""

        installation = _digest(installation_id, "installation_id")
        normalized_epoch = _epoch(epoch)
        recovery_digest = _digest(
            recovery_state_digest,
            "recovery_state_digest",
        )
        if (
            not isinstance(recovery_floor, int)
            or isinstance(recovery_floor, bool)
            or not 0 <= recovery_floor < _MAX_MUTATION_SEQUENCE
        ):
            raise ValueError("recovery_floor is invalid")
        try:
            with self._transaction_lock:
                if self._closed:
                    raise PaidMediaAssetStoreError(
                        "paid-media asset store instance is closed"
                    )
                if self._pre_mutation_hook_active or self._root_commit_hook_active:
                    raise PaidMediaAssetStoreError(
                        "paid-media manual recovery is unavailable during a hook"
                    )
                with self._connect(validate=False) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        self._validate_schema(connection)
                        self._validate_anchor_against_database(connection)
                        self._configure_page_budget(connection)
                        current = self._root_state_from_connection(connection)
                        expected_before = PaidMediaAssetRootState(
                            database_identity=current.database_identity,
                            installation_id=installation,
                            epoch=normalized_epoch,
                            mutation_sequence=recovery_floor,
                            state_digest=recovery_digest,
                        )
                        if current.authority_mode == "manual_only":
                            if (
                                current.installation_id != installation
                                or current.epoch != normalized_epoch
                                or current.recovery_floor != recovery_floor
                                or current.recovery_state_digest != recovery_digest
                                or current.mutation_sequence != recovery_floor + 1
                            ):
                                raise PaidMediaAssetStoreError(
                                    "paid-media manual recovery receipt conflicts"
                                )
                            connection.commit()
                            self._root_commit_pending = None
                            return PaidMediaAssetRootTransition(
                                before=expected_before,
                                after=current,
                            )
                        if current != expected_before:
                            raise PaidMediaAssetStoreError(
                                "paid-media recovery fence does not match local state"
                            )
                        next_sequence = recovery_floor + 1
                        cursor = connection.execute(
                            "UPDATE asset_store_meta SET mutation_sequence=?,"
                            "authority_mode='manual_only',recovery_floor=?,"
                            "recovery_state_digest=? WHERE singleton=1 "
                            "AND installation_id=? AND epoch=? "
                            "AND database_identity=? AND mutation_sequence=? "
                            "AND authority_state_digest=? AND authority_mode='normal' "
                            "AND recovery_floor IS NULL "
                            "AND recovery_state_digest IS NULL",
                            (
                                next_sequence,
                                recovery_floor,
                                recovery_digest,
                                installation,
                                normalized_epoch,
                                current.database_identity,
                                recovery_floor,
                                recovery_digest,
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise sqlite3.DatabaseError(
                                "paid-media recovery receipt changed concurrently"
                            )
                        projection_digest = _authority_projection_digest(connection)
                        next_state_digest = _authority_state_digest(
                            current.database_identity,
                            installation,
                            normalized_epoch,
                            next_sequence,
                            projection_digest,
                        )
                        after = PaidMediaAssetRootState(
                            database_identity=current.database_identity,
                            installation_id=installation,
                            epoch=normalized_epoch,
                            mutation_sequence=next_sequence,
                            state_digest=next_state_digest,
                            authority_mode="manual_only",
                            recovery_floor=recovery_floor,
                            recovery_state_digest=recovery_digest,
                        )
                        self._write_anchor(after)
                        cursor = connection.execute(
                            "UPDATE asset_store_meta SET authority_state_digest=? "
                            "WHERE singleton=1 AND database_identity=? "
                            "AND mutation_sequence=? AND authority_state_digest=? "
                            "AND authority_mode='manual_only' "
                            "AND recovery_floor=? AND recovery_state_digest=?",
                            (
                                next_state_digest,
                                current.database_identity,
                                next_sequence,
                                recovery_digest,
                                recovery_floor,
                                recovery_digest,
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise sqlite3.DatabaseError(
                                "paid-media recovery state changed concurrently"
                            )
                        self._validate_schema(connection)
                        self._validate_anchor_against_database(connection)
                        connection.commit()
                        self._root_commit_pending = None
                        return PaidMediaAssetRootTransition(
                            before=current,
                            after=after,
                        )
                    except BaseException:
                        if connection.in_transaction:
                            connection.rollback()
                        raise
        except PaidMediaAssetStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError(
                "paid-media manual recovery failed closed"
            ) from exc

    def _unlink_private_leaf(
        self,
        directory: Path,
        leaf: str,
        pattern: re.Pattern[str],
    ) -> None:
        if pattern.fullmatch(leaf) is None:
            raise PaidMediaAssetStoreError("paid-media cleanup leaf is invalid")
        path = directory / leaf
        try:
            _assert_plain(path, directory=False)
            self.dependencies.assert_acl(path, False)
            path.unlink()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PaidMediaAssetStoreError(
                "paid-media pending file cleanup failed closed"
            ) from exc

    def reconcile_expired_pending(self) -> int:
        """Converge only tombstoned, expired crash windows; never guess paths."""

        try:
            now = float(self.dependencies.clock())
            with self._connect() as connection:
                expired = connection.execute(
                    "SELECT 1 FROM asset_pending_commits "
                    "WHERE lease_expires_at<=? LIMIT 1",
                    (now,),
                ).fetchone()
            if expired is None:
                return 0
            return self._reconcile_expired_pending()
        except PaidMediaAssetStoreError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError(
                "paid-media pending reconciliation failed closed"
            ) from exc

    def _reconcile_expired_pending(self) -> int:
        """Internal reconciliation body; callers use the fail-closed wrapper."""

        now = float(self.dependencies.clock())
        cleaned = 0
        # Hold the same BEGIN IMMEDIATE ownership used by finalizers while
        # reselecting and unlinking.  A stale read can therefore never delete
        # an object after another process promoted it to paid_media_assets.
        with self._write() as connection:
            rows = connection.execute(
                "SELECT token_hash,staging_leaf,object_leaf FROM asset_pending_commits "
                "WHERE lease_expires_at<=? ORDER BY token_hash LIMIT 64",
                (now,),
            ).fetchall()
            for token_hash, staging_leaf, object_leaf in rows:
                if connection.execute(
                    "SELECT 1 FROM paid_media_assets WHERE token_hash=?",
                    (str(token_hash),),
                ).fetchone() is not None:
                    raise PaidMediaAssetConflictError(
                        "expired pending asset was already committed"
                    )
                self._unlink_private_leaf(
                    self.staging_directory,
                    str(staging_leaf),
                    _STAGING_LEAF_RE,
                )
                self._unlink_private_leaf(
                    self.object_directory,
                    str(object_leaf),
                    _LEAF_RE,
                )
                cursor = connection.execute(
                    "DELETE FROM asset_pending_commits WHERE token_hash=? "
                    "AND staging_leaf=? AND object_leaf=? AND lease_expires_at<=?",
                    (
                        str(token_hash),
                        str(staging_leaf),
                        str(object_leaf),
                        now,
                    ),
                )
                if cursor.rowcount != 1:
                    raise PaidMediaAssetConflictError(
                        "expired pending cleanup ownership changed"
                    )
                cleaned += 1
        return cleaned

    def reserve(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        epoch: int,
        operation: str,
        reserved_bytes: int = OPERATION_RESERVATION_BYTES,
    ) -> PaidMediaAssetReservation:
        turn = _digest(turn_id, "turn_id")
        principal = _digest(principal_hash, "principal_hash")
        normalized_epoch = _epoch(epoch)
        normalized_operation = _operation(operation)
        if normalized_epoch != self.epoch:
            raise PaidMediaAssetConflictError("asset reservation epoch is not current")
        if reserved_bytes != OPERATION_RESERVATION_BYTES:
            raise ValueError("paid-media operation reservation must close the maximum")
        self.reconcile_expired_pending()
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT principal_hash,epoch,operation,reserved_bytes,state "
                    "FROM asset_reservations WHERE turn_id=?",
                    (turn,),
                ).fetchone()
                expected = (
                    principal,
                    normalized_epoch,
                    normalized_operation,
                    reserved_bytes,
                )
                if row is not None:
                    if tuple(row[:4]) != expected or row[4] == "acked":
                        raise PaidMediaAssetConflictError(
                            "paid-media reservation conflicts with existing authority"
                        )
                    self._assert_physical_headroom(connection)
                    return PaidMediaAssetReservation(turn, *expected)
                # Serialize the physical admission check with the persistent
                # logical counter.  Concurrent processes can no longer both
                # observe one operation's free space and oversell the volume.
                self._assert_physical_headroom(
                    connection,
                    additional_reserved_bytes=reserved_bytes,
                )
                meta = connection.execute(
                    "SELECT reserved_total_bytes,max_capacity_bytes "
                    "FROM asset_store_meta WHERE singleton=1"
                ).fetchone()
                if (
                    meta is None
                    or int(meta[0]) + reserved_bytes > int(meta[1])
                ):
                    raise PaidMediaAssetCapacityError(
                        "paid-media asset logical capacity is full"
                    )
                connection.execute(
                    "INSERT INTO asset_reservations "
                    "(turn_id,principal_hash,epoch,operation,reserved_bytes,"
                    "actual_bytes,state,token_set_digest,created_at) "
                    "VALUES(?,?,?,?,?,0,'active',NULL,?)",
                    (
                        turn,
                        principal,
                        normalized_epoch,
                        normalized_operation,
                        reserved_bytes,
                        float(self.dependencies.clock()),
                    ),
                )
                connection.execute(
                    "UPDATE asset_store_meta SET reserved_total_bytes="
                    "reserved_total_bytes+? WHERE singleton=1",
                    (reserved_bytes,),
                )
            return PaidMediaAssetReservation(
                turn,
                principal,
                normalized_epoch,
                normalized_operation,
                reserved_bytes,
            )
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError(
                "paid-media asset reservation failed closed"
            ) from exc

    def release_pre_provider(self, *, turn_id: str, principal_hash: str) -> bool:
        turn = _digest(turn_id, "turn_id")
        principal = _digest(principal_hash, "principal_hash")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT principal_hash,reserved_bytes,state,"
                    "EXISTS(SELECT 1 FROM paid_media_assets a "
                    "WHERE a.turn_id=r.turn_id),"
                    "EXISTS(SELECT 1 FROM asset_pending_commits p "
                    "WHERE p.turn_id=r.turn_id) FROM asset_reservations r "
                    "WHERE turn_id=?",
                    (turn,),
                ).fetchone()
                if row is None:
                    # Exact absence is an idempotent proof that no local bytes
                    # remain.  A row owned by another principal or any staged
                    # evidence below still fails closed.
                    return True
                if row != (principal, int(row[1]), "active", 0, 0):
                    return False
                connection.execute(
                    "DELETE FROM asset_reservations WHERE turn_id=?",
                    (turn,),
                )
                connection.execute(
                    "UPDATE asset_store_meta SET reserved_total_bytes="
                    "reserved_total_bytes-? WHERE singleton=1",
                    (int(row[1]),),
                )
                return True
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError(
                "paid-media asset reservation release failed closed"
            ) from exc

    def _assert_reservation_for_stage(
        self, connection: sqlite3.Connection, *, turn_id: str, ordinal: int
    ) -> None:
        row = connection.execute(
            "SELECT state FROM asset_reservations WHERE turn_id=?",
            (turn_id,),
        ).fetchone()
        if row != ("active",):
            raise PaidMediaAssetConflictError("asset reservation is not stageable")
        if not 0 <= ordinal < MAX_ASSETS:
            raise ValueError("paid-media asset ordinal is invalid")
        if connection.execute(
            "SELECT 1 FROM paid_media_assets WHERE turn_id=? AND ordinal=?",
            (turn_id, ordinal),
        ).fetchone() is not None:
            raise PaidMediaAssetConflictError("paid-media asset ordinal already exists")

    def stage_url(
        self,
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        downloader: Callable[..., object] = download_public_file,
        prepared_token: object | None = None,
        probe: Callable[..., TrustedMediaProbeResult] = probe_trusted_media_staged_file,
    ) -> PaidMediaAssetDescriptor:
        turn = _digest(turn_id, "turn_id")
        normalized_prepared_token = _prepared_token(prepared_token)
        self._assert_authoritative_entry()
        with self._write(authoritative=False) as connection:
            self._assert_reservation_for_stage(
                connection, turn_id=turn, ordinal=ordinal
            )
            self._assert_physical_headroom(connection)
        result = downloader(
            url,
            max_bytes=MAX_ASSET_BYTES,
            allowed_exact_types=tuple(sorted(SUPPORTED_MEDIA_TYPES)),
            # Agnes' output CDN has been observed returning raw image/video bytes
            # with the invalid header ``Content-Encoding: utf-8`` even after
            # ``Accept-Encoding: identity``.  This narrowly scoped exception
            # never decompresses data; the raw file still has to pass the
            # trusted full-media probe before it can be committed.
            utf8_identity_url_guard=_agnes_media_utf8_identity_url,
            temp_dir=self.staging_directory,
        )
        path = Path(str(getattr(result, "path", "")))
        try:
            content_type = str(getattr(result, "content_type", "")).lower()
            byte_length = int(getattr(result, "size", 0))
            if content_type not in SUPPORTED_MEDIA_TYPES:
                raise PaidMediaAssetStoreError("provider asset media type is unsupported")
            return self._validate_and_commit_stage(
                turn_id=turn,
                ordinal=ordinal,
                path=path,
                expected_media_type=content_type,
                expected_byte_length=byte_length,
                prepared_token=normalized_prepared_token,
                probe=probe,
            )
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def stage_base64_chunks(
        self,
        *,
        turn_id: str,
        ordinal: int,
        media_type: str,
        chunks: Iterable[str | bytes],
        prepared_token: object | None = None,
        probe: Callable[..., TrustedMediaProbeResult] = probe_trusted_media_staged_file,
    ) -> PaidMediaAssetDescriptor:
        """Strictly decode ASCII base64 by quartets directly into private staging."""

        turn = _digest(turn_id, "turn_id")
        normalized_prepared_token = _prepared_token(prepared_token)
        if media_type not in SUPPORTED_MEDIA_TYPES:
            raise ValueError("paid-media base64 media type is unsupported")
        self._assert_authoritative_entry()
        with self._write(authoritative=False) as connection:
            self._assert_reservation_for_stage(
                connection, turn_id=turn, ordinal=ordinal
            )
            self._assert_physical_headroom(connection)
        stage = self.staging_directory / f"{secrets.token_hex(32)}.stage"
        carry = b""
        total = 0
        digest = hashlib.sha256()
        try:
            with stage.open("xb") as handle:
                self._harden_file(stage)

                def consume(encoded: bytes) -> None:
                    nonlocal carry, total
                    if not encoded:
                        return
                    if any(byte in b" \t\r\n" for byte in encoded):
                        raise PaidMediaAssetStoreError(
                            "provider base64 contains whitespace"
                        )
                    # ``encoded`` is capped below, so this concatenation can
                    # never scale with the provider's entire JSON field.
                    carry += encoded
                    complete = max(0, ((len(carry) - 4) // 4) * 4)
                    block, carry = carry[:complete], carry[complete:]
                    if not block:
                        return
                    if b"=" in block:
                        raise PaidMediaAssetStoreError(
                            "provider base64 padding precedes the final quartet"
                        )
                    try:
                        decoded_block = base64.b64decode(block, validate=True)
                    except (ValueError, TypeError) as exc:
                        raise PaidMediaAssetStoreError(
                            "provider base64 is invalid"
                        ) from exc
                    if base64.b64encode(decoded_block) != block:
                        raise PaidMediaAssetStoreError(
                            "provider base64 has noncanonical pad bits"
                        )
                    total += len(decoded_block)
                    if total > MAX_ASSET_BYTES:
                        raise PaidMediaAssetCapacityError(
                            "provider asset exceeds 24 MiB"
                        )
                    handle.write(decoded_block)
                    digest.update(decoded_block)

                for raw in chunks:
                    if isinstance(raw, str):
                        for offset in range(0, len(raw), 64 * 1024):
                            try:
                                consume(raw[offset : offset + 64 * 1024].encode("ascii", "strict"))
                            except UnicodeError as exc:
                                raise PaidMediaAssetStoreError(
                                    "provider base64 is not ASCII"
                                ) from exc
                    elif isinstance(raw, bytes):
                        view = memoryview(raw)
                        try:
                            for offset in range(0, len(view), 64 * 1024):
                                consume(bytes(view[offset : offset + 64 * 1024]))
                        finally:
                            view.release()
                    else:
                        raise PaidMediaAssetStoreError(
                            "provider base64 chunk type is invalid"
                        )
                if len(carry) != 4:
                    raise PaidMediaAssetStoreError("provider base64 is empty or truncated")
                try:
                    decoded = base64.b64decode(carry, validate=True)
                except (ValueError, TypeError) as exc:
                    raise PaidMediaAssetStoreError("provider base64 final quartet is invalid") from exc
                if base64.b64encode(decoded) != carry:
                    raise PaidMediaAssetStoreError(
                        "provider base64 final quartet is noncanonical"
                    )
                total += len(decoded)
                if total > MAX_ASSET_BYTES or total <= 0:
                    raise PaidMediaAssetCapacityError("provider asset size is invalid")
                handle.write(decoded)
                digest.update(decoded)
                handle.flush()
                os.fsync(handle.fileno())
            return self._validate_and_commit_stage(
                turn_id=turn,
                ordinal=ordinal,
                path=stage,
                expected_media_type=media_type,
                expected_byte_length=total,
                expected_sha256=digest.hexdigest(),
                prepared_token=normalized_prepared_token,
                probe=probe,
            )
        finally:
            try:
                stage.unlink(missing_ok=True)
            except OSError:
                pass

    def _harden_file(self, path: Path) -> None:
        if os.name != "nt":
            os.chmod(path, 0o600)
        self.dependencies.harden_acl(path, False)
        self.dependencies.assert_acl(path, False)

    def _validate_and_commit_stage(
        self,
        *,
        turn_id: str,
        ordinal: int,
        path: Path,
        expected_media_type: str,
        expected_byte_length: int,
        expected_sha256: str | None = None,
        prepared_token: str | None = None,
        probe: Callable[..., TrustedMediaProbeResult],
    ) -> PaidMediaAssetDescriptor:
        if not 1 <= expected_byte_length <= MAX_ASSET_BYTES:
            raise PaidMediaAssetCapacityError("provider asset length is invalid")
        path = Path(os.path.abspath(os.fspath(path)))
        if path.parent != self.staging_directory:
            raise PaidMediaAssetStoreError("provider downloader escaped private staging")
        verification_handle: BinaryIO | None = None
        with self._write(authoritative=False) as connection:
            self._assert_reservation_for_stage(
                connection, turn_id=turn_id, ordinal=ordinal
            )
            self._assert_physical_headroom(connection)
        self._harden_file(path)
        identity = _file_identity(path)
        if identity.size != expected_byte_length:
            raise PaidMediaAssetStoreError("provider asset length changed in staging")
        with path.open("rb") as handle:
            if not _same_open_identity(
                _identity_from_stat(os.fstat(handle.fileno())), identity
            ):
                raise PaidMediaAssetAuthorizationError(
                    "paid-media staging handle was substituted"
                )
            sha256 = _hash_file(handle, expected_byte_length)
            if not _same_open_identity(
                _identity_from_stat(os.fstat(handle.fileno())), identity
            ):
                raise PaidMediaAssetAuthorizationError(
                    "paid-media staging changed while hashing"
                )
        _require_same_file(path, identity)
        if expected_sha256 is not None and sha256 != expected_sha256:
            raise PaidMediaAssetStoreError("provider asset digest changed in staging")
        _require_same_file(path, identity)
        scratch_owner = self._probe_cache_owner
        if scratch_owner is None:
            raise PaidMediaAssetStoreError(
                "trusted media cache owner is unavailable"
            )
        receipt = probe(
            path,
            expected_media_type=expected_media_type,
            expected_byte_length=expected_byte_length,
            expected_sha256=sha256,
            max_input_bytes=MAX_ASSET_BYTES,
            scratch_owner=scratch_owner,
        )
        _require_same_file(path, identity)
        if (
            receipt.media_type != expected_media_type
            or receipt.byte_length != expected_byte_length
            or receipt.sha256 != sha256
            or not receipt.fully_decoded
        ):
            raise PaidMediaAssetStoreError("trusted probe receipt does not match staging")
        validation_digest = _validation_receipt_digest(receipt)
        token = create_asset_token() if prepared_token is None else prepared_token
        token_hash = asset_token_hash(token)
        object_leaf = f"{secrets.token_hex(32)}.asset"
        destination = self.object_directory / object_leaf
        with self._write() as connection:
            self._assert_reservation_for_stage(
                connection, turn_id=turn_id, ordinal=ordinal
            )
            self._assert_physical_headroom(connection)
            if connection.execute(
                "SELECT 1 FROM paid_media_assets WHERE token_hash=? "
                "UNION ALL SELECT 1 FROM asset_pending_commits WHERE token_hash=? "
                "LIMIT 1",
                (token_hash, token_hash),
            ).fetchone() is not None:
                raise PaidMediaAssetConflictError(
                    "paid-media asset token already exists"
                )
            connection.execute(
                "INSERT INTO asset_pending_commits "
                "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
                "validation_receipt_sha256,staging_leaf,object_leaf,lease_expires_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    token_hash,
                    turn_id,
                    ordinal,
                    expected_media_type,
                    expected_byte_length,
                    sha256,
                    validation_digest,
                    path.name,
                    object_leaf,
                    float(self.dependencies.clock())
                    + _PENDING_COMMIT_LEASE_SECONDS,
                ),
            )
        _require_same_file(path, identity)
        os.replace(path, destination)
        self._harden_file(destination)
        destination_identity = _file_identity(destination)
        if (
            destination_identity.device != identity.device
            or destination_identity.inode != identity.inode
            or destination_identity.size != identity.size
            or destination_identity.modified_ns != identity.modified_ns
        ):
            raise PaidMediaAssetAuthorizationError(
                "paid-media object identity changed during atomic commit"
            )
        self.dependencies.after_object_replace(destination)
        try:
            directory_fd = os.open(self.object_directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Windows does not guarantee directory fsync through the CRT; file
            # fsync and SQLite FULL remain the enforceable local boundary.
            if os.name != "nt":
                raise
        try:
            with self._write() as connection:
                self._assert_reservation_for_stage(
                    connection, turn_id=turn_id, ordinal=ordinal
                )
                pending = connection.execute(
                    "SELECT turn_id,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256,staging_leaf,object_leaf "
                    "FROM asset_pending_commits WHERE token_hash=?",
                    (token_hash,),
                ).fetchone()
                if pending != (
                    turn_id,
                    ordinal,
                    expected_media_type,
                    expected_byte_length,
                    sha256,
                    validation_digest,
                    path.name,
                    object_leaf,
                ):
                    raise PaidMediaAssetConflictError(
                        "paid-media pending commit changed concurrently"
                    )
                # Re-pin and re-hash after acquiring final DB ownership.  If a
                # prior cleanup unlinked the object but rolled its SQLite
                # tombstone deletion back, the stale pending tuple alone must
                # never authorize a missing or replaced object receipt.
                try:
                    verification_handle = self._open_pinned(destination)
                except OSError as exc:
                    raise PaidMediaAssetAuthorizationError(
                        "paid-media object is unavailable before final receipt commit"
                    ) from exc
                open_identity = _identity_from_stat(
                    os.fstat(verification_handle.fileno())
                )
                if not _same_open_identity(open_identity, destination_identity):
                    raise PaidMediaAssetAuthorizationError(
                        "paid-media object changed before final receipt commit"
                    )
                if _hash_file(verification_handle, expected_byte_length) != sha256:
                    raise PaidMediaAssetAuthorizationError(
                        "paid-media object digest changed before final receipt commit"
                    )
                if not _same_open_identity(
                    _identity_from_stat(os.fstat(verification_handle.fileno())),
                    destination_identity,
                ):
                    raise PaidMediaAssetAuthorizationError(
                        "paid-media object changed during final receipt commit"
                    )
                _require_same_file(destination, destination_identity)
                connection.execute(
                    "INSERT INTO paid_media_assets "
                    "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256,object_leaf) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        token_hash,
                        turn_id,
                        ordinal,
                        expected_media_type,
                        expected_byte_length,
                        sha256,
                        validation_digest,
                        object_leaf,
                    ),
                )
                connection.execute(
                    "UPDATE asset_reservations SET actual_bytes=actual_bytes+? "
                    "WHERE turn_id=? AND state='active'",
                    (expected_byte_length, turn_id),
                )
                connection.execute(
                    "DELETE FROM asset_pending_commits WHERE token_hash=?",
                    (token_hash,),
                )
        except PaidMediaAssetRootCommitPending:
            # The object promotion and its authority projection are already
            # durable.  Deleting the object here would corrupt the committed
            # receipt merely because independent Root confirmation was lost.
            raise
        except BaseException:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            if verification_handle is not None:
                verification_handle.close()
        return PaidMediaAssetDescriptor(
            token=token,
            media_type=expected_media_type,
            byte_length=expected_byte_length,
            sha256=sha256,
            validation_receipt_sha256=validation_digest,
        )

    def describe_prepared_asset(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        epoch: int,
        operation: str,
        token: object,
    ) -> PaidMediaAssetDescriptor | None:
        turn = _digest(turn_id, "turn_id")
        principal = _digest(principal_hash, "principal_hash")
        normalized_epoch = _epoch(epoch)
        normalized_operation = _operation(operation)
        token_hash = asset_token_hash(token)
        assert isinstance(token, str)
        if normalized_epoch != self.epoch:
            raise PaidMediaAssetAuthorizationError(
                "prepared asset epoch is not current"
            )
        try:
            with self._connect() as connection:
                reservation = connection.execute(
                    "SELECT principal_hash,epoch,operation,state "
                    "FROM asset_reservations WHERE turn_id=?",
                    (turn,),
                ).fetchone()
                paid = connection.execute(
                    "SELECT turn_id,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256 FROM paid_media_assets "
                    "WHERE token_hash=?",
                    (token_hash,),
                ).fetchone()
                pending = connection.execute(
                    "SELECT turn_id FROM asset_pending_commits WHERE token_hash=?",
                    (token_hash,),
                ).fetchone()
                turn_rows = connection.execute(
                    "SELECT "
                    "(SELECT COUNT(*) FROM paid_media_assets WHERE turn_id=?),"
                    "(SELECT COUNT(*) FROM asset_pending_commits WHERE turn_id=?)",
                    (turn, turn),
                ).fetchone()
            if (
                reservation is None
                or reservation[:3]
                != (principal, normalized_epoch, normalized_operation)
                or reservation[3] not in ("active", "committed")
            ):
                raise PaidMediaAssetAuthorizationError(
                    "prepared asset reservation authority does not match"
                )
            if paid is not None and pending is not None:
                raise PaidMediaAssetConflictError(
                    "prepared asset token has conflicting rows"
                )
            if paid is not None:
                if paid[0] != turn:
                    raise PaidMediaAssetConflictError(
                        "prepared asset token belongs to another reservation"
                    )
                return PaidMediaAssetDescriptor(
                    token=token,
                    media_type=str(paid[2]),
                    byte_length=int(paid[3]),
                    sha256=str(paid[4]),
                    validation_receipt_sha256=str(paid[5]),
                )
            if pending is not None:
                return self._recover_prepared_pending(
                    turn_id=turn,
                    principal_hash=principal,
                    epoch=normalized_epoch,
                    operation=normalized_operation,
                    token=token,
                    token_hash=token_hash,
                )
            if turn_rows == (0, 0) and reservation[3] == "active":
                return None
            raise PaidMediaAssetConflictError(
                "prepared asset token does not match reservation rows"
            )
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError(
                "prepared asset description failed closed"
            ) from exc

    def _recover_prepared_pending(
        self,
        *,
        turn_id: str,
        principal_hash: str,
        epoch: int,
        operation: str,
        token: str,
        token_hash: str,
    ) -> PaidMediaAssetDescriptor:
        verification_handle: BinaryIO | None = None
        try:
            with self._write() as connection:
                reservation = connection.execute(
                    "SELECT principal_hash,epoch,operation,state "
                    "FROM asset_reservations WHERE turn_id=?",
                    (turn_id,),
                ).fetchone()
                if reservation != (
                    principal_hash,
                    epoch,
                    operation,
                    "active",
                ):
                    raise PaidMediaAssetAuthorizationError(
                        "pending prepared asset reservation authority changed"
                    )
                pending = connection.execute(
                    "SELECT turn_id,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256,staging_leaf,object_leaf "
                    "FROM asset_pending_commits WHERE token_hash=?",
                    (token_hash,),
                ).fetchone()
                if pending is None or pending[0] != turn_id:
                    raise PaidMediaAssetConflictError(
                        "pending prepared asset row does not match"
                    )
                (
                    _pending_turn,
                    ordinal,
                    media_type,
                    byte_length,
                    sha256,
                    validation_digest,
                    staging_leaf,
                    object_leaf,
                ) = pending
                if (
                    not isinstance(ordinal, int)
                    or isinstance(ordinal, bool)
                    or not 0 <= ordinal < MAX_ASSETS
                    or media_type not in SUPPORTED_MEDIA_TYPES
                    or not isinstance(byte_length, int)
                    or isinstance(byte_length, bool)
                    or not 1 <= byte_length <= MAX_ASSET_BYTES
                    or _DIGEST_RE.fullmatch(str(sha256)) is None
                    or _DIGEST_RE.fullmatch(str(validation_digest)) is None
                    or _STAGING_LEAF_RE.fullmatch(str(staging_leaf)) is None
                    or _LEAF_RE.fullmatch(str(object_leaf)) is None
                ):
                    raise PaidMediaAssetConflictError(
                        "pending prepared asset receipt is invalid"
                    )
                if connection.execute(
                    "SELECT 1 FROM paid_media_assets "
                    "WHERE token_hash=? OR (turn_id=? AND ordinal=?) LIMIT 1",
                    (token_hash, turn_id, ordinal),
                ).fetchone() is not None:
                    raise PaidMediaAssetConflictError(
                        "pending prepared asset conflicts with a paid row"
                    )

                staging_path = self.staging_directory / str(staging_leaf)
                destination = self.object_directory / str(object_leaf)
                try:
                    staging_identity = _file_identity(staging_path)
                except FileNotFoundError:
                    staging_identity = None
                try:
                    destination_identity = _file_identity(destination)
                except FileNotFoundError:
                    destination_identity = None
                if staging_identity is not None and destination_identity is not None:
                    raise PaidMediaAssetConflictError(
                        "pending prepared asset has duplicate registered files"
                    )
                if staging_identity is None and destination_identity is None:
                    raise PaidMediaAssetAuthorizationError(
                        "pending prepared asset has no registered file"
                    )
                if staging_identity is not None:
                    self.dependencies.assert_acl(self.staging_directory, True)
                    self.dependencies.assert_acl(staging_path, False)
                    if (
                        staging_identity.size != byte_length
                        or destination_identity is not None
                    ):
                        raise PaidMediaAssetAuthorizationError(
                            "pending prepared staging receipt is invalid"
                        )
                    with staging_path.open("rb") as staging_handle:
                        if not _same_open_identity(
                            _identity_from_stat(os.fstat(staging_handle.fileno())),
                            staging_identity,
                        ):
                            raise PaidMediaAssetAuthorizationError(
                                "pending prepared staging handle was substituted"
                            )
                        if _hash_file(staging_handle, byte_length) != sha256:
                            raise PaidMediaAssetAuthorizationError(
                                "pending prepared staging digest is invalid"
                            )
                        if not _same_open_identity(
                            _identity_from_stat(os.fstat(staging_handle.fileno())),
                            staging_identity,
                        ):
                            raise PaidMediaAssetAuthorizationError(
                                "pending prepared staging changed during verification"
                            )
                    _require_same_file(staging_path, staging_identity)
                    os.replace(staging_path, destination)
                    self._harden_file(destination)
                    destination_identity = _file_identity(destination)
                    if (
                        destination_identity.device != staging_identity.device
                        or destination_identity.inode != staging_identity.inode
                        or destination_identity.size != staging_identity.size
                    ):
                        raise PaidMediaAssetAuthorizationError(
                            "pending prepared object identity changed during recovery"
                        )
                assert destination_identity is not None
                verification_handle = self._open_pinned(destination)
                open_identity = _identity_from_stat(
                    os.fstat(verification_handle.fileno())
                )
                if not _same_open_identity(open_identity, destination_identity):
                    raise PaidMediaAssetAuthorizationError(
                        "pending prepared object handle was substituted"
                    )
                if _hash_file(verification_handle, byte_length) != sha256:
                    raise PaidMediaAssetAuthorizationError(
                        "pending prepared object digest is invalid"
                    )
                if not _same_open_identity(
                    _identity_from_stat(os.fstat(verification_handle.fileno())),
                    destination_identity,
                ):
                    raise PaidMediaAssetAuthorizationError(
                        "pending prepared object changed during verification"
                    )
                _require_same_file(destination, destination_identity)
                connection.execute(
                    "INSERT INTO paid_media_assets "
                    "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256,object_leaf) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        token_hash,
                        turn_id,
                        ordinal,
                        media_type,
                        byte_length,
                        sha256,
                        validation_digest,
                        object_leaf,
                    ),
                )
                updated = connection.execute(
                    "UPDATE asset_reservations SET actual_bytes=actual_bytes+? "
                    "WHERE turn_id=? AND state='active'",
                    (byte_length, turn_id),
                )
                deleted = connection.execute(
                    "DELETE FROM asset_pending_commits WHERE token_hash=?",
                    (token_hash,),
                )
                if updated.rowcount != 1 or deleted.rowcount != 1:
                    raise PaidMediaAssetConflictError(
                        "pending prepared asset changed during recovery"
                    )
            return PaidMediaAssetDescriptor(
                token=token,
                media_type=str(media_type),
                byte_length=int(byte_length),
                sha256=str(sha256),
                validation_receipt_sha256=str(validation_digest),
            )
        finally:
            if verification_handle is not None:
                verification_handle.close()

    def finalize_result(
        self, result: PaidMediaAssetResult | object
    ) -> PaidMediaAssetResult:
        # Dataclass instances cross an untrusted adapter seam too; reconstruct
        # and reparse the closed wire object instead of trusting isinstance.
        candidate = (
            asset_result_document(result)
            if isinstance(result, PaidMediaAssetResult)
            else result
        )
        parsed = parse_asset_result(candidate)
        return self._finalize_parsed_result(parsed, authority=None)

    def finalize_prepared_result(
        self,
        result: PaidMediaAssetResult | object,
        *,
        principal_hash: str,
        epoch: int,
        operation: str,
    ) -> PaidMediaAssetResult:
        candidate = (
            asset_result_document(result)
            if isinstance(result, PaidMediaAssetResult)
            else result
        )
        parsed = parse_asset_result(candidate)
        principal = _digest(principal_hash, "principal_hash")
        normalized_epoch = _epoch(epoch)
        normalized_operation = _operation(operation)
        if normalized_epoch != self.epoch:
            raise PaidMediaAssetAuthorizationError(
                "prepared result epoch is not current"
            )
        return self._finalize_parsed_result(
            parsed,
            authority=(principal, normalized_epoch, normalized_operation),
        )

    def _finalize_parsed_result(
        self,
        parsed: PaidMediaAssetResult,
        *,
        authority: tuple[str, int, str] | None,
    ) -> PaidMediaAssetResult:
        token_digest = canonical_token_set_digest(
            [asset.token for asset in parsed.assets]
        )
        expected_operation = (
            "images.create" if parsed.kind == "image" else "videos.create"
        )
        if authority is not None and authority[2] != expected_operation:
            raise PaidMediaAssetConflictError(
                "prepared result kind does not match its operation"
            )
        expected = [
            (
                asset_token_hash(asset.token),
                ordinal,
                asset.media_type,
                asset.byte_length,
                asset.sha256,
                asset.validation_receipt_sha256,
            )
            for ordinal, asset in enumerate(parsed.assets)
        ]
        try:
            with self._write() as connection:
                reservation = connection.execute(
                    "SELECT principal_hash,epoch,operation,state,token_set_digest "
                    "FROM asset_reservations "
                    "WHERE turn_id=?",
                    (parsed.turn_id,),
                ).fetchone()
                if reservation is None:
                    raise PaidMediaAssetConflictError(
                        "asset result has no reservation"
                    )
                if authority is not None and reservation[:3] != authority:
                    raise PaidMediaAssetAuthorizationError(
                        "prepared result reservation authority does not match"
                    )
                if reservation[2] != expected_operation:
                    raise PaidMediaAssetConflictError(
                        "asset result kind does not match its reservation"
                    )
                rows = connection.execute(
                    "SELECT token_hash,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256 FROM paid_media_assets "
                    "WHERE turn_id=? ORDER BY ordinal",
                    (parsed.turn_id,),
                ).fetchall()
                pending = connection.execute(
                    "SELECT COUNT(*) FROM asset_pending_commits WHERE turn_id=?",
                    (parsed.turn_id,),
                ).fetchone()
                if rows != expected or pending != (0,):
                    raise PaidMediaAssetConflictError(
                        "asset result does not match the private committed files"
                    )
                if reservation[3:] == ("committed", token_digest):
                    return parsed
                if reservation[3] == "committed":
                    raise PaidMediaAssetConflictError("committed token set changed")
                if reservation[3:] != ("active", None):
                    raise PaidMediaAssetConflictError(
                        "asset result has no active reservation"
                    )
                updated = connection.execute(
                    "UPDATE asset_reservations SET state='committed',"
                    "token_set_digest=? WHERE turn_id=? AND state='active'",
                    (token_digest, parsed.turn_id),
                )
                if updated.rowcount != 1:
                    raise PaidMediaAssetConflictError(
                        "asset reservation changed during result commit"
                    )
            return parsed
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError("asset result commit failed closed") from exc

    def locate_token(self, token: object) -> PaidMediaAssetLocator:
        hashed = asset_token_hash(token)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT a.turn_id,r.operation FROM paid_media_assets a "
                    "JOIN asset_reservations r ON r.turn_id=a.turn_id "
                    "WHERE a.token_hash=? AND r.state='committed' "
                    "AND NOT EXISTS(SELECT 1 FROM asset_ack_receipts k "
                    "WHERE k.turn_id=r.turn_id)",
                    (hashed,),
                ).fetchone()
            if row is None:
                raise PaidMediaAssetAuthorizationError("asset token is unavailable")
            return PaidMediaAssetLocator(str(row[0]), str(row[1]))
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError("asset token lookup failed closed") from exc

    def pin_authorized(
        self,
        *,
        token: object,
        durable_result: object,
        principal_hash: str,
        epoch: int,
        lease_seconds: float = 15 * 60.0,
    ) -> PinnedPaidMediaAsset:
        result_candidate = (
            asset_result_document(durable_result)
            if isinstance(durable_result, PaidMediaAssetResult)
            else durable_result
        )
        parsed = parse_asset_result(result_candidate)
        principal = _digest(principal_hash, "principal_hash")
        normalized_epoch = _epoch(epoch)
        if normalized_epoch != self.epoch:
            raise PaidMediaAssetAuthorizationError("asset epoch is not current")
        normalized_token = str(token)
        descriptor = next(
            (asset for asset in parsed.assets if asset.token == normalized_token),
            None,
        )
        if descriptor is None:
            raise PaidMediaAssetAuthorizationError(
                "asset token is absent from durable success"
            )
        hashed = asset_token_hash(normalized_token)
        lease_id = secrets.token_hex(32)
        now = float(self.dependencies.clock())
        try:
            with self._write(authoritative=False) as connection:
                connection.execute(
                    "DELETE FROM asset_read_leases WHERE expires_at<=?",
                    (now,),
                )
                row = connection.execute(
                    "SELECT a.object_leaf,a.media_type,a.byte_length,a.sha256,"
                    "a.validation_receipt_sha256,r.principal_hash,r.epoch,r.operation,"
                    "r.state FROM paid_media_assets a JOIN asset_reservations r "
                    "ON r.turn_id=a.turn_id WHERE a.token_hash=? AND a.turn_id=? "
                    "AND NOT EXISTS(SELECT 1 FROM asset_ack_receipts k "
                    "WHERE k.turn_id=r.turn_id)",
                    (hashed, parsed.turn_id),
                ).fetchone()
                expected = (
                    descriptor.media_type,
                    descriptor.byte_length,
                    descriptor.sha256,
                    descriptor.validation_receipt_sha256,
                    principal,
                    normalized_epoch,
                    "images.create" if parsed.kind == "image" else "videos.create",
                    "committed",
                )
                if row is None or tuple(row[1:]) != expected:
                    raise PaidMediaAssetAuthorizationError(
                        "asset index does not match durable success authority"
                    )
                leaf = str(row[0])
                if _LEAF_RE.fullmatch(leaf) is None:
                    raise PaidMediaAssetAuthorizationError("asset object leaf is invalid")
                connection.execute(
                    "INSERT INTO asset_read_leases(token_hash,lease_id,expires_at) "
                    "VALUES(?,?,?)",
                    (hashed, lease_id, now + float(lease_seconds)),
                )
            path = self.object_directory / leaf
            handle = self._open_pinned(path)
            try:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or int(info.st_size) != descriptor.byte_length:
                    raise PaidMediaAssetAuthorizationError("asset file receipt is invalid")
                if _hash_file(handle, descriptor.byte_length) != descriptor.sha256:
                    raise PaidMediaAssetAuthorizationError("asset file digest is invalid")
            except BaseException:
                handle.close()
                raise
            return PinnedPaidMediaAsset(
                store=self,
                token_hash=hashed,
                lease_id=lease_id,
                handle=handle,
                media_type=descriptor.media_type,
                byte_length=descriptor.byte_length,
                sha256=descriptor.sha256,
            )
        except (PaidMediaAssetProtocolError, PaidMediaAssetStoreError):
            self._release_lease(hashed, lease_id)
            raise
        except (OSError, sqlite3.Error) as exc:
            self._release_lease(hashed, lease_id)
            raise PaidMediaAssetAuthorizationError(
                "asset file could not be pinned safely"
            ) from exc

    def _open_pinned(self, path: Path) -> BinaryIO:
        if path.parent != self.object_directory:
            raise OSError("asset path escaped its private object directory")
        _assert_plain(path, directory=False)
        self.dependencies.assert_acl(self.object_directory, True)
        self.dependencies.assert_acl(path, False)
        if os.name != "nt":
            return path.open("rb")

        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        handle = kernel32.CreateFileW(
            str(path),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ only: deny write/delete/replace
            None,
            3,  # OPEN_EXISTING
            0x08000000 | 0x00200000,  # SEQUENTIAL_SCAN | OPEN_REPARSE_POINT
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if int(handle) == int(invalid):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
        except BaseException:
            kernel32.CloseHandle(handle)
            raise
        return os.fdopen(descriptor, "rb", closefd=True)

    def _release_lease(self, token_hash: str, lease_id: str) -> None:
        try:
            with self._write(authoritative=False) as connection:
                connection.execute(
                    "DELETE FROM asset_read_leases WHERE token_hash=? AND lease_id=?",
                    (token_hash, lease_id),
                )
        except Exception:
            # Expiry is a durable upper bound.  A response close error cannot
            # safely resurrect GET authority and ACK will wait for expiry.
            return

    def ack(
        self,
        *,
        ack: PaidMediaAssetAck | object,
        durable_result: PaidMediaAssetResult | object,
        principal_hash: str,
        epoch: int,
        operation: str,
        wait_timeout_seconds: float = 30.0,
    ) -> PaidMediaAssetAckResult:
        ack_candidate = (
            {
                "schema": ACK_SCHEMA,
                "turnId": ack.turn_id,
                "tokens": list(ack.tokens),
                "archiveReceiptSha256": ack.archive_receipt_sha256,
            }
            if isinstance(ack, PaidMediaAssetAck)
            else ack
        )
        parsed_ack = parse_asset_ack(ack_candidate)
        result_candidate = (
            asset_result_document(durable_result)
            if isinstance(durable_result, PaidMediaAssetResult)
            else durable_result
        )
        result = parse_asset_result(result_candidate)
        principal = _digest(principal_hash, "principal_hash")
        normalized_epoch = _epoch(epoch)
        normalized_operation = _operation(operation)
        expected_operation = "images.create" if result.kind == "image" else "videos.create"
        if (
            parsed_ack.turn_id != result.turn_id
            or normalized_operation != expected_operation
            or normalized_epoch != self.epoch
        ):
            raise PaidMediaAssetConflictError("paid-media ACK authority conflicts")
        result_tokens = [asset.token for asset in result.assets]
        ack_digest = canonical_token_set_digest(parsed_ack.tokens)
        expected_digest = canonical_token_set_digest(result_tokens)
        if ack_digest != expected_digest or set(parsed_ack.tokens) != set(result_tokens):
            raise PaidMediaAssetConflictError("paid-media ACK must contain the full token set")
        replayed = False
        now = float(self.dependencies.clock())
        try:
            with self._write() as connection:
                existing = connection.execute(
                    "SELECT principal_hash,epoch,operation,token_set_digest,"
                    "archive_receipt_sha256 FROM asset_ack_receipts WHERE turn_id=?",
                    (result.turn_id,),
                ).fetchone()
                expected_ack = (
                    principal,
                    normalized_epoch,
                    normalized_operation,
                    ack_digest,
                    parsed_ack.archive_receipt_sha256,
                )
                if existing is not None:
                    if tuple(existing) != expected_ack:
                        raise PaidMediaAssetConflictError(
                            "paid-media ACK conflicts with its durable receipt"
                        )
                    replayed = True
                else:
                    reservation = connection.execute(
                        "SELECT principal_hash,epoch,operation,state,token_set_digest "
                        "FROM asset_reservations WHERE turn_id=?",
                        (result.turn_id,),
                    ).fetchone()
                    if reservation != (
                        principal,
                        normalized_epoch,
                        normalized_operation,
                        "committed",
                        expected_digest,
                    ):
                        raise PaidMediaAssetConflictError(
                            "paid-media ACK does not match committed authority"
                        )
                    connection.execute(
                        "INSERT INTO asset_ack_receipts VALUES(?,?,?,?,?,?,?)",
                        (
                            result.turn_id,
                            principal,
                            normalized_epoch,
                            normalized_operation,
                            ack_digest,
                            parsed_ack.archive_receipt_sha256,
                            now,
                        ),
                    )
                    connection.execute(
                        "UPDATE asset_reservations SET state='acked' "
                        "WHERE turn_id=? AND state='committed'",
                        (result.turn_id,),
                    )
        except (OSError, sqlite3.Error) as exc:
            raise PaidMediaAssetStoreError("paid-media ACK CAS failed closed") from exc

        deadline = time.monotonic() + max(0.0, float(wait_timeout_seconds))
        while True:
            now = float(self.dependencies.clock())
            with self._write(authoritative=False) as connection:
                connection.execute(
                    "DELETE FROM asset_read_leases WHERE expires_at<=?",
                    (now,),
                )
                leases = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM asset_read_leases l "
                        "JOIN paid_media_assets a ON a.token_hash=l.token_hash "
                        "WHERE a.turn_id=?",
                        (result.turn_id,),
                    ).fetchone()[0]
                )
            if leases == 0:
                break
            if time.monotonic() >= deadline:
                return PaidMediaAssetAckResult(
                    replayed=replayed,
                    cleanup_complete=False,
                )
            self.dependencies.sleep(0.01)

        leaves: list[str]
        reserved_bytes = 0
        with self._connect() as connection:
            leaves = [
                str(row[0])
                for row in connection.execute(
                    "SELECT object_leaf FROM paid_media_assets WHERE turn_id=?",
                    (result.turn_id,),
                ).fetchall()
            ]
            row = connection.execute(
                "SELECT reserved_bytes FROM asset_reservations WHERE turn_id=? "
                "AND state='acked'",
                (result.turn_id,),
            ).fetchone()
            if row is not None:
                reserved_bytes = int(row[0])
        for leaf in leaves:
            if _LEAF_RE.fullmatch(leaf) is None:
                raise PaidMediaAssetStoreError("ACK cleanup object leaf is corrupt")
            path = self.object_directory / leaf
            try:
                _assert_plain(path, directory=False)
                self.dependencies.assert_acl(path, False)
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise PaidMediaAssetStoreError("ACK cleanup failed closed") from exc
        with self._write() as connection:
            if reserved_bytes:
                connection.execute(
                    "DELETE FROM asset_reservations WHERE turn_id=? AND state='acked'",
                    (result.turn_id,),
                )
                if connection.execute("SELECT changes()").fetchone() == (1,):
                    connection.execute(
                        "UPDATE asset_store_meta SET reserved_total_bytes="
                        "reserved_total_bytes-? WHERE singleton=1",
                        (reserved_bytes,),
                    )
        return PaidMediaAssetAckResult(replayed=replayed, cleanup_complete=True)

    def close(self) -> None:
        """Drain this instance's mutation/root-hook fence, then reject reuse."""

        with self._transaction_lock:
            self._closed = True


__all__ = [
    "ASSET_STORE_DATABASE_NAME",
    "ASSET_STORE_DIRECTORY_NAME",
    "DEFAULT_ASSET_STORE_DEPENDENCIES",
    "DEFAULT_STORE_CAPACITY_BYTES",
    "OPERATION_RESERVATION_BYTES",
    "PaidMediaAssetAckResult",
    "PaidMediaAssetAuthorizationError",
    "PaidMediaAssetCapacityError",
    "PaidMediaAssetConflictError",
    "PaidMediaAssetLocator",
    "PaidMediaAssetReservation",
    "PaidMediaAssetRootCommitPending",
    "PaidMediaAssetRootState",
    "PaidMediaAssetRootTransition",
    "PaidMediaAssetStore",
    "PaidMediaAssetStoreDependencies",
    "PaidMediaAssetStoreError",
    "PinnedPaidMediaAsset",
]
