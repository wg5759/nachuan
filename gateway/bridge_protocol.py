"""Authenticated, encrypted loopback transport for message bridges.

Loopback is a routing hint, not a process identity.  A crashed gateway can leave
its TCP port available for an unrelated local process.  Bridge requests therefore
never send their scoped capability or plaintext body over HTTP.  Instead this
module derives independent request/response encryption and signing keys from the
channel capability, seals every body with AES-256-GCM, and binds the envelope to
the exact HTTP method and raw path/query.

The raw path/query remains visible to the local TCP peer.  Confidential path
metadata requires an OS-authenticated transport (for example a named pipe), which
urllib/FastAPI do not provide here.

Filesystem reparse/identity checks below catch unsafe deployment paths and
fail closed on ordinary replacement anomalies.  They are not a same-SID sandbox:
an adversary with the gateway account's file privileges can still race pathname
resolution or edit the ledger, and must be isolated with a different Windows
account/AppContainer plus an OS-authenticated transport.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.request
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.responses import JSONResponse


PROTOCOL_VERSION = "1"
CONTENT_ENCODING = "nachuan-bridge-aesgcm-v1"
MAX_CLOCK_SKEW_SECONDS = 90
# AESGCM is deliberately one-shot here: the existing FastAPI media endpoints
# also materialize request.body(), so pretending to stream only the cipher stage
# would not make the end-to-end path bounded.  Keep the bridge envelope at 32MB
# (and vision at its existing 25MB endpoint limit).  Larger Feishu videos must
# fail locally before any byte reaches an unauthenticated TCP peer until the
# endpoint is refactored to an authenticated streaming/file transport.
MAX_PLAINTEXT_REQUEST_BYTES = 32 * 1024 * 1024
MAX_PLAINTEXT_RESPONSE_BYTES = 32 * 1024 * 1024
_REQUEST_PATH_LIMITS = {
    "/v1/vision": 25 * 1024 * 1024,
}

HEADER_VERSION = "X-Nachuan-Bridge-Version"
HEADER_CHANNEL = "X-Nachuan-Bridge-Channel"
HEADER_TIMESTAMP = "X-Nachuan-Bridge-Timestamp"
HEADER_REQUEST_NONCE = "X-Nachuan-Bridge-Request-Nonce"
HEADER_REQUEST_IV = "X-Nachuan-Bridge-Request-IV"
HEADER_REQUEST_SHA256 = "X-Nachuan-Bridge-Request-SHA256"
HEADER_REQUEST_SIGNATURE = "X-Nachuan-Bridge-Request-Signature"
HEADER_RESPONSE_NONCE = "X-Nachuan-Bridge-Response-Nonce"
HEADER_RESPONSE_IV = "X-Nachuan-Bridge-Response-IV"
HEADER_RESPONSE_SHA256 = "X-Nachuan-Bridge-Response-SHA256"
HEADER_RESPONSE_SIGNATURE = "X-Nachuan-Bridge-Response-Signature"

_REQUEST_HEADERS = frozenset(
    {
        HEADER_VERSION.lower(),
        HEADER_CHANNEL.lower(),
        HEADER_TIMESTAMP.lower(),
        HEADER_REQUEST_NONCE.lower(),
        HEADER_REQUEST_IV.lower(),
        HEADER_REQUEST_SHA256.lower(),
        HEADER_REQUEST_SIGNATURE.lower(),
    }
)
_RESPONSE_HEADERS = frozenset(
    {
        HEADER_VERSION.lower(),
        HEADER_CHANNEL.lower(),
        HEADER_RESPONSE_NONCE.lower(),
        HEADER_RESPONSE_IV.lower(),
        HEADER_RESPONSE_SHA256.lower(),
        HEADER_RESPONSE_SIGNATURE.lower(),
    }
)
_ALLOWED_CHANNELS = frozenset({"weixin", "feishu"})
_HEX_24 = re.compile(r"^[0-9a-f]{24}$")
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HKDF_SALT = hashlib.sha256(b"nachuan-bridge-hkdf-salt-v1\x00").digest()


class BridgeProtocolError(RuntimeError):
    """A bridge envelope is missing, malformed, unauthentic, or unsafe."""


class BridgeReplayError(BridgeProtocolError):
    """A valid request nonce has already been consumed."""


class BridgePayloadTooLarge(BridgeProtocolError):
    """A bridge body cannot be sealed within the production memory bound."""


class BridgeReplayStoreUnavailable(BridgeProtocolError):
    """Persistent replay state cannot be trusted or updated."""


class _BridgeReplayDatabaseFamilyChanged(sqlite3.DatabaseError):
    """A read-only SQLite-family snapshot changed before it could be trusted."""


@dataclass(frozen=True)
class SealedRequest:
    body: bytes
    headers: dict[str, str]
    channel: str
    method: str
    target: str
    timestamp: int
    request_nonce: str


@dataclass(frozen=True)
class OpenedRequest:
    body: bytes
    channel: str
    timestamp: int
    request_nonce: str


class NonceReplayGuard:
    """Bounded process-local replay cache.

    The timestamp window remains authoritative; cache entries live through the
    last instant at which their timestamp could still be accepted.  A gateway
    restart clears this cache, so a future OS-authenticated transport should also
    provide a persistent monotonic request sequence if restart-spanning replay is
    in scope.
    """

    def __init__(self, *, max_entries: int = 100_000) -> None:
        if not 1 <= int(max_entries) <= 1_000_000:
            raise ValueError("replay cache max_entries is out of range")
        self.max_entries = int(max_entries)
        self._entries: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def consume(
        self,
        channel: str,
        nonce: str,
        *,
        now: float,
        valid_until: float,
    ) -> None:
        identity = (channel, nonce)
        with self._lock:
            expired = [key for key, expiry in self._entries.items() if expiry < now]
            for key in expired:
                self._entries.pop(key, None)
            if identity in self._entries:
                raise BridgeReplayError("bridge request replay rejected")
            if len(self._entries) >= self.max_entries:
                raise BridgeReplayError("bridge replay cache is full")
            self._entries[identity] = max(float(now), float(valid_until))


_BRIDGE_REPLAY_APPLICATION_ID = 0x4E434252  # "NCBR"
_BRIDGE_REPLAY_SCHEMA_VERSION = 1
_BRIDGE_REPLAY_TABLE_DDL = """
CREATE TABLE bridge_nonce_replay (
    channel TEXT NOT NULL,
    nonce TEXT NOT NULL,
    valid_until INTEGER NOT NULL CHECK(valid_until >= 0),
    PRIMARY KEY(channel, nonce),
    CHECK(channel IN ('weixin', 'feishu')),
    CHECK(length(nonce) = 32)
) WITHOUT ROWID
"""
_BRIDGE_REPLAY_META_DDL = """
CREATE TABLE bridge_nonce_replay_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    row_count INTEGER NOT NULL CHECK(row_count >= 0),
    max_entries INTEGER NOT NULL CHECK(max_entries BETWEEN 1 AND 1000000),
    main_db_max_bytes INTEGER NOT NULL CHECK(
        main_db_max_bytes BETWEEN 1048576 AND 1073741824
    ),
    wal_max_bytes INTEGER NOT NULL CHECK(wal_max_bytes >= 65536),
    shm_max_bytes INTEGER NOT NULL CHECK(shm_max_bytes >= 65536),
    CHECK(wal_max_bytes <= main_db_max_bytes),
    CHECK(shm_max_bytes <= main_db_max_bytes)
) WITHOUT ROWID
"""
_BRIDGE_REPLAY_EXPIRY_DDL = """
CREATE INDEX bridge_nonce_replay_expiry
ON bridge_nonce_replay(valid_until)
"""
_BRIDGE_REPLAY_CAPACITY_DDL = """
CREATE TRIGGER bridge_nonce_replay_capacity
BEFORE INSERT ON bridge_nonce_replay
WHEN (SELECT row_count>=max_entries
      FROM bridge_nonce_replay_meta WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'bridge replay capacity reached');
END
"""
_BRIDGE_REPLAY_COUNT_INSERT_DDL = """
CREATE TRIGGER bridge_nonce_replay_count_insert
AFTER INSERT ON bridge_nonce_replay
BEGIN
    UPDATE bridge_nonce_replay_meta
    SET row_count=row_count+1 WHERE singleton=1;
END
"""
_BRIDGE_REPLAY_COUNT_DELETE_DDL = """
CREATE TRIGGER bridge_nonce_replay_count_delete
AFTER DELETE ON bridge_nonce_replay
BEGIN
    UPDATE bridge_nonce_replay_meta
    SET row_count=row_count-1 WHERE singleton=1;
END
"""
_BRIDGE_REPLAY_LIMITS_DDL = """
CREATE TRIGGER bridge_nonce_replay_limits_nonincreasing
BEFORE UPDATE OF max_entries,main_db_max_bytes,wal_max_bytes,shm_max_bytes
ON bridge_nonce_replay_meta
WHEN NEW.max_entries>OLD.max_entries
  OR NEW.main_db_max_bytes>OLD.main_db_max_bytes
  OR NEW.wal_max_bytes>OLD.wal_max_bytes
  OR NEW.shm_max_bytes>OLD.shm_max_bytes
BEGIN
    SELECT RAISE(ABORT, 'bridge replay limits cannot increase');
END
"""
_BRIDGE_REPLAY_SCHEMA_DDL = (
    _BRIDGE_REPLAY_TABLE_DDL,
    _BRIDGE_REPLAY_META_DDL,
    _BRIDGE_REPLAY_EXPIRY_DDL,
    _BRIDGE_REPLAY_CAPACITY_DDL,
    _BRIDGE_REPLAY_COUNT_INSERT_DDL,
    _BRIDGE_REPLAY_COUNT_DELETE_DDL,
    _BRIDGE_REPLAY_LIMITS_DDL,
)

_BRIDGE_REPLAY_LEGACY_TABLE_DDL = """
                    CREATE TABLE bridge_nonce_replay (
                        channel TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        valid_until INTEGER NOT NULL CHECK(valid_until >= 0),
                        PRIMARY KEY(channel, nonce),
                        CHECK(channel IN ('weixin', 'feishu')),
                        CHECK(length(nonce) = 32)
                    ) WITHOUT ROWID
""" + (" " * 20)
_BRIDGE_REPLAY_LEGACY_META_DDL = """
                    CREATE TABLE bridge_nonce_replay_meta (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        row_count INTEGER NOT NULL CHECK(row_count >= 0)
                    ) WITHOUT ROWID
""" + (" " * 20)
_BRIDGE_REPLAY_LEGACY_EXPIRY_DDL = (
    "CREATE INDEX IF NOT EXISTS bridge_nonce_replay_expiry "
    "ON bridge_nonce_replay(valid_until)"
)
_BRIDGE_REPLAY_LEGACY_DDL = (
    _BRIDGE_REPLAY_LEGACY_TABLE_DDL,
    _BRIDGE_REPLAY_LEGACY_EXPIRY_DDL,
    _BRIDGE_REPLAY_LEGACY_META_DDL,
)


def _bridge_replay_schema_rows(
    connection: sqlite3.Connection,
) -> tuple[tuple[object, object, object, object], ...]:
    return tuple(
        connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "ORDER BY type,name,tbl_name"
        ).fetchall()
    )


@lru_cache(maxsize=4)
def _materialized_bridge_replay_schema(
    statements: tuple[str, ...],
) -> tuple[tuple[object, object, object, object], ...]:
    with closing(sqlite3.connect(":memory:")) as connection:
        for statement in statements:
            connection.execute(statement)
        return _bridge_replay_schema_rows(connection)


class PersistentNonceReplayGuard:
    """Crash-persistent, bounded SQLite authority for one-time request nonces.

    Full integrity/schema reconciliation is a startup cost.  The request hot path
    uses the unique primary key plus a transactionally maintained one-row counter;
    it does not scan all retained nonces or run ``quick_check`` per message.
    """

    _TABLE = "bridge_nonce_replay"
    _META_TABLE = "bridge_nonce_replay_meta"
    _REPARSE_ATTRIBUTE = int(
        getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )

    def __init__(
        self,
        db_path: str | Path,
        *,
        max_entries: int = 50_000,
        cleanup_batch: int = 512,
        main_db_max_bytes: int = 16 * 1024 * 1024,
        wal_max_bytes: int = 4 * 1024 * 1024,
        shm_max_bytes: int = 2 * 1024 * 1024,
        busy_timeout_ms: int = 500,
    ) -> None:
        self.path = Path(os.path.abspath(os.fspath(db_path)))
        self.max_entries = int(max_entries)
        self.cleanup_batch = int(cleanup_batch)
        self.main_db_max_bytes = int(main_db_max_bytes)
        self.wal_max_bytes = int(wal_max_bytes)
        self.shm_max_bytes = int(shm_max_bytes)
        self.busy_timeout_ms = int(busy_timeout_ms)
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._file_identity: os.stat_result | None = None
        self._trusted_data_version: int | None = None
        self._trusted_schema_version: int | None = None
        if not 1 <= self.max_entries <= 1_000_000:
            raise ValueError("persistent replay max_entries is out of range")
        if not 1 <= self.cleanup_batch <= 10_000:
            raise ValueError("persistent replay cleanup_batch is out of range")
        if not 1024 * 1024 <= self.main_db_max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("persistent replay database limit is out of range")
        if not 64 * 1024 <= self.wal_max_bytes <= self.main_db_max_bytes:
            raise ValueError("persistent replay WAL limit is out of range")
        if not 64 * 1024 <= self.shm_max_bytes <= self.main_db_max_bytes:
            raise ValueError("persistent replay SHM limit is out of range")
        if not 1 <= self.busy_timeout_ms <= 10_000:
            raise ValueError("persistent replay busy timeout is out of range")
        try:
            # The supervisor owns creation/ACLs of the data directory.  Never
            # mkdir through an unchecked junction: a missing parent is a startup
            # error, not authority to write somewhere else.
            if not self.path.parent.exists():
                raise BridgeReplayStoreUnavailable(
                    "persistent replay parent directory is unavailable"
                )
            self._assert_safe_path_components()
            self._assert_preconnect_file_bounds()
            (
                preflight_generation,
                preflight_identity,
                preflight_family,
            ) = self._stabilized_preflight_generation()
            if self._database_family_presence() != preflight_family:
                (
                    preflight_generation,
                    preflight_identity,
                    preflight_family,
                ) = self._stabilized_preflight_generation()
            connection = self._open_connection(allow_create=True)
            try:
                self._begin_immediate_with_retry(connection)
                generation = self._classify_generation(connection)
                opened_identity = os.lstat(self.path)
                if preflight_identity is not None and not os.path.samestat(
                    preflight_identity, opened_identity
                ):
                    raise sqlite3.DatabaseError(
                        "persistent replay identity changed before locked open"
                    )
                peer_converged = (
                    preflight_generation != "current" and generation == "current"
                )
                if generation != preflight_generation and not peer_converged:
                    raise sqlite3.DatabaseError(
                        "persistent replay database changed during initialization"
                    )
                if generation == "empty":
                    self._provision_current(connection)
                elif generation == "legacy":
                    self._migrate_legacy(connection)
                elif generation == "current_unversioned":
                    self._validate_connection(connection, require_identity=False)
                    connection.execute(
                        f"PRAGMA application_id={_BRIDGE_REPLAY_APPLICATION_ID}"
                    )
                    connection.execute(
                        f"PRAGMA user_version={_BRIDGE_REPLAY_SCHEMA_VERSION}"
                    )
                elif generation == "current":
                    self._validate_connection(connection)
                else:
                    raise sqlite3.DatabaseError(
                        "unsupported persistent replay generation"
                    )
                self._synchronize_limits(connection)
                self._validate_connection(connection)
                connection.commit()
                self._apply_runtime_profile(connection)
                self._validate_connection(
                    connection,
                    quick_check=True,
                    require_runtime_profile=True,
                )
            except BaseException:
                connection.close()
                raise
            self._connection = connection
            self._file_identity = os.lstat(self.path)
            (
                self._trusted_data_version,
                self._trusted_schema_version,
            ) = self._database_versions(connection)
            self._assert_file_bounds()
        except BridgeReplayStoreUnavailable:
            self.close()
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            self.close()
            raise BridgeReplayStoreUnavailable(
                "persistent bridge replay store is unavailable"
            ) from exc

    def _readonly_uri(self, *, wal_aware: bool = False) -> str:
        suffix = "?mode=ro" if wal_aware else "?mode=ro&immutable=1"
        return (
            "file:"
            + quote(self.path.as_posix(), safe="/:")
            + suffix
        )

    def _database_family_presence(self) -> dict[str, bool]:
        self._assert_safe_path_components()
        return {
            suffix: Path(f"{self.path}{suffix}").is_file()
            for suffix in ("", "-wal", "-shm", "-journal")
        }

    def _preflight_generation(
        self,
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        presence = self._database_family_presence()
        if not presence[""]:
            if any(presence[suffix] for suffix in ("-wal", "-shm", "-journal")):
                raise _BridgeReplayDatabaseFamilyChanged(
                    "persistent replay main database is missing beside unstable sidecars"
                )
            return "empty", None, presence
        if presence["-journal"]:
            raise _BridgeReplayDatabaseFamilyChanged(
                "persistent replay rollback journal has not stabilized"
            )
        if presence["-wal"] != presence["-shm"]:
            raise _BridgeReplayDatabaseFamilyChanged(
                "persistent replay WAL and SHM sidecars have not stabilized"
            )
        identity = os.lstat(self.path)
        with closing(
            sqlite3.connect(
                self._readonly_uri(wal_aware=presence["-wal"]),
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
                isolation_level=None,
            )
        ) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            try:
                check = connection.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise sqlite3.DatabaseError(
                        "persistent replay integrity check failed"
                    )
                generation = self._classify_generation(connection)
            finally:
                connection.rollback()
        if self._database_family_presence() != presence:
            raise _BridgeReplayDatabaseFamilyChanged(
                "persistent replay database family changed during read-only preflight"
            )
        try:
            current_identity = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise _BridgeReplayDatabaseFamilyChanged(
                "persistent replay database disappeared during read-only preflight"
            ) from exc
        if not os.path.samestat(identity, current_identity):
            raise _BridgeReplayDatabaseFamilyChanged(
                "persistent replay database identity changed during read-only preflight"
            )
        return generation, identity, presence

    def _stabilized_preflight_generation(
        self,
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        last_change: _BridgeReplayDatabaseFamilyChanged | None = None
        # First-open schema materialization can legitimately keep a rollback
        # journal visible for several seconds on a loaded Windows host.  Keep
        # the wait bounded, read-only, and proportional to the caller's lock
        # budget; a stable foreign journal still fails closed at the deadline.
        stabilization_seconds = max(
            2.0,
            min(10.0, (self.busy_timeout_ms / 1000) * 5.0),
        )
        deadline = time.monotonic() + stabilization_seconds
        while True:
            try:
                return self._preflight_generation()
            except _BridgeReplayDatabaseFamilyChanged as exc:
                last_change = exc
                if time.monotonic() < deadline:
                    time.sleep(0.025)
                    continue
                break
        raise sqlite3.DatabaseError(
            "persistent replay database family did not stabilize during preflight"
        ) from last_change

    @staticmethod
    def _classify_generation(connection: sqlite3.Connection) -> str:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        rows = _bridge_replay_schema_rows(connection)
        current = _materialized_bridge_replay_schema(_BRIDGE_REPLAY_SCHEMA_DDL)
        if (
            application_id == _BRIDGE_REPLAY_APPLICATION_ID
            and user_version == _BRIDGE_REPLAY_SCHEMA_VERSION
            and rows == current
        ):
            return "current"
        if application_id == 0 and user_version == 0:
            if not rows:
                return "empty"
            if rows == _materialized_bridge_replay_schema(
                _BRIDGE_REPLAY_LEGACY_DDL
            ):
                return "legacy"
            if rows == current:
                return "current_unversioned"
        raise sqlite3.DatabaseError("unknown persistent replay database family")

    def _insert_meta(self, connection: sqlite3.Connection, row_count: int) -> None:
        connection.execute(
            "INSERT INTO bridge_nonce_replay_meta("
            "singleton,row_count,max_entries,main_db_max_bytes,"
            "wal_max_bytes,shm_max_bytes) VALUES(1,?,?,?,?,?)",
            (
                row_count,
                self.max_entries,
                self.main_db_max_bytes,
                self.wal_max_bytes,
                self.shm_max_bytes,
            ),
        )

    def _provision_current(self, connection: sqlite3.Connection) -> None:
        for statement in _BRIDGE_REPLAY_SCHEMA_DDL:
            connection.execute(statement)
        self._insert_meta(connection, 0)
        connection.execute(
            f"PRAGMA application_id={_BRIDGE_REPLAY_APPLICATION_ID}"
        )
        connection.execute(
            f"PRAGMA user_version={_BRIDGE_REPLAY_SCHEMA_VERSION}"
        )

    def _migrate_legacy(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT channel,nonce,valid_until FROM bridge_nonce_replay "
            "ORDER BY channel,nonce"
        ).fetchall()
        if len(rows) > self.max_entries:
            raise sqlite3.DatabaseError(
                "legacy persistent replay ledger exceeds capacity"
            )
        for channel, nonce, valid_until in rows:
            if (
                str(channel) not in {"weixin", "feishu"}
                or re.fullmatch(r"[0-9a-f]{32}", str(nonce)) is None
                or not isinstance(valid_until, int)
                or isinstance(valid_until, bool)
                or int(valid_until) < 0
            ):
                raise sqlite3.DatabaseError(
                    "legacy persistent replay row is invalid"
                )
        connection.execute("DROP INDEX bridge_nonce_replay_expiry")
        connection.execute("DROP TABLE bridge_nonce_replay_meta")
        connection.execute(
            "ALTER TABLE bridge_nonce_replay RENAME TO bridge_nonce_replay_legacy"
        )
        for statement in _BRIDGE_REPLAY_SCHEMA_DDL:
            connection.execute(statement)
        self._insert_meta(connection, 0)
        connection.executemany(
            "INSERT INTO bridge_nonce_replay(channel,nonce,valid_until) "
            "VALUES(?,?,?)",
            rows,
        )
        connection.execute("DROP TABLE bridge_nonce_replay_legacy")
        connection.execute(
            f"PRAGMA application_id={_BRIDGE_REPLAY_APPLICATION_ID}"
        )
        connection.execute(
            f"PRAGMA user_version={_BRIDGE_REPLAY_SCHEMA_VERSION}"
        )

    def _synchronize_limits(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT max_entries,main_db_max_bytes,wal_max_bytes,shm_max_bytes,"
            "typeof(max_entries),typeof(main_db_max_bytes),"
            "typeof(wal_max_bytes),typeof(shm_max_bytes) "
            "FROM bridge_nonce_replay_meta WHERE singleton=1"
        ).fetchone()
        if row is None or tuple(row[4:]) != ("integer",) * 4:
            raise sqlite3.DatabaseError("persistent replay limits are missing")
        stored = tuple(int(value) for value in row[:4])
        if (
            not 1 <= stored[0] <= 1_000_000
            or not 1024 * 1024 <= stored[1] <= 1024 * 1024 * 1024
            or not 64 * 1024 <= stored[2] <= stored[1]
            or not 64 * 1024 <= stored[3] <= stored[1]
        ):
            raise sqlite3.DatabaseError("persistent replay limits are invalid")
        effective = (
            min(self.max_entries, stored[0]),
            min(self.main_db_max_bytes, stored[1]),
            min(self.wal_max_bytes, stored[2]),
            min(self.shm_max_bytes, stored[3]),
        )
        if effective != stored:
            connection.execute(
                "UPDATE bridge_nonce_replay_meta SET max_entries=?,"
                "main_db_max_bytes=?,wal_max_bytes=?,shm_max_bytes=? "
                "WHERE singleton=1",
                effective,
            )
        (
            self.max_entries,
            self.main_db_max_bytes,
            self.wal_max_bytes,
            self.shm_max_bytes,
        ) = effective

    def _apply_runtime_profile(self, connection: sqlite3.Connection) -> None:
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if not journal_mode or str(journal_mode[0]).lower() != "wal":
            raise sqlite3.DatabaseError("persistent replay WAL unavailable")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA journal_size_limit={self.wal_max_bytes}")
        connection.execute("PRAGMA wal_autocheckpoint=128")
        self._apply_page_cap(connection)

    def _apply_page_cap(self, connection: sqlite3.Connection) -> None:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size <= 0 or page_size > 65536:
            raise sqlite3.DatabaseError("invalid persistent replay page size")
        max_pages = max(1, self.main_db_max_bytes // page_size)
        if page_count > max_pages:
            raise sqlite3.DatabaseError("persistent replay database is oversized")
        configured_max = int(
            connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        )
        if configured_max > max_pages:
            raise sqlite3.DatabaseError(
                "persistent replay page limit was not applied"
            )

    @classmethod
    def _is_reparse(cls, info: os.stat_result) -> bool:
        return bool(
            int(getattr(info, "st_file_attributes", 0)) & cls._REPARSE_ATTRIBUTE
        )

    def _assert_safe_path_components(self) -> None:
        current = self.path.parent
        while True:
            info = os.lstat(current)
            if not stat.S_ISDIR(info.st_mode) or self._is_reparse(info) or current.is_symlink():
                raise BridgeReplayStoreUnavailable(
                    "persistent replay path contains a reparse component"
                )
            if current.parent == current:
                break
            current = current.parent
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
            Path(f"{self.path}-journal"),
        ):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or self._is_reparse(info) or candidate.is_symlink():
                raise BridgeReplayStoreUnavailable(
                    "persistent replay database is not an ordinary file"
                )

    def _assert_file_bounds(self) -> None:
        self._assert_safe_path_components()
        try:
            current = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise BridgeReplayStoreUnavailable(
                "persistent replay database disappeared"
            ) from exc
        if self._file_identity is not None and not os.path.samestat(
            self._file_identity, current
        ):
            raise BridgeReplayStoreUnavailable(
                "persistent replay database identity changed"
            )
        if current.st_size < 0 or current.st_size > self.main_db_max_bytes:
            raise BridgeReplayStoreUnavailable(
                "persistent replay database exceeds its byte limit"
            )
        self._assert_sidecar_bounds()

    def _assert_sidecar_bounds(self) -> None:
        wal = Path(f"{self.path}-wal")
        try:
            wal_size = wal.stat().st_size
        except FileNotFoundError:
            wal_size = 0
        if wal_size < 0 or wal_size > self.wal_max_bytes:
            raise BridgeReplayStoreUnavailable(
                "persistent replay WAL exceeds its byte limit"
            )
        shm = Path(f"{self.path}-shm")
        try:
            shm_size = shm.stat().st_size
        except FileNotFoundError:
            shm_size = 0
        if shm_size < 0 or shm_size > self.shm_max_bytes:
            raise BridgeReplayStoreUnavailable(
                "persistent replay SHM exceeds its byte limit"
            )

    def _assert_preconnect_file_bounds(self) -> None:
        try:
            main_size = self.path.stat().st_size
        except FileNotFoundError:
            main_size = 0
        if main_size < 0 or main_size > self.main_db_max_bytes:
            raise BridgeReplayStoreUnavailable(
                "persistent replay database exceeds its byte limit"
            )
        self._assert_sidecar_bounds()

    def _open_connection(
        self, *, allow_create: bool = False
    ) -> sqlite3.Connection:
        self._assert_safe_path_components()
        if not allow_create and not self.path.is_file():
            raise BridgeReplayStoreUnavailable(
                "persistent replay database is unavailable"
            )
        existed = self.path.exists()
        before = os.lstat(self.path) if existed else None
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA journal_size_limit={self.wal_max_bytes}")
            connection.execute("PRAGMA wal_autocheckpoint=128")
            self._assert_safe_path_components()
            after = os.lstat(self.path)
            if (
                not stat.S_ISREG(after.st_mode)
                or self._is_reparse(after)
                or self.path.is_symlink()
                or (before is not None and not os.path.samestat(before, after))
            ):
                raise BridgeReplayStoreUnavailable(
                    "persistent replay database identity changed"
                )
            return connection
        except Exception:
            connection.close()
            raise

    def _validate_connection(
        self,
        connection: sqlite3.Connection,
        *,
        require_identity: bool = True,
        quick_check: bool = False,
        require_runtime_profile: bool = False,
    ) -> None:
        if require_identity:
            application_id = connection.execute("PRAGMA application_id").fetchone()
            user_version = connection.execute("PRAGMA user_version").fetchone()
            if (
                not application_id
                or not user_version
                or int(application_id[0]) != _BRIDGE_REPLAY_APPLICATION_ID
                or int(user_version[0]) != _BRIDGE_REPLAY_SCHEMA_VERSION
            ):
                raise sqlite3.DatabaseError(
                    "persistent replay database identity is invalid"
                )
        if _bridge_replay_schema_rows(connection) != (
            _materialized_bridge_replay_schema(_BRIDGE_REPLAY_SCHEMA_DDL)
        ):
            raise sqlite3.DatabaseError("unexpected persistent replay schema")
        if quick_check:
            check = connection.execute("PRAGMA quick_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError(
                    "persistent replay integrity check failed"
                )
        if require_runtime_profile:
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if (
                not journal_mode
                or str(journal_mode[0]).lower() != "wal"
                or not synchronous
                or int(synchronous[0]) != 2
            ):
                raise sqlite3.DatabaseError(
                    "persistent replay runtime profile is invalid"
                )
        meta_rows = connection.execute(
            "SELECT singleton,row_count,max_entries,main_db_max_bytes,"
            "wal_max_bytes,shm_max_bytes,typeof(singleton),typeof(row_count),"
            "typeof(max_entries),typeof(main_db_max_bytes),"
            "typeof(wal_max_bytes),typeof(shm_max_bytes) "
            "FROM bridge_nonce_replay_meta"
        ).fetchall()
        if len(meta_rows) != 1 or tuple(meta_rows[0][6:]) != ("integer",) * 6:
            raise sqlite3.DatabaseError(
                "persistent replay metadata is invalid"
            )
        meta = tuple(int(value) for value in meta_rows[0][:6])
        if (
            meta[0] != 1
            or meta[1] < 0
            or not 1 <= meta[2] <= 1_000_000
            or not 1024 * 1024 <= meta[3] <= 1024 * 1024 * 1024
            or not 64 * 1024 <= meta[4] <= meta[3]
            or not 64 * 1024 <= meta[5] <= meta[3]
        ):
            raise sqlite3.DatabaseError(
                "persistent replay metadata is invalid"
            )
        invalid_row = connection.execute(
            "SELECT 1 FROM bridge_nonce_replay WHERE "
            "typeof(channel)!='text' OR channel NOT IN ('weixin','feishu') OR "
            "typeof(nonce)!='text' OR length(nonce)!=32 OR "
            "nonce GLOB '*[^0-9a-f]*' OR "
            "typeof(valid_until)!='integer' OR valid_until<0 LIMIT 1"
        ).fetchone()
        if invalid_row is not None:
            raise sqlite3.DatabaseError("persistent replay row is invalid")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        if page_size <= 0 or page_size > 65536:
            raise sqlite3.DatabaseError("invalid persistent replay page size")
        max_pages = max(1, meta[3] // page_size)
        configured_max = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_count > max_pages or (
            require_runtime_profile and configured_max > max_pages
        ):
            raise sqlite3.DatabaseError("persistent replay database is oversized")
        actual_count = int(
            connection.execute(f"SELECT COUNT(*) FROM {self._TABLE}").fetchone()[0]
        )
        if meta[1] != actual_count or actual_count > meta[2]:
            raise sqlite3.DatabaseError("persistent replay row counter is invalid")

    @staticmethod
    def _database_versions(connection: sqlite3.Connection) -> tuple[int, int]:
        data_version = connection.execute("PRAGMA data_version").fetchone()
        schema_version = connection.execute("PRAGMA schema_version").fetchone()
        if (
            not data_version
            or not schema_version
            or not isinstance(data_version[0], int)
            or isinstance(data_version[0], bool)
            or not isinstance(schema_version[0], int)
            or isinstance(schema_version[0], bool)
        ):
            raise sqlite3.DatabaseError(
                "persistent replay database versions are invalid"
            )
        return int(data_version[0]), int(schema_version[0])

    @staticmethod
    def _is_transient_lock(exc: sqlite3.OperationalError) -> bool:
        code = getattr(exc, "sqlite_errorcode", None)
        if isinstance(code, int) and (code & 0xFF) in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }:
            return True
        rendered = str(exc).lower()
        return "locked" in rendered or "busy" in rendered

    def _begin_runtime_transaction(
        self, connection: sqlite3.Connection
    ) -> None:
        self._begin_immediate_with_retry(connection)
        data_version, schema_version = self._database_versions(connection)
        if (
            data_version != self._trusted_data_version
            or schema_version != self._trusted_schema_version
        ):
            if self._classify_generation(connection) != "current":
                raise sqlite3.DatabaseError(
                    "persistent replay generation changed"
                )
            self._validate_connection(connection)
            self._synchronize_limits(connection)
            self._validate_connection(connection)
        self._apply_page_cap(connection)

    def _begin_immediate_with_retry(
        self, connection: sqlite3.Connection
    ) -> None:
        for attempt in range(3):
            try:
                connection.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                if attempt >= 2 or not self._is_transient_lock(exc):
                    raise
                time.sleep(0.01 * (2**attempt))

    def _commit_runtime_transaction(
        self, connection: sqlite3.Connection
    ) -> None:
        connection.commit()
        (
            self._trusted_data_version,
            self._trusted_schema_version,
        ) = self._database_versions(connection)

    def consume(
        self,
        channel: str,
        nonce: str,
        *,
        now: float,
        valid_until: float,
    ) -> None:
        normalized_channel = _normalized_channel(channel)
        if not _HEX_32.fullmatch(str(nonce or "")):
            raise BridgeReplayError("invalid bridge replay nonce")
        observed_now = int(float(now))
        expiry = int(float(valid_until))
        if expiry < observed_now or expiry > observed_now + 2 * MAX_CLOCK_SKEW_SECONDS + 2:
            raise BridgeReplayError("invalid bridge replay expiry")
        with self._lock:
            connection = self._connection
            if connection is None:
                raise BridgeReplayStoreUnavailable(
                    "persistent bridge replay store is closed"
                )
            try:
                self._assert_file_bounds()
                self._begin_runtime_transaction(connection)
                deleted = connection.execute(
                    f"""
                    DELETE FROM {self._TABLE}
                    WHERE (channel, nonce) IN (
                        SELECT channel, nonce
                        FROM {self._TABLE}
                        WHERE valid_until < ?
                        ORDER BY valid_until
                        LIMIT ?
                    )
                    """,
                    (observed_now, self.cleanup_batch),
                ).rowcount
                if deleted < 0 or deleted > self.cleanup_batch:
                    raise sqlite3.DatabaseError(
                        "persistent replay cleanup count is invalid"
                    )
                count_row = connection.execute(
                    f"SELECT row_count, typeof(row_count) FROM {self._META_TABLE} "
                    "WHERE singleton=1"
                ).fetchone()
                if (
                    count_row is None
                    or count_row[1] != "integer"
                    or int(count_row[0]) < 0
                    or int(count_row[0]) > self.max_entries
                ):
                    raise sqlite3.DatabaseError(
                        "persistent replay row counter is invalid"
                    )
                if int(count_row[0]) >= self.max_entries:
                    # Keep bounded cleanup even though this request fails closed.
                    self._commit_runtime_transaction(connection)
                    self._assert_file_bounds()
                    raise BridgeReplayError(
                        "persistent bridge replay store is full"
                    )
                try:
                    connection.execute(
                        f"INSERT INTO {self._TABLE}(channel, nonce, valid_until) "
                        "VALUES (?, ?, ?)",
                        (normalized_channel, nonce, expiry),
                    )
                except sqlite3.IntegrityError as exc:
                    connection.rollback()
                    if "capacity reached" in str(exc).lower():
                        raise BridgeReplayError(
                            "persistent bridge replay store is full"
                        ) from exc
                    raise BridgeReplayError(
                        "bridge request replay rejected"
                    ) from exc
                self._commit_runtime_transaction(connection)
                # The nonce is durably consumed once commit returns.  A
                # subsequent filesystem/bounds probe may still fail, but it
                # must cross the protocol boundary as store-unavailable rather
                # than leaking a raw OSError to the bridge caller.
                self._assert_file_bounds()
            except BridgeReplayError:
                raise
            except BridgeReplayStoreUnavailable:
                raise
            except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
                raise BridgeReplayStoreUnavailable(
                    "persistent bridge replay store is unavailable"
                ) from exc

    def close(self) -> None:
        with self._lock:
            connection, self._connection = self._connection, None
            self._trusted_data_version = None
            self._trusted_schema_version = None
            self._file_identity = None
            if connection is not None:
                connection.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _field(value: str | bytes) -> bytes:
    encoded = value if isinstance(value, bytes) else str(value).encode("utf-8")
    return len(encoded).to_bytes(8, "big") + encoded


def _canonical(domain: bytes, *values: str | bytes) -> bytes:
    return domain + b"".join(_field(value) for value in values)


def _normalized_channel(channel: str) -> str:
    value = str(channel or "").strip().lower()
    if value not in _ALLOWED_CHANNELS:
        raise BridgeProtocolError("unsupported bridge channel")
    return value


def canonical_target(url_or_target: str) -> str:
    """Return the exact ASCII path plus raw query used by the HTTP request."""

    value = str(url_or_target or "")
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc:
        if parsed.fragment:
            raise BridgeProtocolError("bridge URL fragments are not allowed")
        path = parsed.path or "/"
        query = parsed.query
    else:
        if "#" in value:
            raise BridgeProtocolError("bridge target fragments are not allowed")
        path, separator, query = value.partition("?")
        path = path or "/"
        if not separator:
            query = ""
    target = path + (f"?{query}" if query else "")
    if len(target.encode("ascii", "strict")) > 8192:
        raise BridgeProtocolError("bridge target is too long")
    if not target.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in target):
        raise BridgeProtocolError("invalid bridge target")
    return target


def asgi_raw_target(scope: Mapping[str, Any]) -> str:
    raw_path = scope.get("raw_path")
    if raw_path is None:
        path = str(scope.get("path") or "/")
    else:
        path = bytes(raw_path).decode("ascii", "strict") or "/"
    raw_query = bytes(scope.get("query_string") or b"").decode("ascii", "strict")
    return canonical_target(path + (f"?{raw_query}" if raw_query else ""))


def _derive_key(secret: str, channel: str, purpose: bytes) -> bytes:
    raw_secret = str(secret or "").encode("utf-8")
    if not raw_secret:
        raise BridgeProtocolError("bridge capability is unavailable")
    normalized = _normalized_channel(channel)
    info = _canonical(b"nachuan-bridge-hkdf-info-v1\x00", normalized, purpose)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=info,
    ).derive(raw_secret)


def _request_aad(
    channel: str,
    method: str,
    target: str,
    timestamp: int,
    request_nonce: str,
) -> bytes:
    return _canonical(
        b"nachuan-bridge-request-aad-v1\x00",
        channel,
        method,
        target,
        str(timestamp),
        request_nonce,
    )


def _request_mac_message(
    channel: str,
    method: str,
    target: str,
    timestamp: int,
    request_nonce: str,
    request_iv: str,
    ciphertext_sha256: str,
) -> bytes:
    return _canonical(
        b"nachuan-bridge-request-signature-v1\x00",
        channel,
        method,
        target,
        str(timestamp),
        request_nonce,
        request_iv,
        ciphertext_sha256,
    )


def _response_aad(channel: str, request_nonce: str, status: int) -> bytes:
    return _canonical(
        b"nachuan-bridge-response-aad-v1\x00",
        channel,
        request_nonce,
        str(int(status)),
    )


def _response_mac_message(
    channel: str,
    request_nonce: str,
    status: int,
    response_iv: str,
    ciphertext_sha256: str,
) -> bytes:
    return _canonical(
        b"nachuan-bridge-response-signature-v1\x00",
        channel,
        request_nonce,
        str(int(status)),
        response_iv,
        ciphertext_sha256,
    )


def seal_request(
    *,
    secret: str,
    channel: str,
    method: str,
    url_or_target: str,
    body: bytes = b"",
    timestamp: int | None = None,
    request_nonce: str | None = None,
    request_iv: bytes | None = None,
) -> SealedRequest:
    normalized_channel = _normalized_channel(channel)
    normalized_method = str(method or "").upper()
    if not normalized_method or not normalized_method.isascii():
        raise BridgeProtocolError("invalid bridge method")
    target = canonical_target(url_or_target)
    plaintext = bytes(body)
    path = target.partition("?")[0]
    plaintext_limit = _REQUEST_PATH_LIMITS.get(path, MAX_PLAINTEXT_REQUEST_BYTES)
    if len(plaintext) > plaintext_limit:
        raise BridgePayloadTooLarge(
            f"bridge request exceeds {plaintext_limit // (1024 * 1024)}MB sealed limit"
        )
    observed_timestamp = int(time.time()) if timestamp is None else int(timestamp)
    nonce = request_nonce or secrets.token_hex(16)
    iv = request_iv or secrets.token_bytes(12)
    if not _HEX_32.fullmatch(nonce) or len(iv) != 12:
        raise BridgeProtocolError("invalid bridge request nonce")
    aad = _request_aad(
        normalized_channel,
        normalized_method,
        target,
        observed_timestamp,
        nonce,
    )
    ciphertext = AESGCM(
        _derive_key(secret, normalized_channel, b"request-aead")
    ).encrypt(iv, plaintext, aad)
    iv_hex = iv.hex()
    digest = hashlib.sha256(ciphertext).hexdigest()
    signature = hmac.new(
        _derive_key(secret, normalized_channel, b"request-signing"),
        _request_mac_message(
            normalized_channel,
            normalized_method,
            target,
            observed_timestamp,
            nonce,
            iv_hex,
            digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    return SealedRequest(
        body=ciphertext,
        headers={
            HEADER_VERSION: PROTOCOL_VERSION,
            HEADER_CHANNEL: normalized_channel,
            HEADER_TIMESTAMP: str(observed_timestamp),
            HEADER_REQUEST_NONCE: nonce,
            HEADER_REQUEST_IV: iv_hex,
            HEADER_REQUEST_SHA256: digest,
            HEADER_REQUEST_SIGNATURE: signature,
            "Content-Encoding": CONTENT_ENCODING,
        },
        channel=normalized_channel,
        method=normalized_method,
        target=target,
        timestamp=observed_timestamp,
        request_nonce=nonce,
    )


def _single_header(headers: Mapping[str, Any] | Any, name: str) -> str:
    values: list[str] = []
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = [str(value) for value in (get_all(name) or [])]
    else:
        for key, value in getattr(headers, "items", lambda: [])():
            if str(key).lower() == name.lower():
                values.append(str(value))
    if len(values) != 1:
        raise BridgeProtocolError(f"missing or duplicate {name}")
    return values[0]


def open_request(
    *,
    secret: str,
    method: str,
    target: str,
    headers: Mapping[str, Any] | Any,
    body: bytes,
    replay_guard: NonceReplayGuard,
    now: float | None = None,
) -> OpenedRequest:
    if _single_header(headers, "Content-Encoding") != CONTENT_ENCODING:
        raise BridgeProtocolError("invalid bridge content encoding")
    if _single_header(headers, HEADER_VERSION) != PROTOCOL_VERSION:
        raise BridgeProtocolError("unsupported bridge protocol version")
    channel = _normalized_channel(_single_header(headers, HEADER_CHANNEL))
    timestamp_text = _single_header(headers, HEADER_TIMESTAMP)
    nonce = _single_header(headers, HEADER_REQUEST_NONCE)
    iv_hex = _single_header(headers, HEADER_REQUEST_IV)
    claimed_digest = _single_header(headers, HEADER_REQUEST_SHA256)
    claimed_signature = _single_header(headers, HEADER_REQUEST_SIGNATURE)
    if (
        not timestamp_text.isdecimal()
        or len(timestamp_text) not in (10, 11, 12)
        or not _HEX_32.fullmatch(nonce)
        or not _HEX_24.fullmatch(iv_hex)
        or not _HEX_64.fullmatch(claimed_digest)
        or not _HEX_64.fullmatch(claimed_signature)
    ):
        raise BridgeProtocolError("malformed bridge request envelope")
    timestamp = int(timestamp_text)
    observed_now = float(time.time() if now is None else now)
    if abs(observed_now - timestamp) > MAX_CLOCK_SKEW_SECONDS:
        raise BridgeProtocolError("bridge request timestamp is outside the allowed window")
    normalized_method = str(method or "").upper()
    normalized_target = canonical_target(target)
    ciphertext = bytes(body)
    path = normalized_target.partition("?")[0]
    plaintext_limit = _REQUEST_PATH_LIMITS.get(path, MAX_PLAINTEXT_REQUEST_BYTES)
    if len(ciphertext) > plaintext_limit + 16:
        raise BridgePayloadTooLarge("bridge request exceeds sealed limit")
    digest = hashlib.sha256(ciphertext).hexdigest()
    if not hmac.compare_digest(digest, claimed_digest):
        raise BridgeProtocolError("bridge request body digest mismatch")
    expected_signature = hmac.new(
        _derive_key(secret, channel, b"request-signing"),
        _request_mac_message(
            channel,
            normalized_method,
            normalized_target,
            timestamp,
            nonce,
            iv_hex,
            digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, claimed_signature):
        raise BridgeProtocolError("bridge request signature is invalid")
    replay_guard.consume(
        channel,
        nonce,
        now=observed_now,
        valid_until=timestamp + MAX_CLOCK_SKEW_SECONDS + 1,
    )
    try:
        plaintext = AESGCM(_derive_key(secret, channel, b"request-aead")).decrypt(
            bytes.fromhex(iv_hex),
            ciphertext,
            _request_aad(
                channel,
                normalized_method,
                normalized_target,
                timestamp,
                nonce,
            ),
        )
    except (InvalidTag, ValueError) as exc:
        raise BridgeProtocolError("bridge request authentication failed") from exc
    if len(plaintext) > plaintext_limit:
        raise BridgePayloadTooLarge("bridge request exceeds sealed limit")
    return OpenedRequest(
        body=plaintext,
        channel=channel,
        timestamp=timestamp,
        request_nonce=nonce,
    )


def seal_response(
    *,
    secret: str,
    channel: str,
    request_nonce: str,
    status: int,
    body: bytes,
    response_iv: bytes | None = None,
) -> tuple[bytes, dict[str, str]]:
    normalized_channel = _normalized_channel(channel)
    if not _HEX_32.fullmatch(request_nonce):
        raise BridgeProtocolError("invalid bridge response request nonce")
    plaintext = bytes(body)
    if len(plaintext) > MAX_PLAINTEXT_RESPONSE_BYTES:
        raise BridgePayloadTooLarge("bridge response exceeds 32MB sealed limit")
    iv = response_iv or secrets.token_bytes(12)
    if len(iv) != 12:
        raise BridgeProtocolError("invalid bridge response nonce")
    ciphertext = AESGCM(
        _derive_key(secret, normalized_channel, b"response-aead")
    ).encrypt(
        iv,
        plaintext,
        _response_aad(normalized_channel, request_nonce, int(status)),
    )
    iv_hex = iv.hex()
    digest = hashlib.sha256(ciphertext).hexdigest()
    signature = hmac.new(
        _derive_key(secret, normalized_channel, b"response-signing"),
        _response_mac_message(
            normalized_channel,
            request_nonce,
            int(status),
            iv_hex,
            digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    return ciphertext, {
        HEADER_VERSION: PROTOCOL_VERSION,
        HEADER_CHANNEL: normalized_channel,
        HEADER_RESPONSE_NONCE: request_nonce,
        HEADER_RESPONSE_IV: iv_hex,
        HEADER_RESPONSE_SHA256: digest,
        HEADER_RESPONSE_SIGNATURE: signature,
        "Content-Encoding": CONTENT_ENCODING,
    }


def open_response(
    *,
    secret: str,
    channel: str,
    request_nonce: str,
    status: int,
    headers: Mapping[str, Any] | Any,
    body: bytes,
) -> bytes:
    normalized_channel = _normalized_channel(channel)
    if _single_header(headers, "Content-Encoding") != CONTENT_ENCODING:
        raise BridgeProtocolError("engine response is not sealed")
    if _single_header(headers, HEADER_VERSION) != PROTOCOL_VERSION:
        raise BridgeProtocolError("unsupported engine response protocol")
    if _normalized_channel(_single_header(headers, HEADER_CHANNEL)) != normalized_channel:
        raise BridgeProtocolError("engine response channel mismatch")
    response_nonce = _single_header(headers, HEADER_RESPONSE_NONCE)
    iv_hex = _single_header(headers, HEADER_RESPONSE_IV)
    claimed_digest = _single_header(headers, HEADER_RESPONSE_SHA256)
    claimed_signature = _single_header(headers, HEADER_RESPONSE_SIGNATURE)
    if (
        not hmac.compare_digest(response_nonce, request_nonce)
        or not _HEX_24.fullmatch(iv_hex)
        or not _HEX_64.fullmatch(claimed_digest)
        or not _HEX_64.fullmatch(claimed_signature)
    ):
        raise BridgeProtocolError("malformed engine response envelope")
    ciphertext = bytes(body)
    if len(ciphertext) > MAX_PLAINTEXT_RESPONSE_BYTES + 16:
        raise BridgePayloadTooLarge("engine response exceeds sealed limit")
    digest = hashlib.sha256(ciphertext).hexdigest()
    if not hmac.compare_digest(digest, claimed_digest):
        raise BridgeProtocolError("engine response body digest mismatch")
    expected_signature = hmac.new(
        _derive_key(secret, normalized_channel, b"response-signing"),
        _response_mac_message(
            normalized_channel,
            request_nonce,
            int(status),
            iv_hex,
            digest,
        ),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, claimed_signature):
        raise BridgeProtocolError("engine response signature is invalid")
    try:
        return AESGCM(_derive_key(secret, normalized_channel, b"response-aead")).decrypt(
            bytes.fromhex(iv_hex),
            ciphertext,
            _response_aad(normalized_channel, request_nonce, int(status)),
        )
    except (InvalidTag, ValueError) as exc:
        raise BridgeProtocolError("engine response authentication failed") from exc


def build_urllib_request(
    *,
    url: str,
    secret: str,
    channel: str,
    method: str,
    body: bytes = b"",
    headers: Mapping[str, str] | None = None,
) -> tuple[urllib.request.Request, SealedRequest]:
    supplied = {str(name).lower(): str(value) for name, value in (headers or {}).items()}
    reserved = _REQUEST_HEADERS | _RESPONSE_HEADERS | {
        "authorization",
        "content-encoding",
        "content-length",
    }
    if supplied.keys() & reserved:
        raise BridgeProtocolError("caller supplied a reserved bridge transport header")
    sealed = seal_request(
        secret=secret,
        channel=channel,
        method=method,
        url_or_target=url,
        body=body,
    )
    request_headers = dict(headers or {})
    request_headers.update(sealed.headers)
    request = urllib.request.Request(
        url,
        data=sealed.body,
        method=sealed.method,
        headers=request_headers,
    )
    return request, sealed


def request_bridge_bytes(
    opener: Any,
    *,
    url: str,
    secret: str,
    channel: str,
    method: str,
    body: bytes = b"",
    headers: Mapping[str, str] | None = None,
    timeout: float,
    max_response_bytes: int = MAX_PLAINTEXT_RESPONSE_BYTES,
) -> bytes:
    """Send one sealed urllib request and return only an authenticated plaintext body."""

    if not 1 <= int(max_response_bytes) <= MAX_PLAINTEXT_RESPONSE_BYTES:
        raise ValueError("invalid bridge response limit")
    request, sealed = build_urllib_request(
        url=url,
        secret=secret,
        channel=channel,
        method=method,
        body=body,
        headers=headers,
    )
    try:
        response = opener.open(request, timeout=float(timeout))
    except urllib.error.HTTPError as exc:
        encrypted = exc.read(int(max_response_bytes) + 17)
        if len(encrypted) > int(max_response_bytes) + 16:
            raise BridgePayloadTooLarge("engine error response exceeds sealed limit") from exc
        plaintext = open_response(
            secret=secret,
            channel=sealed.channel,
            request_nonce=sealed.request_nonce,
            status=int(exc.code),
            headers=exc.headers,
            body=encrypted,
        )
        raise urllib.error.HTTPError(
            exc.url,
            exc.code,
            exc.reason,
            exc.headers,
            io.BytesIO(plaintext),
        ) from None
    with response:
        encrypted = response.read(int(max_response_bytes) + 17)
        status = int(getattr(response, "status", None) or response.getcode())
        response_headers = response.headers
    if len(encrypted) > int(max_response_bytes) + 16:
        raise BridgePayloadTooLarge("engine response exceeds sealed limit")
    return open_response(
        secret=secret,
        channel=sealed.channel,
        request_nonce=sealed.request_nonce,
        status=status,
        headers=response_headers,
        body=encrypted,
    )


class BridgeProtocolMiddleware:
    """ASGI envelope terminator placed before admission and endpoint auth."""

    def __init__(
        self,
        app: Any,
        *,
        key_provider: Callable[[], Mapping[str, str]],
        replay_guard: NonceReplayGuard | None = None,
        wall_clock: Callable[[], float] | None = None,
    ) -> None:
        self.app = app
        self._key_provider = key_provider
        self._replay_guard = replay_guard or NonceReplayGuard()
        self._wall_clock = wall_clock or time.time

    @staticmethod
    def _header_map(scope: Mapping[str, Any]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for raw_name, raw_value in scope.get("headers") or []:
            name = bytes(raw_name).decode("latin-1").lower()
            result.setdefault(name, []).append(bytes(raw_value).decode("latin-1"))
        return result

    @staticmethod
    async def _read_request_body(receive: Callable[[], Any]) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                raise BridgeProtocolError("bridge client disconnected")
            if message.get("type") != "http.request":
                continue
            chunk = bytes(message.get("body") or b"")
            total += len(chunk)
            if total > MAX_PLAINTEXT_REQUEST_BYTES + 16:
                raise BridgePayloadTooLarge("bridge request exceeds sealed limit")
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks)

    @staticmethod
    def _replace_request_headers(scope: dict[str, Any], plaintext_length: int) -> None:
        retained: list[tuple[bytes, bytes]] = []
        for raw_name, raw_value in scope.get("headers") or []:
            name = bytes(raw_name).lower()
            decoded = name.decode("latin-1")
            if (
                decoded in _REQUEST_HEADERS
                or decoded in _RESPONSE_HEADERS
                or name in {b"content-encoding", b"content-length", b"authorization"}
            ):
                continue
            retained.append((bytes(raw_name), bytes(raw_value)))
        retained.append((b"content-length", str(int(plaintext_length)).encode("ascii")))
        scope["headers"] = retained

    @staticmethod
    def _sealed_response_headers(
        original: list[tuple[bytes, bytes]],
        transport_headers: Mapping[str, str],
        body_length: int,
    ) -> list[tuple[bytes, bytes]]:
        retained: list[tuple[bytes, bytes]] = []
        for raw_name, raw_value in original:
            name = bytes(raw_name).decode("latin-1").lower()
            if (
                name in _REQUEST_HEADERS
                or name in _RESPONSE_HEADERS
                or name in {"content-encoding", "content-length"}
            ):
                continue
            retained.append((bytes(raw_name), bytes(raw_value)))
        retained.extend(
            (name.lower().encode("ascii"), value.encode("ascii"))
            for name, value in transport_headers.items()
        )
        retained.append((b"content-length", str(int(body_length)).encode("ascii")))
        retained.append((b"cache-control", b"no-store"))
        return retained

    async def _reject(self, scope: dict[str, Any], receive: Any, send: Any, detail: str) -> None:
        await JSONResponse(
            {"detail": detail},
            status_code=401,
            headers={"Cache-Control": "no-store"},
        )(scope, receive, send)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        header_values = self._header_map(scope)
        has_protocol_header = any(name in _REQUEST_HEADERS for name in header_values) or any(
            value.lower() == CONTENT_ENCODING
            for value in header_values.get("content-encoding", ())
        )
        if not has_protocol_header:
            await self.app(scope, receive, send)
            return
        if any(len(header_values.get(name, ())) != 1 for name in _REQUEST_HEADERS) or len(
            header_values.get("content-encoding", ())
        ) != 1:
            await self._reject(scope, receive, send, "malformed bridge envelope")
            return
        if header_values.get("authorization"):
            await self._reject(scope, receive, send, "ambiguous bridge authorization")
            return
        try:
            channel = _normalized_channel(header_values[HEADER_CHANNEL.lower()][0])
            keys = {
                _normalized_channel(name): str(value or "").strip()
                for name, value in self._key_provider().items()
                if str(value or "").strip()
            }
            secret = keys.get(channel, "")
            if not secret:
                raise BridgeProtocolError("bridge capability is unavailable")
            encrypted = await self._read_request_body(receive)
            opened = open_request(
                secret=secret,
                method=str(scope.get("method") or ""),
                target=asgi_raw_target(scope),
                headers={name: values[0] for name, values in header_values.items()},
                body=encrypted,
                replay_guard=self._replay_guard,
                now=float(self._wall_clock()),
            )
        except (BridgeProtocolError, UnicodeError, ValueError):
            await self._reject(scope, receive, send, "invalid bridge envelope")
            return

        state = scope.setdefault("state", {})
        state["nachuan_bridge_credential"] = f"bridge:{opened.channel}"
        # Admission receives only the same domain-separated irreversible bucket
        # used for ordinary Bearer credentials; it never receives the capability.
        from gateway.admission import hash_bearer_token

        state["nachuan_bridge_bucket_hash"] = hash_bearer_token(secret)
        self._replace_request_headers(scope, len(opened.body))
        delivered = False

        async def plaintext_receive() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": opened.body, "more_body": False}

        start_message: dict[str, Any] | None = None
        response_chunks: list[bytes] = []
        response_size = 0

        async def capture_send(message: dict[str, Any]) -> None:
            nonlocal start_message, response_size
            message_type = message.get("type")
            if message_type == "http.response.start":
                if start_message is not None:
                    raise BridgeProtocolError("duplicate bridge response start")
                start_message = dict(message)
                return
            if message_type == "http.response.body":
                chunk = bytes(message.get("body") or b"")
                response_size += len(chunk)
                if response_size <= MAX_PLAINTEXT_RESPONSE_BYTES:
                    response_chunks.append(chunk)
                return
            raise BridgeProtocolError("unsupported bridge response event")

        await self.app(scope, plaintext_receive, capture_send)
        if start_message is None:
            raise BridgeProtocolError("bridge endpoint returned no response")
        status = int(start_message.get("status") or 500)
        if response_size > MAX_PLAINTEXT_RESPONSE_BYTES:
            status = 502
            plaintext_response = json.dumps(
                {"detail": "bridge response exceeds sealed limit"},
                separators=(",", ":"),
            ).encode("utf-8")
        else:
            plaintext_response = b"".join(response_chunks)
        sealed_body, sealed_headers = seal_response(
            secret=secret,
            channel=opened.channel,
            request_nonce=opened.request_nonce,
            status=status,
            body=plaintext_response,
        )
        response_start = dict(start_message)
        response_start["status"] = status
        response_start["headers"] = self._sealed_response_headers(
            list(start_message.get("headers") or []),
            sealed_headers,
            len(sealed_body),
        )
        await send(response_start)
        await send({"type": "http.response.body", "body": sealed_body, "more_body": False})
