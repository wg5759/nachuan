"""Durable, fenced idempotency for inbound channel agent turns.

Only hashes of credentials, message keys, and request semantics are retained.
The one permitted plaintext payload is the successful business response needed
to replay a reply after the bridge loses its HTTP response.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Any, Literal
from urllib.parse import quote

from gateway.sqlite_runtime import enable_wal_with_deadline

_PRINCIPAL_DOMAIN = b"nachuan-durable-channel-principal-v1\x00"
_KEY_DOMAIN = b"nachuan-durable-channel-message-key-v1\x00"
_CHANNEL_KEY_PREFIXES = {"weixin": "wxmsg-v1:", "feishu": "fsmsg-v1:"}
_KEY_RE = re.compile(r"\A(?:wx|fs)msg-v1:[0-9a-f]{64}\Z")
_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_ERROR_CODE_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
_MAX_RESPONSE_BYTES = 1024 * 1024
_DEFAULT_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
_ABSOLUTE_MAX_RECORDS = 1_000_000
_ABSOLUTE_TOTAL_RESPONSE_BYTES = 1024 * 1024 * 1024
_DEFAULT_MAX_DATABASE_BYTES = 256 * 1024 * 1024
_MAX_WAL_BYTES = 64 * 1024 * 1024
_APPLICATION_ID = 0x4E435749  # "NCWI"
_SCHEMA_VERSION = 1


_LEGACY_TABLE_DDL = """
                    CREATE TABLE weixin_agent_idempotency (
                        principal_hash TEXT NOT NULL CHECK(length(principal_hash) = 64),
                        key_hash TEXT NOT NULL CHECK(length(key_hash) = 64),
                        request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                        status TEXT NOT NULL CHECK(status IN ('processing','succeeded','failed')),
                        fencing_token TEXT NOT NULL,
                        lease_expires_at REAL NOT NULL,
                        attempt_count INTEGER NOT NULL CHECK(attempt_count >= 1),
                        response_json TEXT,
                        last_error_code TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY(principal_hash, key_hash)
                    ) WITHOUT ROWID

""".rstrip("\n")

# This exact declaration shipped in an early regression fixture.  It is kept as
# an explicit, closed migration generation; it is not a fuzzy column match.
_LEGACY_FIXTURE_TABLE_DDL = """
            CREATE TABLE weixin_agent_idempotency (
                principal_hash TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                fencing_token TEXT NOT NULL,
                lease_expires_at REAL NOT NULL,
                attempt_count INTEGER NOT NULL,
                response_json TEXT,
                last_error_code TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(principal_hash, key_hash)
            ) WITHOUT ROWID

""".rstrip("\n")

_PREVIOUS_CURRENT_TABLE_DDL = """
                    CREATE TABLE weixin_agent_idempotency (
                        principal_hash TEXT NOT NULL CHECK(length(principal_hash) = 64),
                        key_hash TEXT NOT NULL CHECK(length(key_hash) = 64),
                        recovery_id TEXT NOT NULL CHECK(
                            length(recovery_id) = 64
                            AND recovery_id NOT GLOB '*[^0-9a-f]*'
                        ),
                        request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                        status TEXT NOT NULL CHECK(status IN ('processing','succeeded','failed')),
                        fencing_token TEXT NOT NULL,
                        lease_expires_at REAL NOT NULL,
                        attempt_count INTEGER NOT NULL CHECK(attempt_count >= 1),
                        response_json TEXT,
                        last_error_code TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        provider_phase INTEGER NOT NULL DEFAULT 0
                            CHECK(provider_phase IN (0,1)),
                        PRIMARY KEY(principal_hash, key_hash)
                    ) WITHOUT ROWID

""".rstrip("\n")

_CURRENT_TABLE_DDL = """
CREATE TABLE weixin_agent_idempotency (
    principal_hash TEXT NOT NULL CHECK(length(principal_hash) = 64),
    key_hash TEXT NOT NULL CHECK(length(key_hash) = 64),
    recovery_id TEXT NOT NULL CHECK(
        length(recovery_id) = 64
        AND recovery_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
    status TEXT NOT NULL CHECK(status IN ('processing','succeeded','failed')),
    fencing_token TEXT NOT NULL,
    lease_expires_at REAL NOT NULL,
    attempt_count INTEGER NOT NULL CHECK(attempt_count >= 1),
    response_json TEXT,
    last_error_code TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    provider_phase INTEGER NOT NULL DEFAULT 0 CHECK(provider_phase IN (0,1)),
    PRIMARY KEY(principal_hash, key_hash)
) WITHOUT ROWID
"""

_META_TABLE_DDL = f"""
CREATE TABLE weixin_agent_idempotency_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    record_count INTEGER NOT NULL CHECK(record_count >= 0),
    response_bytes INTEGER NOT NULL CHECK(response_bytes >= 0),
    max_records INTEGER NOT NULL CHECK(
        max_records >= 1 AND max_records <= {_ABSOLUTE_MAX_RECORDS}
    ),
    max_total_response_bytes INTEGER NOT NULL CHECK(
        max_total_response_bytes >= 1
        AND max_total_response_bytes <= {_ABSOLUTE_TOTAL_RESPONSE_BYTES}
    ),
    max_database_bytes INTEGER NOT NULL CHECK(
        max_database_bytes >= 1048576 AND max_database_bytes <= 4294967296
    )
) WITHOUT ROWID
"""

_CAPACITY_INSERT_DDL = """
CREATE TRIGGER weixin_idempotency_capacity_insert
BEFORE INSERT ON weixin_agent_idempotency
WHEN (SELECT record_count >= max_records
      FROM weixin_agent_idempotency_meta WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'idempotency record capacity reached');
END
"""

_CAPACITY_RESPONSE_UPDATE_DDL = """
CREATE TRIGGER weixin_idempotency_capacity_response_update
BEFORE UPDATE OF response_json ON weixin_agent_idempotency
WHEN (SELECT response_bytes-
        COALESCE(length(CAST(OLD.response_json AS BLOB)),0)+
        COALESCE(length(CAST(NEW.response_json AS BLOB)),0)>
        max_total_response_bytes
      FROM weixin_agent_idempotency_meta WHERE singleton=1)
BEGIN
    SELECT RAISE(ABORT, 'idempotency response capacity reached');
END
"""

_CAPACITY_LIMITS_NONINCREASING_DDL = """
CREATE TRIGGER weixin_idempotency_capacity_limits_nonincreasing
BEFORE UPDATE OF max_records,max_total_response_bytes,max_database_bytes
ON weixin_agent_idempotency_meta
WHEN NEW.max_records>OLD.max_records
  OR NEW.max_total_response_bytes>OLD.max_total_response_bytes
  OR NEW.max_database_bytes>OLD.max_database_bytes
BEGIN
    SELECT RAISE(ABORT, 'idempotency capacity limits cannot increase');
END
"""

_COUNT_INSERT_DDL = """
CREATE TRIGGER weixin_idempotency_count_insert
AFTER INSERT ON weixin_agent_idempotency
BEGIN
    UPDATE weixin_agent_idempotency_meta
    SET record_count=record_count+1,
        response_bytes=response_bytes+
            COALESCE(length(CAST(NEW.response_json AS BLOB)),0)
    WHERE singleton=1;
END
"""

_COUNT_DELETE_DDL = """
CREATE TRIGGER weixin_idempotency_count_delete
AFTER DELETE ON weixin_agent_idempotency
BEGIN
    UPDATE weixin_agent_idempotency_meta
    SET record_count=record_count-1,
        response_bytes=response_bytes-
            COALESCE(length(CAST(OLD.response_json AS BLOB)),0)
    WHERE singleton=1;
END
"""

_COUNT_RESPONSE_UPDATE_DDL = """
CREATE TRIGGER weixin_idempotency_count_response_update
AFTER UPDATE OF response_json ON weixin_agent_idempotency
BEGIN
    UPDATE weixin_agent_idempotency_meta
    SET response_bytes=response_bytes-
            COALESCE(length(CAST(OLD.response_json AS BLOB)),0)+
            COALESCE(length(CAST(NEW.response_json AS BLOB)),0)
    WHERE singleton=1;
END
"""

_UPDATED_INDEX_DDL = """
CREATE INDEX weixin_idempotency_updated_idx
ON weixin_agent_idempotency(updated_at)
"""

_RESPONSE_PRUNE_INDEX_DDL = """
CREATE INDEX weixin_idempotency_response_prune_idx
ON weixin_agent_idempotency(updated_at)
WHERE status='succeeded' AND response_json IS NOT NULL
"""

_RECOVERY_INDEX_DDL = """
CREATE UNIQUE INDEX weixin_idempotency_recovery_idx
ON weixin_agent_idempotency(recovery_id)
"""

_RECOVERY_REQUIRED_INSERT_DDL = """
CREATE TRIGGER weixin_idempotency_recovery_required_insert
BEFORE INSERT ON weixin_agent_idempotency
WHEN NEW.recovery_id IS NULL
  OR length(NEW.recovery_id) <> 64
  OR NEW.recovery_id GLOB '*[^0-9a-f]*'
BEGIN
    SELECT RAISE(ABORT, 'valid recovery_id is required');
END
"""

_RECOVERY_IMMUTABLE_DDL = """
CREATE TRIGGER weixin_idempotency_recovery_immutable
BEFORE UPDATE OF recovery_id ON weixin_agent_idempotency
WHEN NEW.recovery_id IS NOT OLD.recovery_id
BEGIN
    SELECT RAISE(ABORT, 'recovery_id is immutable');
END
"""

_HISTORICAL_META_TABLE_DDL = """
                    CREATE TABLE weixin_agent_idempotency_meta (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        record_count INTEGER NOT NULL CHECK(record_count >= 0),
                        response_bytes INTEGER NOT NULL CHECK(response_bytes >= 0)
                    ) WITHOUT ROWID

""".rstrip("\n")

_HISTORICAL_COUNT_INSERT_DDL = """
                    CREATE TRIGGER weixin_idempotency_count_insert
                    AFTER INSERT ON weixin_agent_idempotency
                    BEGIN
                        UPDATE weixin_agent_idempotency_meta
                        SET record_count=record_count+1,
                            response_bytes=response_bytes+
                                COALESCE(length(CAST(NEW.response_json AS BLOB)),0)
                        WHERE singleton=1;
                    END

""".rstrip("\n")

_HISTORICAL_COUNT_DELETE_DDL = """
                    CREATE TRIGGER weixin_idempotency_count_delete
                    AFTER DELETE ON weixin_agent_idempotency
                    BEGIN
                        UPDATE weixin_agent_idempotency_meta
                        SET record_count=record_count-1,
                            response_bytes=response_bytes-
                                COALESCE(length(CAST(OLD.response_json AS BLOB)),0)
                        WHERE singleton=1;
                    END

""".rstrip("\n")

_HISTORICAL_COUNT_RESPONSE_UPDATE_DDL = """
                    CREATE TRIGGER weixin_idempotency_count_response_update
                    AFTER UPDATE OF response_json ON weixin_agent_idempotency
                    BEGIN
                        UPDATE weixin_agent_idempotency_meta
                        SET response_bytes=response_bytes-
                                COALESCE(length(CAST(OLD.response_json AS BLOB)),0)+
                                COALESCE(length(CAST(NEW.response_json AS BLOB)),0)
                        WHERE singleton=1;
                    END

""".rstrip("\n")

_HISTORICAL_UPDATED_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS weixin_idempotency_updated_idx "
    "ON weixin_agent_idempotency(updated_at)"
)
_HISTORICAL_RESPONSE_PRUNE_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS weixin_idempotency_response_prune_idx "
    "ON weixin_agent_idempotency(updated_at) "
    "WHERE status='succeeded' AND response_json IS NOT NULL"
)
_HISTORICAL_BASE_AUXILIARY_DDL = (
    _HISTORICAL_META_TABLE_DDL,
    _HISTORICAL_COUNT_INSERT_DDL,
    _HISTORICAL_COUNT_DELETE_DDL,
    _HISTORICAL_COUNT_RESPONSE_UPDATE_DDL,
    _HISTORICAL_UPDATED_INDEX_DDL,
    _HISTORICAL_RESPONSE_PRUNE_INDEX_DDL,
)

_HISTORICAL_RECOVERY_REQUIRED_INSERT_DDL = """
                    CREATE TRIGGER weixin_idempotency_recovery_required_insert
                    BEFORE INSERT ON weixin_agent_idempotency
                    WHEN NEW.recovery_id IS NULL
                      OR length(NEW.recovery_id) <> 64
                      OR NEW.recovery_id GLOB '*[^0-9a-f]*'
                    BEGIN
                        SELECT RAISE(ABORT, 'valid recovery_id is required');
                    END

""".rstrip("\n")

_HISTORICAL_RECOVERY_IMMUTABLE_DDL = """
                    CREATE TRIGGER weixin_idempotency_recovery_immutable
                    BEFORE UPDATE OF recovery_id ON weixin_agent_idempotency
                    WHEN NEW.recovery_id IS NOT OLD.recovery_id
                    BEGIN
                        SELECT RAISE(ABORT, 'recovery_id is immutable');
                    END

""".rstrip("\n")

_HISTORICAL_RECOVERY_AUXILIARY_DDL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS weixin_idempotency_recovery_idx "
    "ON weixin_agent_idempotency(recovery_id)",
    _HISTORICAL_RECOVERY_REQUIRED_INSERT_DDL,
    _HISTORICAL_RECOVERY_IMMUTABLE_DDL,
)

_BASE_AUXILIARY_DDL = (
    _META_TABLE_DDL,
    _CAPACITY_INSERT_DDL,
    _CAPACITY_RESPONSE_UPDATE_DDL,
    _CAPACITY_LIMITS_NONINCREASING_DDL,
    _COUNT_INSERT_DDL,
    _COUNT_DELETE_DDL,
    _COUNT_RESPONSE_UPDATE_DDL,
    _UPDATED_INDEX_DDL,
    _RESPONSE_PRUNE_INDEX_DDL,
)
_RECOVERY_AUXILIARY_DDL = (
    _RECOVERY_INDEX_DDL,
    _RECOVERY_REQUIRED_INSERT_DDL,
    _RECOVERY_IMMUTABLE_DDL,
)
_CURRENT_SCHEMA_DDL = (
    _CURRENT_TABLE_DDL,
    *_BASE_AUXILIARY_DDL,
    *_RECOVERY_AUXILIARY_DDL,
)


def _persistent_schema_rows(
    connection: sqlite3.Connection,
) -> tuple[tuple[object, object, object, object], ...]:
    """Return the complete materialized sqlite_master closed set."""

    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "ORDER BY type,name,tbl_name"
    ).fetchall()
    # sqlite_master may preserve indentation that follows a closing SQL token
    # in a historical CREATE statement.  Trailing whitespace has no schema
    # semantics and varies across fixture writers/SQLite builds; keep every
    # token and internal byte exact while canonicalizing only the tail.
    return tuple(
        (kind, name, table_name, sql.rstrip() if isinstance(sql, str) else sql)
        for kind, name, table_name, sql in rows
    )


@lru_cache(maxsize=16)
def _materialized_schema_rows(
    statements: tuple[str, ...],
) -> tuple[tuple[object, object, object, object], ...]:
    with closing(sqlite3.connect(":memory:")) as connection:
        for statement in statements:
            connection.execute(statement)
        return _persistent_schema_rows(connection)


def _legacy_generation_statements(*, fixture: bool = False) -> tuple[str, ...]:
    return ((_LEGACY_FIXTURE_TABLE_DDL if fixture else _LEGACY_TABLE_DDL),)


def _capacity_generation_statements() -> tuple[str, ...]:
    return (_LEGACY_TABLE_DDL, *_HISTORICAL_BASE_AUXILIARY_DDL)


def _provider_generation_statements() -> tuple[str, ...]:
    return (
        *_capacity_generation_statements(),
        "ALTER TABLE weixin_agent_idempotency "
        "ADD COLUMN provider_phase INTEGER NOT NULL DEFAULT 0 "
        "CHECK(provider_phase IN (0,1))",
    )


def _installed_generation_statements() -> tuple[str, ...]:
    return (
        *_provider_generation_statements(),
        "ALTER TABLE weixin_agent_idempotency "
        "ADD COLUMN recovery_id TEXT CHECK("
        "recovery_id IS NULL OR (length(recovery_id)=64 AND "
        "recovery_id NOT GLOB '*[^0-9a-f]*'))",
        *_HISTORICAL_RECOVERY_AUXILIARY_DDL,
    )


def _previous_current_generation_statements() -> tuple[str, ...]:
    return (
        _PREVIOUS_CURRENT_TABLE_DDL,
        *_HISTORICAL_BASE_AUXILIARY_DDL,
        *_HISTORICAL_RECOVERY_AUXILIARY_DDL,
    )


def _allowed_unversioned_generations() -> dict[
    tuple[tuple[object, object, object, object], ...], str
]:
    return {
        (): "empty",
        _materialized_schema_rows(_legacy_generation_statements()): "legacy",
        _materialized_schema_rows(
            _legacy_generation_statements(fixture=True)
        ): "legacy_fixture",
        _materialized_schema_rows(_capacity_generation_statements()): "capacity",
        _materialized_schema_rows(_provider_generation_statements()): "provider",
        _materialized_schema_rows(_installed_generation_statements()): "installed",
        _materialized_schema_rows(
            _previous_current_generation_statements()
        ): "previous_current",
        _materialized_schema_rows(_CURRENT_SCHEMA_DDL): "current_unversioned",
    }


class WeixinIdempotencyUnavailable(RuntimeError):
    """The shared durable-channel ledger cannot be trusted or updated."""


class _IdempotencyDatabaseFamilyChanged(sqlite3.DatabaseError):
    """A read-only SQLite-family snapshot changed before it could be trusted."""


@dataclass(frozen=True)
class IdempotencyClaim:
    state: Literal[
        "claimed", "processing", "succeeded", "conflict", "recovery_required"
    ]
    fencing_token: str = ""
    response: dict[str, Any] | None = None
    retry_after_seconds: int = 0
    attempt: int = 0


def _is_reparse_or_symlink(info: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & reparse_flag
    )


def _assert_non_reparse_path(path: Path) -> None:
    """Reject an existing symlink/junction anywhere in a lexical path."""

    lexical = Path(os.path.abspath(os.fspath(path)))
    components = [lexical, *lexical.parents]
    for component in reversed(components):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            continue
        if _is_reparse_or_symlink(info):
            raise OSError(f"reparse point is forbidden in idempotency path: {component}")


def validate_weixin_idempotency_key(value: Any) -> str:
    """Accept only bridge-generated, fixed-shape message keys."""

    if (
        not isinstance(value, str)
        or not value.startswith(_CHANNEL_KEY_PREFIXES["weixin"])
        or _KEY_RE.fullmatch(value) is None
    ):
        raise ValueError("idempotency_key must be wxmsg-v1 followed by 64 lowercase hex digits")
    return value


def validate_channel_idempotency_key(value: Any, *, channel: str) -> str:
    """Require the fixed message-key namespace belonging to the channel."""

    expected = _CHANNEL_KEY_PREFIXES.get(str(channel))
    if expected is None or not isinstance(value, str):
        raise ValueError("unsupported durable channel idempotency namespace")
    if not value.startswith(expected) or _KEY_RE.fullmatch(value) is None:
        raise ValueError(f"idempotency_key must use the {expected} channel namespace")
    return value


def hash_channel_principal(*, channel: str, user_id: str, chat_id: str) -> str:
    """Stable authenticated-channel namespace, independent of key rotation."""

    values = (str(channel), str(user_id), str(chat_id))
    if values[0] not in _CHANNEL_KEY_PREFIXES or not values[1] or not values[2]:
        raise ValueError("canonical durable-channel user_id and chat_id are required")
    digest = hashlib.sha256(_PRINCIPAL_DOMAIN)
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _hash_message_key(message_key: str) -> str:
    if not isinstance(message_key, str) or _KEY_RE.fullmatch(message_key) is None:
        raise ValueError("idempotency_key must use a supported durable channel namespace")
    validated = message_key
    return hashlib.sha256(_KEY_DOMAIN + validated.encode("ascii")).hexdigest()


def hash_turn_identity(principal_hash: str, message_key: str) -> str:
    """Stable, channel-scoped Turn key that survives runtime-key rotation.

    The gateway ledger remains scoped to ``principal_hash`` as required.  The
    principal is derived from canonical channel/user/chat identity rather than
    the runtime credential, so including it isolates equal provider message IDs
    across conversations without letting a supervisor key rotation create a
    second business Turn.
    """

    if not isinstance(principal_hash, str) or _HASH_RE.fullmatch(principal_hash) is None:
        raise ValueError("principal_hash must be a lowercase SHA-256 digest")
    key_hash = _hash_message_key(message_key)
    return _hash_turn_identity_from_hashes(principal_hash, key_hash)


def _hash_turn_identity_from_hashes(principal_hash: str, key_hash: str) -> str:
    """Derive the public recovery handle without retaining the message key."""

    if not isinstance(principal_hash, str) or _HASH_RE.fullmatch(principal_hash) is None:
        raise ValueError("principal_hash must be a lowercase SHA-256 digest")
    if not isinstance(key_hash, str) or _HASH_RE.fullmatch(key_hash) is None:
        raise ValueError("key_hash must be a lowercase SHA-256 digest")
    return hashlib.sha256(
        b"nachuan-weixin-turn-v1\x00"
        + principal_hash.encode("ascii")
        + b"\x00"
        + key_hash.encode("ascii")
    ).hexdigest()


def hash_weixin_request(
    *,
    channel: str,
    chat_id: str,
    user_id: str,
    message: str,
    model: str,
    system: Any,
    video_async: bool,
) -> str:
    """Hash exactly the normalized values that affect ``agent_chat`` semantics."""

    semantic = {
        "version": 1,
        "principal_binding": "external",
        "channel": channel,
        "chat_id": chat_id,
        "user_id": user_id,
        "message": message,
        "model": model,
        "system": system,
        "video_async": bool(video_async),
    }
    try:
        canonical = json.dumps(
            semantic,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("request semantics must be bounded JSON") from exc
    return hashlib.sha256(canonical).hexdigest()


class WeixinIdempotencyStore:
    """Compatibility-named channel ledger safe across threads and processes."""

    def __init__(
        self,
        path: str | Path,
        *,
        lease_seconds: float = 90.0,
        busy_timeout_ms: int = 10_000,
        retention_seconds: float = 30 * 24 * 60 * 60,
        max_records: int = 50_000,
        prune_batch: int = 256,
        max_total_response_bytes: int = _DEFAULT_TOTAL_RESPONSE_BYTES,
        max_database_bytes: int = _DEFAULT_MAX_DATABASE_BYTES,
    ) -> None:
        self._keeper: sqlite3.Connection | None = None
        self._lock = RLock()
        self._closed = False
        self._trusted_data_version: int | None = None
        self._trusted_schema_version: int | None = None
        self.path = Path(os.path.abspath(os.fspath(path)))
        self.lease_seconds = max(10.0, min(float(lease_seconds), 15 * 60.0))
        requested_busy_timeout = max(100, min(int(busy_timeout_ms), 30_000))
        # A renewal must leave time to cancel/fence business work before the
        # lease expires.  Letting SQLite wait longer than one quarter of the
        # lease creates a real duplicate-execution window for short leases.
        self.busy_timeout_ms = min(
            requested_busy_timeout,
            max(100, int(self.lease_seconds * 250)),
        )
        self.retention_seconds = max(
            self.lease_seconds * 2.0,
            min(float(retention_seconds), 365 * 24 * 60 * 60.0),
        )
        self.max_records = max(1, min(int(max_records), _ABSOLUTE_MAX_RECORDS))
        self.prune_batch = max(1, min(int(prune_batch), 2048))
        self.max_total_response_bytes = max(
            1,
            min(int(max_total_response_bytes), _ABSOLUTE_TOTAL_RESPONSE_BYTES),
        )
        self.max_database_bytes = max(
            1024 * 1024,
            min(int(max_database_bytes), 4 * 1024 * 1024 * 1024),
        )
        try:
            self._assert_database_path()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_database_path()
            # Classify the complete SQLite family before a writer exists.
            # mode=ro is required for a complete WAL+SHM pair because
            # immutable=1 intentionally ignores committed WAL frames.
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
            with closing(self._open_connection()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                generation = self._classify_generation(connection)
                opened_identity = os.lstat(self.path)
                if preflight_identity is not None and not os.path.samestat(
                    preflight_identity, opened_identity
                ):
                    raise sqlite3.DatabaseError(
                        "idempotency database identity changed before locked open"
                    )
                peer_converged = (
                    preflight_generation != "current" and generation == "current"
                )
                if generation != preflight_generation and not peer_converged:
                    raise sqlite3.DatabaseError(
                        "idempotency database changed during initialization"
                    )
                if generation == "empty":
                    self._provision_current(connection)
                elif generation in {
                    "legacy",
                    "legacy_fixture",
                    "capacity",
                    "provider",
                    "installed",
                    "previous_current",
                }:
                    self._migrate_generation(connection)
                elif generation == "current_unversioned":
                    self._validate_current(connection, require_identity=False)
                    connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                elif generation != "current":
                    raise sqlite3.DatabaseError(
                        "unsupported idempotency database generation"
                    )
                self._synchronize_capacity_limits(connection)
                self._validate_current(connection)
                connection.commit()
                self._apply_runtime_profile(connection)
                self._validate_current(connection, quick_check=True)
            # Keep one WAL reader open for the store lifetime.  Otherwise every
            # short operation becomes the last connection and SQLite performs
            # an expensive checkpoint-on-close on the request path.  Normal
            # autocheckpointing still bounds WAL growth.
            self._keeper = self._open_connection()
            self._keeper.execute("PRAGMA wal_autocheckpoint=1000")
            self._apply_page_cap(self._keeper)
            self._trusted_data_version, self._trusted_schema_version = (
                self._database_versions(self._keeper)
            )
        except (OSError, sqlite3.Error) as exc:
            if self._keeper is not None:
                self._keeper.close()
                self._keeper = None
            self._closed = True
            raise WeixinIdempotencyUnavailable("cannot initialize idempotency ledger") from exc

    def _readonly_uri(self, *, wal_aware: bool = False) -> str:
        suffix = "?mode=ro" if wal_aware else "?mode=ro&immutable=1"
        return "file:" + quote(self.path.as_posix(), safe="/:") + suffix

    def _database_family_presence(self) -> dict[str, bool]:
        self._assert_database_path()
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
                raise _IdempotencyDatabaseFamilyChanged(
                    "idempotency main database is missing beside unstable sidecars"
                )
            return "empty", None, presence
        if presence["-journal"]:
            raise _IdempotencyDatabaseFamilyChanged(
                "idempotency rollback journal has not stabilized"
            )
        if presence["-wal"] != presence["-shm"]:
            raise _IdempotencyDatabaseFamilyChanged(
                "idempotency WAL and SHM sidecars have not stabilized"
            )
        identity = os.lstat(self.path)
        with closing(
            sqlite3.connect(
                self._readonly_uri(wal_aware=presence["-wal"]),
                uri=True,
                timeout=self.busy_timeout_ms / 1000.0,
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
                        "idempotency database integrity check failed"
                    )
                generation = self._classify_generation(connection)
            finally:
                connection.rollback()
        if self._database_family_presence() != presence:
            raise _IdempotencyDatabaseFamilyChanged(
                "idempotency database family changed during read-only preflight"
            )
        try:
            current_identity = os.lstat(self.path)
        except FileNotFoundError as exc:
            raise _IdempotencyDatabaseFamilyChanged(
                "idempotency database disappeared during read-only preflight"
            ) from exc
        if not os.path.samestat(identity, current_identity):
            raise _IdempotencyDatabaseFamilyChanged(
                "idempotency database identity changed during read-only preflight"
            )
        return generation, identity, presence

    def _stabilized_preflight_generation(
        self,
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        last_change: _IdempotencyDatabaseFamilyChanged | None = None
        # Eight honest cold starters can keep the first owner's rollback
        # journal visible beyond two seconds while the exact schema is
        # materialized.  This remains a bounded, read-only startup wait; a
        # stable foreign journal still fails closed at the deadline.
        stabilization_seconds = max(
            2.0,
            min(10.0, (self.busy_timeout_ms / 1000) * 5.0),
        )
        deadline = time.monotonic() + stabilization_seconds
        while True:
            try:
                return self._preflight_generation()
            except _IdempotencyDatabaseFamilyChanged as exc:
                last_change = exc
                if time.monotonic() < deadline:
                    time.sleep(0.025)
                    continue
                break
        raise sqlite3.DatabaseError(
            "idempotency database family did not stabilize during preflight"
        ) from last_change

    @staticmethod
    def _classify_generation(connection: sqlite3.Connection) -> str:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        rows = _persistent_schema_rows(connection)
        current = _materialized_schema_rows(_CURRENT_SCHEMA_DDL)
        if (
            application_id == _APPLICATION_ID
            and user_version == _SCHEMA_VERSION
            and rows == current
        ):
            return "current"
        if application_id == 0 and user_version == 0:
            generation = _allowed_unversioned_generations().get(rows)
            if generation is not None:
                return generation
        raise sqlite3.DatabaseError("unknown idempotency database family")

    @staticmethod
    def _execute_schema(connection: sqlite3.Connection) -> None:
        for statement in _CURRENT_SCHEMA_DDL:
            connection.execute(statement)

    def _provision_current(self, connection: sqlite3.Connection) -> None:
        self._execute_schema(connection)
        connection.execute(
            "INSERT INTO weixin_agent_idempotency_meta"
            "(singleton,record_count,response_bytes,max_records,"
            "max_total_response_bytes,max_database_bytes) VALUES(1,0,0,?,?,?)",
            (
                self.max_records,
                self.max_total_response_bytes,
                self.max_database_bytes,
            ),
        )
        connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _migrate_generation(self, connection: sqlite3.Connection) -> None:
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_xinfo(weixin_agent_idempotency)"
            )
        }
        has_provider = "provider_phase" in columns
        has_recovery = "recovery_id" in columns
        select_columns = [
            "principal_hash",
            "key_hash",
            "request_sha256",
            "status",
            "fencing_token",
            "lease_expires_at",
            "attempt_count",
            "response_json",
            "last_error_code",
            "created_at",
            "updated_at",
        ]
        if has_provider:
            select_columns.append("provider_phase")
        if has_recovery:
            select_columns.append("recovery_id")
        legacy_rows = connection.execute(
            "SELECT " + ",".join(select_columns) +
            " FROM weixin_agent_idempotency ORDER BY principal_hash,key_hash"
        ).fetchall()
        if len(legacy_rows) > self.max_records:
            raise sqlite3.DatabaseError("legacy idempotency ledger exceeds row capacity")

        migrated_rows: list[tuple[object, ...]] = []
        response_bytes = 0
        for raw in legacy_rows:
            try:
                offset = 11
                provider_phase = int(raw[offset]) if has_provider else 0
                offset += 1 if has_provider else 0
                stored_recovery = raw[offset] if has_recovery else None
                principal_hash = self._validate_hash(raw[0], "principal_hash")
                key_hash = self._validate_hash(raw[1], "key_hash")
                request_sha256 = self._validate_hash(raw[2], "request_sha256")
                recovery_id = _hash_turn_identity_from_hashes(
                    principal_hash,
                    key_hash,
                )
                if stored_recovery is not None and stored_recovery != recovery_id:
                    raise sqlite3.DatabaseError(
                        "legacy idempotency recovery identity is inconsistent"
                    )
                if str(raw[3]) not in {"processing", "succeeded", "failed"}:
                    raise sqlite3.DatabaseError("legacy idempotency status is invalid")
                if provider_phase not in {0, 1}:
                    raise sqlite3.DatabaseError("legacy provider phase is invalid")
                if not math.isfinite(float(raw[5])) or int(raw[6]) < 1:
                    raise sqlite3.DatabaseError("legacy lease metadata is invalid")
                if not math.isfinite(float(raw[9])) or not math.isfinite(float(raw[10])):
                    raise sqlite3.DatabaseError("legacy timestamps are invalid")
                if raw[7] is not None:
                    encoded_bytes = len(str(raw[7]).encode("utf-8"))
                    if encoded_bytes > _MAX_RESPONSE_BYTES:
                        raise sqlite3.DatabaseError(
                            "legacy response exceeds row capacity"
                        )
                    self._decode_response(raw[7])
                    response_bytes += encoded_bytes
                migrated_rows.append(
                    (
                        principal_hash,
                        key_hash,
                        recovery_id,
                        request_sha256,
                        str(raw[3]),
                        str(raw[4]),
                        float(raw[5]),
                        int(raw[6]),
                        raw[7],
                        str(raw[8]),
                        float(raw[9]),
                        float(raw[10]),
                        provider_phase,
                    )
                )
            except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
                raise sqlite3.DatabaseError(
                    "legacy idempotency row is invalid"
                ) from exc
            except WeixinIdempotencyUnavailable as exc:
                raise sqlite3.DatabaseError(
                    "legacy idempotency response is invalid"
                ) from exc
        if response_bytes > self.max_total_response_bytes:
            raise sqlite3.DatabaseError("legacy response ledger exceeds byte capacity")

        for object_type, name, _table_name, _sql in _persistent_schema_rows(connection):
            if str(object_type) in {"index", "trigger", "view"}:
                escaped = str(name).replace('"', '""')
                connection.execute(f'DROP {str(object_type).upper()} "{escaped}"')
        if "weixin_agent_idempotency_meta" in {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }:
            connection.execute("DROP TABLE weixin_agent_idempotency_meta")
        connection.execute(
            "ALTER TABLE weixin_agent_idempotency "
            "RENAME TO weixin_agent_idempotency_legacy"
        )
        connection.execute(_CURRENT_TABLE_DDL)
        connection.executemany(
            "INSERT INTO weixin_agent_idempotency("
            "principal_hash,key_hash,recovery_id,request_sha256,status,"
            "fencing_token,lease_expires_at,attempt_count,response_json,"
            "last_error_code,created_at,updated_at,provider_phase) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            migrated_rows,
        )
        connection.execute("DROP TABLE weixin_agent_idempotency_legacy")
        for statement in (*_BASE_AUXILIARY_DDL, *_RECOVERY_AUXILIARY_DDL):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO weixin_agent_idempotency_meta"
            "(singleton,record_count,response_bytes,max_records,"
            "max_total_response_bytes,max_database_bytes) "
            "VALUES(1,?,?,?,?,?)",
            (
                len(migrated_rows),
                response_bytes,
                self.max_records,
                self.max_total_response_bytes,
                self.max_database_bytes,
            ),
        )
        connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _validate_current(
        self,
        connection: sqlite3.Connection,
        *,
        require_identity: bool = True,
        quick_check: bool = False,
    ) -> None:
        if _persistent_schema_rows(connection) != _materialized_schema_rows(
            _CURRENT_SCHEMA_DDL
        ):
            raise sqlite3.DatabaseError("idempotency schema is not exact")
        if require_identity and (
            int(connection.execute("PRAGMA application_id").fetchone()[0])
            != _APPLICATION_ID
            or int(connection.execute("PRAGMA user_version").fetchone()[0])
            != _SCHEMA_VERSION
        ):
            raise sqlite3.DatabaseError("idempotency database identity is invalid")
        if quick_check:
            check = connection.execute("PRAGMA quick_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError(
                    "idempotency database integrity check failed"
                )
        meta = connection.execute(
            "SELECT record_count,response_bytes,max_records,"
            "max_total_response_bytes,max_database_bytes,"
            "typeof(record_count),typeof(response_bytes),typeof(max_records),"
            "typeof(max_total_response_bytes),typeof(max_database_bytes) "
            "FROM weixin_agent_idempotency_meta "
            "WHERE singleton=1"
        ).fetchone()
        if meta is None or meta[5:] != (
            "integer",
            "integer",
            "integer",
            "integer",
            "integer",
        ):
            raise sqlite3.DatabaseError("idempotency usage counters are invalid")
        if (
            not 1 <= int(meta[2]) <= _ABSOLUTE_MAX_RECORDS
            or not 1
            <= int(meta[3])
            <= _ABSOLUTE_TOTAL_RESPONSE_BYTES
            or not 1024 * 1024 <= int(meta[4]) <= 4 * 1024 * 1024 * 1024
        ):
            raise sqlite3.DatabaseError("idempotency capacity limits are invalid")
        actual = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(response_json AS BLOB))),0) "
            "FROM weixin_agent_idempotency"
        ).fetchone()
        if actual is None or (int(meta[0]), int(meta[1])) != (
            int(actual[0]),
            int(actual[1]),
        ):
            raise sqlite3.DatabaseError("idempotency usage counters do not match rows")
        # A current ledger may be reopened under a tighter operational budget;
        # bounded pruning in claim/succeed then converges it without deleting
        # an active replay during construction.  Only the absolute family
        # envelope is a construction blocker.  Historical migrations remain
        # bound by the requested limits before any rewrite.
        if (
            int(actual[0]) > _ABSOLUTE_MAX_RECORDS
            or int(actual[1]) > _ABSOLUTE_TOTAL_RESPONSE_BYTES
        ):
            raise sqlite3.DatabaseError("idempotency ledger exceeds family capacity")
        for row in connection.execute(
            "SELECT principal_hash,key_hash,recovery_id,request_sha256,status,"
            "lease_expires_at,attempt_count,response_json,created_at,updated_at,"
            "provider_phase FROM weixin_agent_idempotency"
        ):
            try:
                principal_hash = self._validate_hash(row[0], "principal_hash")
                key_hash = self._validate_hash(row[1], "key_hash")
                if row[2] != _hash_turn_identity_from_hashes(
                    principal_hash,
                    key_hash,
                ):
                    raise sqlite3.DatabaseError(
                        "idempotency recovery identity is invalid"
                    )
                self._validate_hash(row[3], "request_sha256")
                if str(row[4]) not in {"processing", "succeeded", "failed"}:
                    raise sqlite3.DatabaseError("idempotency status is invalid")
                if (
                    not math.isfinite(float(row[5]))
                    or int(row[6]) < 1
                    or not math.isfinite(float(row[8]))
                    or not math.isfinite(float(row[9]))
                    or int(row[10]) not in {0, 1}
                ):
                    raise sqlite3.DatabaseError("idempotency row metadata is invalid")
                if row[7] is not None:
                    if len(str(row[7]).encode("utf-8")) > _MAX_RESPONSE_BYTES:
                        raise sqlite3.DatabaseError("idempotency response is oversized")
                    self._decode_response(row[7])
            except (TypeError, ValueError, OverflowError, UnicodeError) as exc:
                raise sqlite3.DatabaseError("idempotency row is invalid") from exc
            except WeixinIdempotencyUnavailable as exc:
                raise sqlite3.DatabaseError(
                    "idempotency response is invalid"
                ) from exc
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size <= 0 or page_count * page_size > self.max_database_bytes:
            raise sqlite3.DatabaseError("idempotency database exceeds file capacity")

    def _synchronize_capacity_limits(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        row = connection.execute(
            "SELECT max_records,max_total_response_bytes,max_database_bytes "
            "FROM weixin_agent_idempotency_meta WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise sqlite3.DatabaseError("idempotency capacity limits are missing")
        stored = (int(row[0]), int(row[1]), int(row[2]))
        effective = (
            min(self.max_records, stored[0]),
            min(self.max_total_response_bytes, stored[1]),
            min(self.max_database_bytes, stored[2]),
        )
        if effective != stored:
            connection.execute(
                "UPDATE weixin_agent_idempotency_meta SET max_records=?,"
                "max_total_response_bytes=?,max_database_bytes=? "
                "WHERE singleton=1",
                effective,
            )
        (
            self.max_records,
            self.max_total_response_bytes,
            self.max_database_bytes,
        ) = effective

    def _apply_runtime_profile(self, connection: sqlite3.Connection) -> None:
        enable_wal_with_deadline(
            connection,
            error_message="idempotency WAL profile is unavailable",
        )
        connection.execute("PRAGMA synchronous=FULL")
        self._apply_page_cap(connection)
        connection.execute(f"PRAGMA journal_size_limit={_MAX_WAL_BYTES}")
        connection.execute("PRAGMA wal_autocheckpoint=1000")

    def _apply_page_cap(self, connection: sqlite3.Connection) -> None:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        max_pages = max(1, self.max_database_bytes // page_size)
        if page_count > max_pages:
            raise sqlite3.DatabaseError("idempotency database exceeds file capacity")
        actual_max = int(
            connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        )
        if actual_max > max_pages:
            raise sqlite3.DatabaseError("idempotency page cap was not applied")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            keeper, self._keeper = self._keeper, None
            self._trusted_data_version = None
            self._trusted_schema_version = None
            if keeper is not None:
                keeper.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _assert_database_path(self) -> None:
        _assert_non_reparse_path(self.path)
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
            if _is_reparse_or_symlink(info) or not stat.S_ISREG(info.st_mode):
                raise OSError(
                    "idempotency database files must be regular non-reparse files"
                )

    def _open_connection(self) -> sqlite3.Connection:
        self._assert_database_path()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                str(self.path),
                timeout=self.busy_timeout_ms / 1000.0,
                isolation_level=None,
                check_same_thread=False,
            )
            # Recheck after SQLite opens/creates the main file.  On Windows an
            # open database cannot be swapped; on POSIX this also closes the
            # common pre-open symlink race, though no pathname API can make an
            # arbitrary hostile same-user rename fully atomic with sqlite3_open.
            self._assert_database_path()
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA journal_size_limit={_MAX_WAL_BYTES}")
            connection.execute("PRAGMA wal_autocheckpoint=1000")
            return connection
        except BaseException:
            if connection is not None:
                connection.close()
            raise

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise WeixinIdempotencyUnavailable("idempotency ledger is closed")
        return self._open_connection()

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
            raise sqlite3.DatabaseError("idempotency database versions are invalid")
        return int(data_version[0]), int(schema_version[0])

    def _begin_runtime_transaction(self, connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")
        if self._keeper is None:
            raise sqlite3.DatabaseError("idempotency keeper is unavailable")
        data_version = self._database_versions(self._keeper)[0]
        schema_version = self._database_versions(connection)[1]
        if (
            data_version != self._trusted_data_version
            or schema_version != self._trusted_schema_version
        ):
            self._validate_current(connection)
            self._synchronize_capacity_limits(connection)
            self._trusted_data_version = data_version
            self._trusted_schema_version = schema_version
        self._apply_page_cap(connection)

    def _commit_runtime_transaction(self, connection: sqlite3.Connection) -> None:
        connection.commit()
        if self._keeper is None:
            raise sqlite3.DatabaseError("idempotency keeper is unavailable")
        self._trusted_data_version, self._trusted_schema_version = (
            self._database_versions(self._keeper)
        )

    @staticmethod
    def _validate_hash(value: str, label: str) -> str:
        if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
            raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _decode_response(raw: Any) -> dict[str, Any]:
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError, RecursionError) as exc:
            raise WeixinIdempotencyUnavailable("cached response is corrupt") from exc
        if not isinstance(value, dict):
            raise WeixinIdempotencyUnavailable("cached response is not an object")
        return value

    @staticmethod
    def _meta_usage(connection: sqlite3.Connection) -> tuple[int, int]:
        row = connection.execute(
            "SELECT record_count,response_bytes,typeof(record_count),"
            "typeof(response_bytes) FROM weixin_agent_idempotency_meta "
            "WHERE singleton=1"
        ).fetchone()
        if (
            row is None
            or row[2] != "integer"
            or row[3] != "integer"
            or int(row[0]) < 0
            or int(row[1]) < 0
        ):
            raise sqlite3.DatabaseError("idempotency usage counters are invalid")
        return int(row[0]), int(row[1])

    def _prune(
        self,
        connection: sqlite3.Connection,
        current: float,
        *,
        incoming_response_bytes: int = 0,
        reserve_record_slot: bool = True,
        protected_key: tuple[str, str] | None = None,
    ) -> bool:
        """Bound storage in small batches without touching live leases."""

        protected_principal, protected_message = protected_key or ("", "")
        cutoff = current - self.retention_seconds
        connection.execute(
            "DELETE FROM weixin_agent_idempotency WHERE (principal_hash,key_hash) IN ("
            "SELECT principal_hash,key_hash FROM weixin_agent_idempotency "
            "WHERE updated_at < ? AND (status <> 'processing' OR lease_expires_at <= ?) "
            "AND (principal_hash<>? OR key_hash<>?) "
            "ORDER BY updated_at LIMIT ?)",
            (
                cutoff,
                cutoff,
                protected_principal,
                protected_message,
                self.prune_batch,
            ),
        )
        count, _stored_bytes = self._meta_usage(connection)
        # Leave one slot for a genuinely new claim.  Live leases are never
        # evicted; when all slots are live the caller fails closed instead of
        # exceeding the cross-process hard capacity.
        excess = count - self.max_records + (1 if reserve_record_slot else 0)
        if excess > 0:
            connection.execute(
                "DELETE FROM weixin_agent_idempotency WHERE (principal_hash,key_hash) IN ("
                "SELECT principal_hash,key_hash FROM weixin_agent_idempotency "
                "WHERE (status <> 'processing' OR lease_expires_at <= ?) "
                "AND (principal_hash<>? OR key_hash<>?) "
                "ORDER BY updated_at LIMIT ?)",
                (
                    current,
                    protected_principal,
                    protected_message,
                    min(excess, self.prune_batch),
                ),
            )
        count, stored_bytes = self._meta_usage(connection)
        record_slot_available = (
            not reserve_record_slot or count < self.max_records
        )
        byte_excess = (
            stored_bytes
            + max(0, int(incoming_response_bytes))
            - self.max_total_response_bytes
        )
        if byte_excess > 0:
            candidates = connection.execute(
                "SELECT principal_hash,key_hash,length(CAST(response_json AS BLOB)) "
                "FROM weixin_agent_idempotency "
                "WHERE status='succeeded' AND response_json IS NOT NULL "
                "AND (principal_hash<>? OR key_hash<>?) "
                "ORDER BY updated_at LIMIT ?",
                (protected_principal, protected_message, self.prune_batch),
            ).fetchall()
            victims: list[tuple[str, str]] = []
            reclaimed = 0
            for principal_hash, key_hash, response_bytes in candidates:
                victims.append((str(principal_hash), str(key_hash)))
                reclaimed += int(response_bytes or 0)
                if reclaimed >= byte_excess:
                    break
            if victims:
                connection.executemany(
                    "DELETE FROM weixin_agent_idempotency "
                    "WHERE principal_hash=? AND key_hash=?",
                    victims,
                )
                _count, stored_bytes = self._meta_usage(connection)
        return record_slot_available and (
            stored_bytes + max(0, int(incoming_response_bytes))
            <= self.max_total_response_bytes
        )

    def recovery_snapshot(self, recovery_id: str) -> dict[str, Any]:
        """Return a read-only, non-sensitive durable-Turn recovery status.

        ``recovery_id`` is a one-way Turn identity with a unique on-disk index.
        Neither principal/key hashes nor the cached response leave this store.
        """

        normalized = self._validate_hash(recovery_id, "recovery_id")
        try:
            with self._lock, closing(self._connect()) as connection:
                self._begin_runtime_transaction(connection)
                row = connection.execute(
                    "SELECT status,lease_expires_at,attempt_count,response_json,"
                    "provider_phase,length(CAST(response_json AS BLOB)) "
                    "FROM weixin_agent_idempotency "
                    "WHERE recovery_id=?",
                    (normalized,),
                ).fetchone()
                if row is not None:
                    (
                    status,
                    lease_expires_at,
                    attempt_count,
                    response_json,
                    provider_phase,
                    response_bytes,
                    ) = row
                    normalized_status = str(status)
                    normalized_lease_expires_at = float(lease_expires_at)
                    normalized_attempt_count = int(attempt_count)
                    normalized_provider_phase = int(provider_phase)
                    if (
                        normalized_status not in {"processing", "succeeded", "failed"}
                        or not math.isfinite(normalized_lease_expires_at)
                        or normalized_attempt_count < 1
                        or normalized_provider_phase not in {0, 1}
                    ):
                        raise sqlite3.DatabaseError(
                            "durable Turn recovery status is corrupt"
                        )
                    response_persisted = response_json is not None
                    if response_persisted and (
                        response_bytes is None
                        or int(response_bytes) < 0
                        or int(response_bytes) > _MAX_RESPONSE_BYTES
                    ):
                        raise sqlite3.DatabaseError(
                            "durable Turn recovery response size is invalid"
                        )
                    recovery_notice_persisted = False
                    if response_persisted:
                        response = self._decode_response(response_json)
                        recovery_notice_persisted = (
                            response.get("outcome")
                            == "provider_result_recovery_required"
                            and response.get("recovery_id") == normalized
                        )
                    result = {
                        "found": True,
                        "record_status": normalized_status,
                        "provider_phase_entered": bool(normalized_provider_phase),
                        "attempt_count": normalized_attempt_count,
                        "response_persisted": response_persisted,
                        "recovery_notice_persisted": recovery_notice_persisted,
                        "processing_lease_active": bool(
                            normalized_status == "processing"
                            and normalized_lease_expires_at > time.time()
                        ),
                    }
                    connection.rollback()
                    return result
                connection.rollback()
                return {"found": False}
        except WeixinIdempotencyUnavailable:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise WeixinIdempotencyUnavailable(
                "cannot read durable Turn recovery status"
            ) from exc

    def claim(
        self,
        principal_hash: str,
        message_key: str,
        request_sha256: str,
        *,
        now: float | None = None,
    ) -> IdempotencyClaim:
        principal_hash = self._validate_hash(principal_hash, "principal_hash")
        request_sha256 = self._validate_hash(request_sha256, "request_sha256")
        key_hash = _hash_message_key(message_key)
        recovery_id = _hash_turn_identity_from_hashes(principal_hash, key_hash)
        requested_now = None if now is None else float(now)
        fencing_token = secrets.token_hex(32)
        try:
            with self._lock, closing(self._connect()) as connection:
                self._begin_runtime_transaction(connection)
                current = time.time() if requested_now is None else requested_now
                within_budget = self._prune(
                    connection,
                    current,
                    protected_key=(principal_hash, key_hash),
                )
                row = connection.execute(
                    "SELECT request_sha256,status,fencing_token,lease_expires_at,"
                    "attempt_count,response_json,provider_phase,recovery_id "
                    "FROM weixin_agent_idempotency "
                    "WHERE principal_hash=? AND key_hash=?",
                    (principal_hash, key_hash),
                ).fetchone()
                if row is None:
                    if not within_budget:
                        # Persist the bounded cleanup batch, then reject rather
                        # than exceeding a cross-process record/byte budget.
                        self._commit_runtime_transaction(connection)
                        raise WeixinIdempotencyUnavailable(
                            "idempotency ledger capacity reached"
                        )
                    connection.execute(
                        "INSERT INTO weixin_agent_idempotency "
                        "(principal_hash,key_hash,recovery_id,request_sha256,status,fencing_token,"
                        "lease_expires_at,attempt_count,response_json,last_error_code,"
                        "created_at,updated_at) VALUES(?,?,?,?,'processing',?,?,1,NULL,'',?,?)",
                        (
                            principal_hash,
                            key_hash,
                            recovery_id,
                            request_sha256,
                            fencing_token,
                            current + self.lease_seconds,
                            current,
                            current,
                        ),
                    )
                    self._commit_runtime_transaction(connection)
                    return IdempotencyClaim(
                        state="claimed", fencing_token=fencing_token, attempt=1
                    )

                (
                    stored_request,
                    status,
                    _stored_token,
                    lease_expires,
                    attempts,
                    response,
                    provider_phase,
                    stored_recovery_id,
                ) = row
                if stored_recovery_id != recovery_id:
                    raise WeixinIdempotencyUnavailable(
                        "idempotency recovery identity does not match its primary key"
                    )
                if stored_request != request_sha256:
                    self._commit_runtime_transaction(connection)
                    return IdempotencyClaim(state="conflict", attempt=int(attempts))
                if status == "succeeded":
                    decoded = self._decode_response(response)
                    self._commit_runtime_transaction(connection)
                    return IdempotencyClaim(
                        state="succeeded", response=decoded, attempt=int(attempts)
                    )
                if status == "processing" and float(lease_expires) > current:
                    retry_after = max(1, int(math.ceil(float(lease_expires) - current)))
                    self._commit_runtime_transaction(connection)
                    return IdempotencyClaim(
                        state="processing",
                        retry_after_seconds=retry_after,
                        attempt=int(attempts),
                    )

                next_attempt = int(attempts) + 1
                connection.execute(
                    "UPDATE weixin_agent_idempotency SET status='processing',"
                    "fencing_token=?,lease_expires_at=?,attempt_count=?,response_json=NULL,"
                    "last_error_code='',updated_at=? "
                    "WHERE principal_hash=? AND key_hash=? AND request_sha256=?",
                    (
                        fencing_token,
                        current + self.lease_seconds,
                        next_attempt,
                        current,
                        principal_hash,
                        key_hash,
                        request_sha256,
                    ),
                )
                self._commit_runtime_transaction(connection)
                return IdempotencyClaim(
                    state=(
                        "recovery_required" if int(provider_phase) == 1 else "claimed"
                    ),
                    fencing_token=fencing_token,
                    attempt=next_attempt,
                )
        except WeixinIdempotencyUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise WeixinIdempotencyUnavailable("cannot claim idempotency record") from exc

    def renew(
        self,
        principal_hash: str,
        message_key: str,
        request_sha256: str,
        fencing_token: str,
        *,
        now: float | None = None,
    ) -> bool:
        principal_hash = self._validate_hash(principal_hash, "principal_hash")
        request_sha256 = self._validate_hash(request_sha256, "request_sha256")
        key_hash = _hash_message_key(message_key)
        requested_now = None if now is None else float(now)
        try:
            with self._lock, closing(self._connect()) as connection:
                self._begin_runtime_transaction(connection)
                current = time.time() if requested_now is None else requested_now
                cursor = connection.execute(
                    "UPDATE weixin_agent_idempotency SET lease_expires_at=?,updated_at=? "
                    "WHERE principal_hash=? AND key_hash=? AND request_sha256=? "
                    "AND status='processing' AND fencing_token=? AND lease_expires_at>?",
                    (
                        current + self.lease_seconds,
                        current,
                        principal_hash,
                        key_hash,
                        request_sha256,
                        fencing_token,
                        current,
                    ),
                )
                self._commit_runtime_transaction(connection)
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise WeixinIdempotencyUnavailable("cannot renew idempotency lease") from exc

    def enter_provider_phase(
        self,
        principal_hash: str,
        message_key: str,
        request_sha256: str,
        fencing_token: str,
        *,
        now: float | None = None,
    ) -> bool:
        """Atomically fence the one owner allowed to enter provider-capable work."""

        principal_hash = self._validate_hash(principal_hash, "principal_hash")
        request_sha256 = self._validate_hash(request_sha256, "request_sha256")
        key_hash = _hash_message_key(message_key)
        requested_now = None if now is None else float(now)
        try:
            with self._lock, closing(self._connect()) as connection:
                self._begin_runtime_transaction(connection)
                current = time.time() if requested_now is None else requested_now
                cursor = connection.execute(
                    "UPDATE weixin_agent_idempotency SET provider_phase=1,"
                    "lease_expires_at=?,updated_at=? "
                    "WHERE principal_hash=? AND key_hash=? AND request_sha256=? "
                    "AND status='processing' AND fencing_token=? "
                    "AND lease_expires_at>? AND provider_phase=0",
                    (
                        current + self.lease_seconds,
                        current,
                        principal_hash,
                        key_hash,
                        request_sha256,
                        fencing_token,
                        current,
                    ),
                )
                self._commit_runtime_transaction(connection)
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise WeixinIdempotencyUnavailable(
                "cannot enter durable provider phase"
            ) from exc

    def succeed(
        self,
        principal_hash: str,
        message_key: str,
        request_sha256: str,
        fencing_token: str,
        response: dict[str, Any],
        *,
        now: float | None = None,
    ) -> bool:
        principal_hash = self._validate_hash(principal_hash, "principal_hash")
        request_sha256 = self._validate_hash(request_sha256, "request_sha256")
        key_hash = _hash_message_key(message_key)
        if not isinstance(response, dict):
            raise ValueError("successful response must be an object")
        try:
            encoded = json.dumps(
                response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("successful response must be bounded JSON") from exc
        encoded_bytes = len(encoded.encode("utf-8"))
        if encoded_bytes > _MAX_RESPONSE_BYTES:
            raise ValueError("successful response exceeds idempotency storage limit")
        requested_now = None if now is None else float(now)
        try:
            with self._lock, closing(self._connect()) as connection:
                self._begin_runtime_transaction(connection)
                current = time.time() if requested_now is None else requested_now
                within_budget = self._prune(
                    connection,
                    current,
                    incoming_response_bytes=encoded_bytes,
                    reserve_record_slot=False,
                    protected_key=(principal_hash, key_hash),
                )
                if not within_budget:
                    # Commit the bounded cleanup batch so a legacy oversized
                    # ledger converges over retries, but fail closed on this
                    # response until the configured total budget can be met.
                    self._commit_runtime_transaction(connection)
                    raise ValueError("successful response exceeds total idempotency budget")
                cursor = connection.execute(
                    "UPDATE weixin_agent_idempotency SET status='succeeded',"
                    "fencing_token='',lease_expires_at=0,response_json=?,"
                    "last_error_code='',updated_at=? "
                    "WHERE principal_hash=? AND key_hash=? AND request_sha256=? "
                    "AND status='processing' AND fencing_token=? AND lease_expires_at>?",
                    (
                        encoded,
                        current,
                        principal_hash,
                        key_hash,
                        request_sha256,
                        fencing_token,
                        current,
                    ),
                )
                self._commit_runtime_transaction(connection)
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise WeixinIdempotencyUnavailable("cannot persist successful response") from exc

    def fail(
        self,
        principal_hash: str,
        message_key: str,
        request_sha256: str,
        fencing_token: str,
        *,
        error_code: str,
        now: float | None = None,
    ) -> bool:
        principal_hash = self._validate_hash(principal_hash, "principal_hash")
        request_sha256 = self._validate_hash(request_sha256, "request_sha256")
        key_hash = _hash_message_key(message_key)
        safe_code = _ERROR_CODE_RE.sub("_", str(error_code or "error"))[:64] or "error"
        requested_now = None if now is None else float(now)
        try:
            with self._lock, closing(self._connect()) as connection:
                self._begin_runtime_transaction(connection)
                current = time.time() if requested_now is None else requested_now
                cursor = connection.execute(
                    "UPDATE weixin_agent_idempotency SET status='failed',"
                    "fencing_token='',lease_expires_at=0,response_json=NULL,"
                    "last_error_code=?,updated_at=? "
                    "WHERE principal_hash=? AND key_hash=? AND request_sha256=? "
                    "AND status='processing' AND fencing_token=? AND lease_expires_at>?",
                    (
                        safe_code,
                        current,
                        principal_hash,
                        key_hash,
                        request_sha256,
                        fencing_token,
                        current,
                    ),
                )
                self._commit_runtime_transaction(connection)
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise WeixinIdempotencyUnavailable("cannot release failed idempotency claim") from exc
