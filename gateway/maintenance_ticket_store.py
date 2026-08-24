"""Persistent one-time tickets for the restricted maintenance coordinator.

This module is transport agnostic.  It deliberately exposes no HTTP, IPC,
engine, or service entrypoint; an authenticated service boundary must supply
the requester SID digest and the service-specific ACL implementation.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Callable, Iterator, Literal

from gateway.restricted_capture_contract import RestrictedCaptureRequest


_APPLICATION_ID = 0x4E434D54  # "NCMT"
_SCHEMA_VERSION = 1
_MAX_TTL_SECONDS = 600
_MAX_TICKETS_PER_BOOT = 256
_PAGE_SIZE = 4096
_MAX_MAIN_DB_BYTES = 4 * 1024 * 1024
_MAX_PAGE_COUNT = _MAX_MAIN_DB_BYTES // _PAGE_SIZE
_MAX_WAL_BYTES = 2 * _MAX_MAIN_DB_BYTES
_MAX_SHM_BYTES = 8 * 1024 * 1024
_MAX_ROLLBACK_JOURNAL_BYTES = _MAX_MAIN_DB_BYTES
_BUSY_TIMEOUT_MS = 10_000
_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_BOOT_ID_RE = re.compile(r"\Aservice-boot-v1:[0-9a-f]{64}\Z")
_TICKET_SECRET_RE = re.compile(r"\Amaintenance-ticket-v1:[0-9a-f]{64}\Z")
_INT64_MAX = (1 << 63) - 1
_ROLLBACK_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

TicketState = Literal["prepared", "claimed", "consumed", "failed", "expired"]


class MaintenanceTicketError(RuntimeError):
    """Base class for the intentionally small public error surface."""


class MaintenanceTicketUnavailable(MaintenanceTicketError):
    """The durable store or its authority boundary cannot be trusted."""


class MaintenanceTicketValidationError(MaintenanceTicketError):
    """A caller supplied a malformed closed-contract value."""


class MaintenanceTicketCapacity(MaintenanceTicketError):
    """The fixed per-service-boot ticket capacity is exhausted."""


class _DatabaseFamilyChanged(RuntimeError):
    """A read-only ticket database family snapshot changed."""


@dataclass(frozen=True, slots=True)
class MaintenanceTicketStoreDependencies:
    """Explicit service-boundary dependencies.

    No permissive default ACL policy exists: a future LocalService host must
    inject its exact ProgramData ACL assertions and provisioning hardener.
    """

    wall_clock: Callable[[], float]
    random_bytes: Callable[[int], bytes]
    assert_acl: Callable[[Path, bool], None]
    harden_acl: Callable[[Path, bool], None]
    trusted_boundary: Callable[[Path], Path]


@dataclass(frozen=True, slots=True)
class IssuedMaintenanceTicket:
    secret: str
    expires_at_ms: int


@dataclass(frozen=True, slots=True)
class MaintenanceClaimedOperationDiscoveryPage:
    """A secret-free page of active-boot claimed operation bindings."""

    items: tuple[RestrictedCaptureRequest, ...]
    ambiguous_operation_digests: tuple[str, ...]
    next_cursor: str | None


_META_DDL = """
CREATE TABLE maintenance_ticket_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    active_boot_digest TEXT NOT NULL CHECK(length(active_boot_digest) = 64),
    last_wall_time_ms INTEGER NOT NULL CHECK(last_wall_time_ms >= 0),
    clock_state TEXT NOT NULL CHECK(clock_state IN ('ok','rollback'))
) WITHOUT ROWID
"""

_TICKETS_DDL = """
CREATE TABLE maintenance_tickets (
    ticket_digest TEXT PRIMARY KEY CHECK(length(ticket_digest) = 64),
    requester_sid_digest TEXT NOT NULL CHECK(length(requester_sid_digest) = 64),
    installation_id TEXT NOT NULL CHECK(length(installation_id) = 64),
    epoch INTEGER NOT NULL CHECK(epoch >= 1),
    root_revision INTEGER NOT NULL CHECK(root_revision >= 1),
    operation_digest TEXT NOT NULL CHECK(length(operation_digest) = 64),
    service_boot_digest TEXT NOT NULL CHECK(length(service_boot_digest) = 64),
    state TEXT NOT NULL CHECK(
        state IN ('prepared','claimed','consumed','failed','expired')
    ),
    issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > issued_at_ms),
    claimed_at_ms INTEGER CHECK(
        claimed_at_ms IS NULL OR claimed_at_ms >= issued_at_ms
    ),
    finished_at_ms INTEGER CHECK(
        finished_at_ms IS NULL OR finished_at_ms >= issued_at_ms
    ),
    CHECK(
        (state = 'prepared' AND claimed_at_ms IS NULL AND finished_at_ms IS NULL)
        OR (state = 'claimed' AND claimed_at_ms IS NOT NULL AND finished_at_ms IS NULL)
        OR (state IN ('consumed','failed')
            AND claimed_at_ms IS NOT NULL AND finished_at_ms IS NOT NULL)
        OR (state = 'expired' AND claimed_at_ms IS NULL AND finished_at_ms IS NOT NULL)
    )
) WITHOUT ROWID
"""


def _normalize_sql(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise sqlite3.DatabaseError("schema SQL is missing")
    return value


def _schema_entry_sql(value: object) -> str | None:
    return None if value is None else _normalize_sql(value)


@lru_cache(maxsize=1)
def _expected_schema() -> dict[tuple[str, str], tuple[str, str | None]]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.execute(_META_DDL)
        connection.execute(_TICKETS_DDL)
        return {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_entry_sql(row[3]),
            )
            for row in connection.execute(
                """
                SELECT type, name, tbl_name, sql FROM sqlite_master
                ORDER BY type, name
                """
            ).fetchall()
        }
    finally:
        connection.close()


def _digest(domain: bytes, value: str) -> str:
    return hashlib.sha256(domain + value.encode("ascii")).hexdigest()


def _required_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or _DIGEST_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise MaintenanceTicketValidationError(
            "maintenance ticket request is invalid"
        )
    return value


def _required_counter(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _INT64_MAX:
        raise MaintenanceTicketValidationError(
            "maintenance ticket request is invalid"
        )
    return value


class MaintenanceTicketStore:
    """SQLite-backed, boot-fenced, one-time maintenance tickets."""

    def __init__(
        self,
        path: Path,
        *,
        service_boot_id: str,
        dependencies: MaintenanceTicketStoreDependencies,
    ) -> None:
        if not isinstance(service_boot_id, str) or _BOOT_ID_RE.fullmatch(service_boot_id) is None:
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        self.path = Path(os.path.abspath(os.fspath(path)))
        self._dependencies = dependencies
        self._boot_digest = _digest(b"nachuan-maintenance-boot-v1\0", service_boot_id)
        self._trusted_clean_schema_signature: tuple[int, int, bytes] | None = None

    @classmethod
    def provision(
        cls,
        path: str | Path,
        *,
        service_boot_id: str,
        dependencies: MaintenanceTicketStoreDependencies,
    ) -> MaintenanceTicketStore:
        store = cls(
            Path(path),
            service_boot_id=service_boot_id,
            dependencies=dependencies,
        )
        try:
            store._prepare_parent(provisioning=True)
            if any(store._database_family_presence().values()):
                raise OSError(
                    "ticket provisioning target contains an existing database family"
                )
            descriptor = os.open(
                store.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            os.close(descriptor)
            dependencies.harden_acl(store.path, False)
            dependencies.assert_acl(store.path, False)
            now_ms = store._wall_time_ms()
            connection = sqlite3.connect(str(store.path), isolation_level=None)
            try:
                connection.execute(f"PRAGMA page_size={_PAGE_SIZE}")
                mode = connection.execute("PRAGMA journal_mode=PERSIST").fetchone()
                if not mode or str(mode[0]).casefold() != "persist":
                    raise sqlite3.DatabaseError("PERSIST journal mode is required")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(_META_DDL)
                connection.execute(_TICKETS_DDL)
                connection.execute(
                    "INSERT INTO maintenance_ticket_meta VALUES(1,1,?,?,'ok')",
                    (store._boot_digest, now_ms),
                )
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                connection.execute(f"PRAGMA max_page_count={_MAX_PAGE_COUNT}")
                connection.commit()
            finally:
                connection.close()
            store._harden_sidecars()
            store._assert_authority_path()
            with store._connection():
                pass
            return store
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        service_boot_id: str,
        dependencies: MaintenanceTicketStoreDependencies,
    ) -> MaintenanceTicketStore:
        store = cls(
            Path(path),
            service_boot_id=service_boot_id,
            dependencies=dependencies,
        )
        try:
            with store._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                store._observe_clock(connection)
                row = connection.execute(
                    "SELECT active_boot_digest FROM maintenance_ticket_meta WHERE singleton=1"
                ).fetchone()
                if not row:
                    raise sqlite3.DatabaseError("ticket metadata is missing")
                if str(row[0]) != store._boot_digest:
                    # Tickets are capabilities, not an audit ledger.  A service
                    # restart establishes a new trust epoch and atomically
                    # forgets every old capability before activating it.
                    connection.execute("DELETE FROM maintenance_tickets")
                    connection.execute(
                        "UPDATE maintenance_ticket_meta SET active_boot_digest=? "
                        "WHERE singleton=1",
                        (store._boot_digest,),
                    )
                connection.commit()
            return store
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def issue(
        self,
        *,
        requester_sid_digest: str,
        installation_id: str,
        epoch: int,
        root_revision: int,
        operation_digest: str,
        ttl_seconds: int,
    ) -> IssuedMaintenanceTicket:
        requester_sid_digest = _required_digest(requester_sid_digest)
        installation_id = _required_digest(installation_id)
        epoch = _required_counter(epoch)
        root_revision = _required_counter(root_revision)
        operation_digest = _required_digest(operation_digest)
        ttl_seconds = _required_counter(ttl_seconds)
        if ttl_seconds > _MAX_TTL_SECONDS:
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        try:
            raw = self._dependencies.random_bytes(32)
            if not isinstance(raw, bytes) or len(raw) != 32:
                raise ValueError("invalid random source")
            secret = f"maintenance-ticket-v1:{raw.hex()}"
            ticket_digest = self._ticket_digest(secret)
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = self._observe_clock(connection)
                self._require_active_boot(connection)
                count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM maintenance_tickets WHERE service_boot_digest=?",
                        (self._boot_digest,),
                    ).fetchone()[0]
                )
                if count >= _MAX_TICKETS_PER_BOOT:
                    connection.rollback()
                    raise MaintenanceTicketCapacity(
                        "maintenance ticket capacity is exhausted"
                    )
                expires_at_ms = now_ms + ttl_seconds * 1000
                connection.execute(
                    """
                    INSERT INTO maintenance_tickets(
                        ticket_digest,requester_sid_digest,installation_id,epoch,
                        root_revision,operation_digest,service_boot_digest,state,
                        issued_at_ms,expires_at_ms,claimed_at_ms,finished_at_ms
                    ) VALUES(?,?,?,?,?,?,?,'prepared',?,?,NULL,NULL)
                    """,
                    (
                        ticket_digest,
                        requester_sid_digest,
                        installation_id,
                        epoch,
                        root_revision,
                        operation_digest,
                        self._boot_digest,
                        now_ms,
                        expires_at_ms,
                    ),
                )
                connection.commit()
            return IssuedMaintenanceTicket(secret=secret, expires_at_ms=expires_at_ms)
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def claim(
        self,
        secret: str,
        *,
        requester_sid_digest: str,
        installation_id: str,
        epoch: int,
        root_revision: int,
        operation_digest: str,
    ) -> bool:
        ticket_digest = self._ticket_digest(secret)
        requester_sid_digest = _required_digest(requester_sid_digest)
        installation_id = _required_digest(installation_id)
        epoch = _required_counter(epoch)
        root_revision = _required_counter(root_revision)
        operation_digest = _required_digest(operation_digest)
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = self._observe_clock(connection)
                self._require_active_boot(connection)
                self._expire_locked(connection, now_ms)
                cursor = connection.execute(
                    """
                    UPDATE maintenance_tickets
                    SET state='claimed', claimed_at_ms=?
                    WHERE ticket_digest=? AND requester_sid_digest=?
                      AND installation_id=? AND epoch=? AND root_revision=?
                      AND operation_digest=? AND service_boot_digest=?
                      AND state='prepared' AND expires_at_ms>?
                    """,
                    (
                        now_ms,
                        ticket_digest,
                        requester_sid_digest,
                        installation_id,
                        epoch,
                        root_revision,
                        operation_digest,
                        self._boot_digest,
                        now_ms,
                    ),
                )
                connection.commit()
                return cursor.rowcount == 1
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def state(self, secret: str) -> TicketState | None:
        ticket_digest = self._ticket_digest(secret)
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = self._observe_clock(connection)
                self._require_active_boot(connection)
                self._expire_locked(connection, now_ms)
                row = connection.execute(
                    "SELECT state FROM maintenance_tickets WHERE ticket_digest=?",
                    (ticket_digest,),
                ).fetchone()
                connection.commit()
                return None if row is None else str(row[0])  # type: ignore[return-value]
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def finish(self, secret: str, *, success: bool) -> bool:
        ticket_digest = self._ticket_digest(secret)
        if not isinstance(success, bool):
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = self._observe_clock(connection)
                self._require_active_boot(connection)
                cursor = connection.execute(
                    """
                    UPDATE maintenance_tickets
                    SET state=?, finished_at_ms=?
                    WHERE ticket_digest=? AND service_boot_digest=?
                      AND state='claimed'
                    """,
                    (
                        "consumed" if success else "failed",
                        now_ms,
                        ticket_digest,
                        self._boot_digest,
                    ),
                )
                connection.commit()
                return cursor.rowcount == 1
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def is_claimed_operation(self, request: RestrictedCaptureRequest) -> bool:
        """Confirm the sole active-boot ticket for an exact operation binding.

        This service-only lookup deliberately has no public-secret fallback.
        Ambiguous duplicate bindings fail closed because a caller without the
        secret cannot prove which claimed capability it is reconciling.
        """

        if not isinstance(request, RestrictedCaptureRequest):
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = self._observe_clock(connection)
                self._require_active_boot(connection)
                self._expire_locked(connection, now_ms)
                rows = connection.execute(
                    """
                    SELECT state FROM maintenance_tickets
                    WHERE requester_sid_digest=? AND installation_id=?
                      AND epoch=? AND root_revision=? AND operation_digest=?
                      AND service_boot_digest=?
                    """,
                    (
                        request.requester_sid_digest,
                        request.installation_id,
                        request.epoch,
                        request.root_revision,
                        request.operation_digest,
                        self._boot_digest,
                    ),
                ).fetchall()
                connection.commit()
                return len(rows) == 1 and str(rows[0][0]) == "claimed"
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def discover_claimed_operations(
        self,
        *,
        after_operation_digest: str | None = None,
        limit: int = 32,
    ) -> MaintenanceClaimedOperationDiscoveryPage:
        """Discover active-boot claimed bindings without ticket secrets.

        A digest with more than one claimed ticket is reported as ambiguous
        and never converted into an actionable request.  This is intentionally
        a read-only snapshot: claimed capabilities do not expire, and startup
        discovery must not advance the wall-clock ledger or mutate ticket
        state merely by observing it.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_TICKETS_PER_BOOT
        ):
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        if after_operation_digest is not None:
            cursor = _required_digest(after_operation_digest)
        else:
            cursor = None
        try:
            with self._read_connection() as connection:
                rows = connection.execute(
                    """
                    SELECT ticket_digest,requester_sid_digest,installation_id,
                           epoch,root_revision,operation_digest
                    FROM maintenance_tickets
                    WHERE service_boot_digest=? AND state='claimed'
                    ORDER BY operation_digest,ticket_digest
                    LIMIT ?
                    """,
                    (self._boot_digest, _MAX_TICKETS_PER_BOOT + 1),
                ).fetchall()
                if len(rows) > _MAX_TICKETS_PER_BOOT:
                    raise sqlite3.DatabaseError(
                        "maintenance ticket row capacity is invalid"
                    )

                grouped: dict[str, list[RestrictedCaptureRequest]] = {}
                for row in rows:
                    _required_digest(row[0])
                    request = RestrictedCaptureRequest(
                        requester_sid_digest=_required_digest(row[1]),
                        installation_id=_required_digest(row[2]),
                        epoch=_required_counter(row[3]),
                        root_revision=_required_counter(row[4]),
                        operation_digest=_required_digest(row[5]),
                    )
                    grouped.setdefault(request.operation_digest, []).append(request)

                operation_digests = sorted(
                    operation_digest
                    for operation_digest in grouped
                    if cursor is None or operation_digest > cursor
                )
                page_digests = operation_digests[:limit]
                items: list[RestrictedCaptureRequest] = []
                ambiguous: list[str] = []
                for operation_digest in page_digests:
                    candidates = grouped[operation_digest]
                    if len(candidates) != 1:
                        ambiguous.append(operation_digest)
                    else:
                        items.append(candidates[0])
                return MaintenanceClaimedOperationDiscoveryPage(
                    items=tuple(items),
                    ambiguous_operation_digests=tuple(ambiguous),
                    next_cursor=(
                        page_digests[-1]
                        if len(operation_digests) > limit and page_digests
                        else None
                    ),
                )
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def finalize_claimed_operation(
        self,
        request: RestrictedCaptureRequest,
        *,
        success: bool,
    ) -> bool:
        """Finalize one unambiguous active-boot claim by exact binding.

        The method is idempotent only for the requested terminal value.  It
        never changes a prepared, opposite-terminal, expired, foreign-boot,
        or ambiguously duplicated ticket.
        """

        if not isinstance(request, RestrictedCaptureRequest) or not isinstance(
            success, bool
        ):
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        terminal = "consumed" if success else "failed"
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = self._observe_clock(connection)
                self._require_active_boot(connection)
                rows = connection.execute(
                    """
                    SELECT ticket_digest,state FROM maintenance_tickets
                    WHERE requester_sid_digest=? AND installation_id=?
                      AND epoch=? AND root_revision=? AND operation_digest=?
                      AND service_boot_digest=?
                    """,
                    (
                        request.requester_sid_digest,
                        request.installation_id,
                        request.epoch,
                        request.root_revision,
                        request.operation_digest,
                        self._boot_digest,
                    ),
                ).fetchall()
                if len(rows) != 1:
                    connection.commit()
                    return False
                ticket_digest = str(rows[0][0])
                state = str(rows[0][1])
                if state == terminal:
                    connection.commit()
                    return True
                if state != "claimed":
                    connection.commit()
                    return False
                cursor = connection.execute(
                    """
                    UPDATE maintenance_tickets
                    SET state=?, finished_at_ms=?
                    WHERE ticket_digest=? AND requester_sid_digest=?
                      AND installation_id=? AND epoch=? AND root_revision=?
                      AND operation_digest=? AND service_boot_digest=?
                      AND state='claimed'
                    """,
                    (
                        terminal,
                        now_ms,
                        ticket_digest,
                        request.requester_sid_digest,
                        request.installation_id,
                        request.epoch,
                        request.root_revision,
                        request.operation_digest,
                        self._boot_digest,
                    ),
                )
                connection.commit()
                return cursor.rowcount == 1
        except MaintenanceTicketError:
            raise
        except Exception:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            ) from None

    def _ticket_digest(self, secret: object) -> str:
        if not isinstance(secret, str) or _TICKET_SECRET_RE.fullmatch(secret) is None:
            raise MaintenanceTicketValidationError(
                "maintenance ticket request is invalid"
            )
        return hashlib.sha256(
            b"nachuan-maintenance-ticket-v1\0"
            + bytes.fromhex(self._boot_digest)
            + secret.encode("ascii")
        ).hexdigest()

    def _wall_time_ms(self) -> int:
        value = self._dependencies.wall_clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid wall clock")
        numeric = float(value)
        if not math.isfinite(numeric) or numeric < 0:
            raise ValueError("invalid wall clock")
        milliseconds = int(numeric * 1000)
        if milliseconds > _INT64_MAX:
            raise OverflowError("wall clock is outside SQLite range")
        return milliseconds

    def _observe_clock(self, connection: sqlite3.Connection) -> int:
        now_ms = self._wall_time_ms()
        row = connection.execute(
            "SELECT last_wall_time_ms,clock_state FROM maintenance_ticket_meta WHERE singleton=1"
        ).fetchone()
        if not row or str(row[1]) != "ok":
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            )
        if now_ms < int(row[0]):
            # Persist the alarm before reporting it.  Continuing after the
            # wall clock later catches up could silently extend a capability.
            connection.execute(
                "UPDATE maintenance_ticket_meta SET clock_state='rollback' "
                "WHERE singleton=1 AND clock_state='ok'"
            )
            connection.commit()
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            )
        connection.execute(
            "UPDATE maintenance_ticket_meta SET last_wall_time_ms=? WHERE singleton=1",
            (now_ms,),
        )
        return now_ms

    def _require_active_boot(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT active_boot_digest FROM maintenance_ticket_meta WHERE singleton=1"
        ).fetchone()
        if not row or str(row[0]) != self._boot_digest:
            raise MaintenanceTicketUnavailable(
                "maintenance ticket store is unavailable"
            )

    def _expire_locked(self, connection: sqlite3.Connection, now_ms: int) -> None:
        connection.execute(
            """
            UPDATE maintenance_tickets
            SET state='expired', finished_at_ms=?
            WHERE service_boot_digest=? AND state='prepared' AND expires_at_ms<=?
            """,
            (now_ms, self._boot_digest, now_ms),
        )

    def _prepare_parent(self, *, provisioning: bool) -> None:
        boundary = Path(self._dependencies.trusted_boundary(self.path))
        parent = self.path.parent
        if boundary != parent:
            raise OSError("ticket database must be directly inside its trusted boundary")
        if not parent.is_dir():
            raise OSError("trusted boundary does not exist")
        if provisioning:
            self._dependencies.harden_acl(parent, True)
        self._dependencies.assert_acl(parent, True)

    def _assert_authority_path(self) -> None:
        self._prepare_parent(provisioning=False)
        presence = self._database_family_presence()
        if not presence[""]:
            raise OSError("ticket database is missing")
        if not presence["-journal"] and not (
            presence["-wal"] and presence["-shm"]
        ):
            raise OSError("ticket database journal is missing")

    @staticmethod
    def _is_reparse(info: os.stat_result) -> bool:
        flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return stat.S_ISLNK(info.st_mode) or bool(
            int(getattr(info, "st_file_attributes", 0)) & flag
        )

    def _database_family_presence(self) -> dict[str, bool]:
        presence: dict[str, bool] = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(f"{self.path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                presence[suffix] = False
                continue
            if not stat.S_ISREG(info.st_mode) or self._is_reparse(info):
                raise OSError("ticket database family contains an unsafe object")
            self._dependencies.assert_acl(candidate, False)
            presence[suffix] = True
        return presence

    def _database_path_identity(self) -> tuple[int, int]:
        info = os.lstat(self.path)
        if not stat.S_ISREG(info.st_mode) or self._is_reparse(info):
            raise OSError("ticket database path is unsafe")
        return int(info.st_dev), int(info.st_ino)

    def _assert_database_family_bounds(self) -> None:
        limits = {
            "": _MAX_MAIN_DB_BYTES,
            "-wal": _MAX_WAL_BYTES,
            "-shm": _MAX_SHM_BYTES,
            "-journal": _MAX_ROLLBACK_JOURNAL_BYTES,
        }
        for suffix, limit in limits.items():
            candidate = Path(f"{self.path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or self._is_reparse(info)
                or int(info.st_size) > limit
            ):
                raise sqlite3.DatabaseError(
                    "ticket database family exceeds its bounded profile"
                )

    def _database_header_mode(self) -> str:
        with self.path.open("rb") as handle:
            header = handle.read(20)
        if len(header) < 20 or not header.startswith(b"SQLite format 3\x00"):
            raise sqlite3.DatabaseError("ticket database header is invalid")
        if header[18:20] == b"\x01\x01":
            return "rollback"
        if header[18:20] == b"\x02\x02":
            return "wal"
        raise sqlite3.DatabaseError("ticket database journal header is invalid")

    def _database_schema_signature(
        self, identity: tuple[int, int]
    ) -> tuple[int, int, bytes]:
        with self.path.open("rb") as handle:
            header = handle.read(72)
        if len(header) < 72 or not header.startswith(b"SQLite format 3\x00"):
            raise sqlite3.DatabaseError("ticket database header is invalid")
        schema_header = header[16:18] + header[40:48] + header[52:72]
        return identity[0], identity[1], schema_header

    def _rollback_journal_state(self) -> str:
        journal = Path(f"{self.path}-journal")
        if not journal.exists():
            return "absent"
        with journal.open("rb") as handle:
            header = handle.read(8)
        if not header or header == b"\x00" * len(header):
            return "clean"
        if header == _ROLLBACK_JOURNAL_MAGIC:
            return "hot"
        raise sqlite3.DatabaseError(
            "ticket rollback journal requires explicit forensic recovery"
        )

    def _classify_schema_generation(self, connection: sqlite3.Connection) -> str:
        if int(connection.execute("PRAGMA application_id").fetchone()[0]) != _APPLICATION_ID:
            raise sqlite3.DatabaseError("ticket database application id is invalid")
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != _SCHEMA_VERSION:
            raise sqlite3.DatabaseError("ticket database schema version is invalid")
        if int(connection.execute("PRAGMA page_size").fetchone()[0]) != _PAGE_SIZE:
            raise sqlite3.DatabaseError("ticket database page size is invalid")
        actual = {
            (str(row[0]), str(row[1])): (
                str(row[2]),
                _schema_entry_sql(row[3]),
            )
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "ORDER BY type, name"
            ).fetchall()
        }
        if actual != _expected_schema():
            raise sqlite3.DatabaseError("ticket database schema is invalid")
        return "current"

    def _preflight_database_family_once(self) -> tuple[dict[str, bool], tuple[int, int]]:
        self._assert_authority_path()
        presence = self._database_family_presence()
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "ticket WAL and SHM sidecars must be present together"
            )
        identity = self._database_path_identity()
        self._assert_database_family_bounds()
        header_mode = self._database_header_mode()
        journal_state = self._rollback_journal_state()
        clean_signature: tuple[int, int, bytes] | None = None
        if not presence["-wal"]:
            if header_mode != "rollback":
                raise sqlite3.DatabaseError(
                    "ticket WAL header is missing its complete sidecars"
                )
            if journal_state == "clean":
                clean_signature = self._database_schema_signature(identity)
                if self._trusted_clean_schema_signature == clean_signature:
                    presence_after = self._database_family_presence()
                    if presence_after != presence:
                        raise _DatabaseFamilyChanged(
                            "ticket database family changed during fast preflight"
                        )
                    if self._database_path_identity() != identity:
                        raise sqlite3.DatabaseError(
                            "ticket database path changed during fast preflight"
                        )
                    return presence_after, identity
        immutable_uri = f"{self.path.as_uri()}?mode=ro&immutable=1"
        connection = sqlite3.connect(
            immutable_uri,
            uri=True,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            self._classify_schema_generation(connection)
        finally:
            connection.close()
        presence_after = self._database_family_presence()
        if presence_after != presence:
            raise _DatabaseFamilyChanged(
                "ticket database family changed during immutable preflight"
            )
        if self._database_path_identity() != identity:
            raise sqlite3.DatabaseError(
                "ticket database path changed during immutable preflight"
            )
        if clean_signature is not None:
            if self._database_schema_signature(identity) != clean_signature:
                raise _DatabaseFamilyChanged(
                    "ticket schema signature changed during immutable preflight"
                )
            self._trusted_clean_schema_signature = clean_signature
        if presence_after["-wal"]:
            wal_uri = f"{self.path.as_uri()}?mode=ro"
            connection = sqlite3.connect(
                wal_uri,
                uri=True,
                isolation_level=None,
                timeout=_BUSY_TIMEOUT_MS / 1000,
            )
            try:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("BEGIN")
                try:
                    self._classify_schema_generation(connection)
                finally:
                    connection.rollback()
            finally:
                connection.close()
            wal_presence = self._database_family_presence()
            if wal_presence != presence_after:
                raise _DatabaseFamilyChanged(
                    "ticket database family changed during WAL-aware preflight"
                )
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "ticket database path changed during WAL-aware preflight"
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
        raise sqlite3.DatabaseError(
            "ticket database family did not stabilize during preflight"
        ) from last_change

    def _harden_sidecars(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                self._dependencies.harden_acl(candidate, False)
                self._dependencies.assert_acl(candidate, False)

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        """Open a validated logical snapshot without a read-write handle."""

        preflight_presence, preflight_identity = self._preflight_database_family()
        if not preflight_presence["-wal"] and self._rollback_journal_state() != "clean":
            raise sqlite3.DatabaseError(
                "ticket database requires read-write recovery before discovery"
            )
        suffix = "?mode=ro" if preflight_presence["-wal"] else "?mode=ro&immutable=1"
        connection = sqlite3.connect(
            f"{self.path.as_uri()}{suffix}",
            uri=True,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            if self._database_path_identity() != preflight_identity:
                raise sqlite3.DatabaseError(
                    "ticket database path changed before read-only open"
                )
            # max_page_count is a per-connection writer limit rather than
            # durable schema authority.  The read-only snapshot enforces the
            # physical family bounds above and validates the exact schema,
            # while every writer-capable handle reapplies the page limit.
            self._validate_schema(connection, require_capacity=False)
            self._require_active_boot(connection)
            yield connection
            if self._database_path_identity() != preflight_identity:
                raise sqlite3.DatabaseError(
                    "ticket database path changed during read-only discovery"
                )
            if self._database_family_presence() != preflight_presence:
                raise sqlite3.DatabaseError(
                    "ticket database family changed during read-only discovery"
                )
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        preflight_presence, preflight_identity = self._preflight_database_family()
        if self._database_family_presence() != preflight_presence:
            preflight_presence, preflight_identity = self._preflight_database_family()
        uri = f"file:{self.path.as_posix()}?mode=rw"
        connection = sqlite3.connect(
            uri,
            uri=True,
            isolation_level=None,
            timeout=_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            if self._database_path_identity() != preflight_identity:
                raise sqlite3.DatabaseError(
                    "ticket database path changed before read-write open"
                )
            opened_presence = self._database_family_presence()
            if not opened_presence[""] or (
                opened_presence["-wal"] != opened_presence["-shm"]
            ):
                raise sqlite3.DatabaseError(
                    "ticket database family changed during read-write recovery"
                )
            connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            self._validate_schema(connection, require_capacity=False)
            mode = connection.execute("PRAGMA journal_mode=PERSIST").fetchone()
            if not mode or str(mode[0]).casefold() != "persist":
                raise sqlite3.DatabaseError(
                    "ticket database requires PERSIST journal mode"
                )
            journal = Path(f"{self.path}-journal")
            if not journal.exists():
                # A successful hot-journal rollback or trusted WAL-to-PERSIST
                # conversion can remove the previous sidecar.  Create a new
                # SQLite-owned pinned journal through a fully rolled-back DDL
                # transaction; the closed schema is unchanged.
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        "CREATE TABLE nachuan_ticket_persist_probe(singleton INTEGER)"
                    )
                finally:
                    connection.rollback()
            self._assert_authority_path()
            max_pages = connection.execute(
                f"PRAGMA max_page_count={_MAX_PAGE_COUNT}"
            ).fetchone()
            if not max_pages or int(max_pages[0]) != _MAX_PAGE_COUNT:
                raise sqlite3.DatabaseError(
                    "ticket database capacity cannot be enforced"
                )
            self._validate_schema(connection)
            if self._trusted_clean_schema_signature is None:
                current_presence = self._database_family_presence()
                if (
                    not current_presence["-wal"]
                    and not current_presence["-shm"]
                    and self._rollback_journal_state() == "clean"
                ):
                    current_identity = self._database_path_identity()
                    self._trusted_clean_schema_signature = (
                        self._database_schema_signature(current_identity)
                    )
            yield connection
            self._assert_authority_path()
        finally:
            connection.close()

    def _validate_schema(
        self,
        connection: sqlite3.Connection,
        *,
        require_capacity: bool = True,
    ) -> None:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise sqlite3.DatabaseError("ticket database integrity check failed")
        self._classify_schema_generation(connection)
        if (
            require_capacity
            and int(connection.execute("PRAGMA max_page_count").fetchone()[0])
            != _MAX_PAGE_COUNT
        ):
            raise sqlite3.DatabaseError("ticket database capacity is invalid")
