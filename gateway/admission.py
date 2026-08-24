"""Global admission control for explicitly expensive authenticated requests.

The middleware deliberately accounts *requests*, not fictional dollar costs.  A
request is admitted only after three independent gates pass:

* per-key in-flight concurrency;
* a per-key rolling sixty-second request window; and
* an atomic, persistent SQLite per-key/day counter.

Only a domain-separated SHA-256 bucket is retained.  Bearer credentials are never
written to SQLite, returned to clients, or kept by this middleware after hashing.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import math
import secrets
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable, Collection
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, time as datetime_time, timedelta
from pathlib import Path
from typing import Any

from starlette.responses import JSONResponse

_HASH_DOMAIN = b"nachuan-admission-key-v1\x00"
_HEX = frozenset("0123456789abcdef")

# POST is charged by default.  Only control-plane operations which are both
# bounded and demonstrably cheap stay available when inference capacity is full.
# This allowlist is intentionally tiny so a newly-added model/embedding/fetch
# endpoint cannot silently bypass admission.  Explicit GET families cover remote
# provider polling and large video transfers; ordinary local status reads stay
# available while model capacity is saturated.
_EXPENSIVE_GET_ONE_SEGMENT_PREFIXES = (
    "/v1/videos/",
    "/v1/studio/video/",
)
_CHEAP_POST_EXACT = frozenset(
    {
        "/v1/agent/feedback",
        "/v1/agent/inject",
        "/v1/agent/undo",
        # Already-paid bytes must remain archivable after the ordinary daily
        # inference quota is exhausted. This route has independent dual auth,
        # two upload/decode slots and private-spool capacity accounting.
        "/v1/paid-media/probe",
        # Local Web archive recovery performs no inference and no provider
        # create/poll.  It has its own authenticated principal, bounded page
        # size, archive read slots, byte budgets, and digest verification.
        # Keeping these paths available prevents an exhausted inference quota
        # from stranding bytes which have already been paid for and archived.
        "/v1/paid-media/web/list-archives",
        "/v1/paid-media/web/list",
        "/v1/paid-media/web/import-legacy",
        "/v1/paid-media/web/recover-archive",
        "/v1/paid-media/web/read-asset",
    }
)

_CURRENT_BUCKET: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "nachuan_admission_bucket",
    default=None,
)
_CURRENT_BACKGROUND_LEASES: contextvars.ContextVar[dict[str, str] | None] = (
    contextvars.ContextVar("nachuan_background_job_leases", default=None)
)


def hash_bearer_token(token: str) -> str:
    """Return the stable, domain-separated bucket for one Bearer credential."""

    if not isinstance(token, str) or not token:
        raise ValueError("Bearer token must be a non-empty string")
    return hashlib.sha256(_HASH_DOMAIN + token.encode("utf-8")).hexdigest()


def hash_api_keys(keys: Collection[str]) -> frozenset[str]:
    """Hash configured API keys without retaining their plaintext in middleware."""

    return frozenset(hash_bearer_token(key) for key in keys if key)


def is_expensive_request(method: str, path: str) -> bool:
    """Charge costly requests, with POST defaulting to expensive.

    Cheap local GET/HEAD status routes do not enter the gate.  Remote video
    provider polling, the video fetch proxy and large Studio video transfers do.
    POST endpoints such as intent routing, web reads and knowledge queries also
    do: although semantically read-only, they perform real model, embedding or
    network work.
    """

    request_method = str(method).upper()
    canonical = str(path or "")
    if len(canonical) > 1:
        canonical = canonical.rstrip("/")
    if request_method == "GET":
        for prefix in _EXPENSIVE_GET_ONE_SEGMENT_PREFIXES:
            if canonical.startswith(prefix):
                suffix = canonical[len(prefix) :]
                if suffix and "/" not in suffix:
                    return True
        return False
    if request_method != "POST":
        return False
    if canonical in _CHEAP_POST_EXACT:
        return False
    if canonical.startswith("/v1/approvals/") and canonical.endswith("/resolve"):
        approval_id = canonical[len("/v1/approvals/") : -len("/resolve")]
        if approval_id.isdecimal() and "/" not in approval_id:
            return False
    return True


def current_admission_bucket() -> str:
    """Return the current authenticated hash bucket, or a stable internal bucket."""

    return _CURRENT_BUCKET.get() or hash_bearer_token("nachuan-internal-job")


def current_background_job_lease(kind: str) -> str | None:
    leases = _CURRENT_BACKGROUND_LEASES.get() or {}
    return leases.get(str(kind))


def set_background_job_lease(kind: str, token: str) -> contextvars.Token:
    leases = dict(_CURRENT_BACKGROUND_LEASES.get() or {})
    leases[str(kind)] = str(token)
    return _CURRENT_BACKGROUND_LEASES.set(leases)


def reset_background_job_lease(token: contextvars.Token) -> None:
    _CURRENT_BACKGROUND_LEASES.reset(token)


class AdmissionStoreUnavailable(RuntimeError):
    """Persistent admission accounting cannot be trusted or updated."""


class _AmbiguousAuthorization(ValueError):
    """More than one credential was supplied for one HTTP request."""


class _SQLiteDailyCounter:
    """Small connection-per-operation SQLite counter safe across processes."""

    _TABLE = "admission_daily"

    def __init__(self, db_path: str | Path, *, busy_timeout_ms: int = 250) -> None:
        self.path = Path(db_path)
        self.busy_timeout_ms = max(1, min(int(busy_timeout_ms), 10_000))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and not self.path.is_file():
                raise OSError("admission database path is not a regular file")
            with closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._TABLE} (
                        bucket_hash TEXT NOT NULL,
                        day TEXT NOT NULL,
                        request_count INTEGER NOT NULL CHECK(request_count >= 0),
                        PRIMARY KEY(bucket_hash, day)
                    ) WITHOUT ROWID
                    """
                )
                check = connection.execute("PRAGMA quick_check").fetchone()
                if not check or check[0] != "ok":
                    raise sqlite3.DatabaseError("admission database integrity check failed")
                columns = connection.execute(
                    f"PRAGMA table_info({self._TABLE})"
                ).fetchall()
                signature = [(row[1], str(row[2]).upper(), int(row[5])) for row in columns]
                expected = [
                    ("bucket_hash", "TEXT", 1),
                    ("day", "TEXT", 2),
                    ("request_count", "INTEGER", 0),
                ]
                if signature != expected:
                    raise sqlite3.DatabaseError("unexpected admission database schema")
        except (OSError, sqlite3.Error) as exc:
            raise AdmissionStoreUnavailable("admission accounting is unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            return connection
        except Exception:
            connection.close()
            raise

    def _try_consume_once(self, *, bucket_hash: str, day: str, limit: int) -> bool:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                f"""
                SELECT request_count, typeof(request_count)
                FROM {self._TABLE}
                WHERE bucket_hash = ? AND day = ?
                """,
                (bucket_hash, day),
            ).fetchone()
            if row is not None:
                if row[1] != "integer" or int(row[0]) < 0:
                    raise sqlite3.DatabaseError("invalid admission counter")
                if int(row[0]) >= limit:
                    connection.rollback()
                    return False
                connection.execute(
                    f"""
                    UPDATE {self._TABLE}
                    SET request_count = request_count + 1
                    WHERE bucket_hash = ? AND day = ?
                    """,
                    (bucket_hash, day),
                )
            else:
                connection.execute(
                    f"""
                    INSERT INTO {self._TABLE}(bucket_hash, day, request_count)
                    VALUES (?, ?, 1)
                    """,
                    (bucket_hash, day),
                )
            connection.commit()
            return True
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise AdmissionStoreUnavailable("admission accounting is unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _is_transient_lock(exc: AdmissionStoreUnavailable) -> bool:
        cause = exc.__cause__
        if not isinstance(cause, sqlite3.OperationalError):
            return False
        code = getattr(cause, "sqlite_errorcode", None)
        if isinstance(code, int) and (code & 0xFF) in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }:
            return True
        return "locked" in str(cause).lower() or "busy" in str(cause).lower()

    def try_consume(self, *, bucket_hash: str, day: str, limit: int) -> bool:
        """Atomically consume one daily request across gateway instances.

        SQLite already waits for ``busy_timeout_ms``.  Two short additional
        attempts cover normal cross-process commit races on Windows without ever
        turning a sustained lock into a false admission.
        """

        for attempt in range(3):
            try:
                return self._try_consume_once(
                    bucket_hash=bucket_hash,
                    day=day,
                    limit=limit,
                )
            except AdmissionStoreUnavailable as exc:
                if attempt >= 2 or not self._is_transient_lock(exc):
                    raise
                time.sleep(0.01 * (2**attempt))
        raise AdmissionStoreUnavailable("admission accounting is unavailable")

    def _probe_writable_once(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            check = connection.execute("PRAGMA quick_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError("admission database integrity check failed")
            connection.execute(
                f"SELECT bucket_hash, day, request_count FROM {self._TABLE} LIMIT 0"
            ).fetchall()
            connection.rollback()
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            raise AdmissionStoreUnavailable("admission accounting is unavailable") from exc
        finally:
            if connection is not None:
                connection.close()

    def probe_writable(self) -> None:
        """Verify integrity and obtain a write reservation without mutating data."""

        for attempt in range(3):
            try:
                self._probe_writable_once()
                return
            except AdmissionStoreUnavailable as exc:
                if attempt >= 2 or not self._is_transient_lock(exc):
                    raise
                time.sleep(0.01 * (2**attempt))


@dataclass
class _BucketState:
    in_flight: int = 0
    recent: deque[tuple[float, int]] = field(default_factory=deque)


@dataclass(frozen=True)
class _LocalLease:
    bucket_hash: str
    rate_event: tuple[float, int]


class BackgroundJobLimitExceeded(RuntimeError):
    """No background-job capacity is available for this principal/system."""


@dataclass
class _BackgroundLease:
    bucket_hash: str
    kind: str
    expires_at: float
    external_ids: set[str] = field(default_factory=set)


class BackgroundJobLeasePool:
    """Thread-safe process-level leases for work which outlives its HTTP request.

    Leases contain only an irreversible API-key bucket.  A bounded TTL fences
    abandoned remote jobs which are never polled, while normal studio/agent jobs
    release in their task ``finally`` and remote video jobs release on terminal
    polling.
    """

    def __init__(
        self,
        *,
        max_global: int = 8,
        max_per_key: int = 4,
        lease_ttl_seconds: int = 21_600,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_global = int(max_global)
        self.max_per_key = int(max_per_key)
        self.lease_ttl_seconds = int(lease_ttl_seconds)
        if not 1 <= self.max_global <= 256:
            raise ValueError("background max_global must be in [1, 256]")
        if not 1 <= self.max_per_key <= self.max_global:
            raise ValueError("background max_per_key must be in [1, max_global]")
        if not 300 <= self.lease_ttl_seconds <= 86_400:
            raise ValueError("background lease TTL must be in [300, 86400]")
        self._clock = monotonic_clock or time.monotonic
        self._lock = threading.Lock()
        self._leases: dict[str, _BackgroundLease] = {}
        self._external: dict[tuple[str, str], str] = {}

    @staticmethod
    def _validated_kind(value: str) -> str:
        kind = str(value or "").strip()
        if not kind or len(kind) > 64 or any(ord(ch) < 33 or ord(ch) == 127 for ch in kind):
            raise ValueError("invalid background job kind")
        return kind

    @staticmethod
    def _validated_ids(values: Collection[str]) -> tuple[str, ...]:
        out: list[str] = []
        for value in values:
            item = str(value or "").strip()
            if not item or len(item) > 256 or any(ord(ch) < 32 or ord(ch) == 127 for ch in item):
                raise ValueError("invalid background job id")
            if item not in out:
                out.append(item)
        if len(out) > 8:
            raise ValueError("too many aliases for one background job")
        return tuple(out)

    def _drop_locked(self, token: str) -> bool:
        lease = self._leases.pop(token, None)
        if lease is None:
            return False
        for external_id in lease.external_ids:
            self._external.pop((lease.kind, external_id), None)
        return True

    def _prune_locked(self, now: float) -> None:
        for token, lease in list(self._leases.items()):
            if lease.expires_at <= now:
                self._drop_locked(token)

    def try_acquire(
        self,
        *,
        kind: str,
        bucket_hash: str | None = None,
        external_ids: Collection[str] = (),
    ) -> str | None:
        """Acquire a job slot or return ``None`` without queueing unbounded work."""

        normalized_kind = self._validated_kind(kind)
        bucket = str(bucket_hash or current_admission_bucket())
        if len(bucket) != 64 or any(ch not in _HEX for ch in bucket):
            raise ValueError("background job bucket must be a SHA-256 digest")
        aliases = self._validated_ids(external_ids)
        now = float(self._clock())
        with self._lock:
            self._prune_locked(now)
            if len(self._leases) >= self.max_global:
                return None
            if sum(1 for lease in self._leases.values() if lease.bucket_hash == bucket) >= self.max_per_key:
                return None
            if any((normalized_kind, alias) in self._external for alias in aliases):
                return None
            token = secrets.token_hex(16)
            while token in self._leases:
                token = secrets.token_hex(16)
            lease = _BackgroundLease(
                bucket_hash=bucket,
                kind=normalized_kind,
                expires_at=now + self.lease_ttl_seconds,
                external_ids=set(aliases),
            )
            self._leases[token] = lease
            for alias in aliases:
                self._external[(normalized_kind, alias)] = token
            return token

    def restore(
        self,
        *,
        kind: str,
        bucket_hash: str,
        external_ids: Collection[str],
    ) -> str:
        """Restore one already-running durable job without weakening admission.

        A deployment may lower its configured limits while more remote jobs are
        still running.  Those jobs must all remain counted, even when the
        restored total is temporarily above the new limit; ``try_acquire`` then
        stays closed until enough terminal jobs have released their aliases.
        """

        normalized_kind = self._validated_kind(kind)
        bucket = str(bucket_hash or "")
        if len(bucket) != 64 or any(ch not in _HEX for ch in bucket):
            raise ValueError("background job bucket must be a SHA-256 digest")
        aliases = self._validated_ids(external_ids)
        if not aliases:
            raise ValueError("restored background job requires an external id")
        now = float(self._clock())
        with self._lock:
            self._prune_locked(now)
            existing_tokens = {
                token
                for alias in aliases
                if (token := self._external.get((normalized_kind, alias))) is not None
            }
            if existing_tokens:
                if len(existing_tokens) != 1:
                    raise ValueError("restored background job aliases conflict")
                token = next(iter(existing_tokens))
                lease = self._leases.get(token)
                if lease is None or lease.bucket_hash != bucket:
                    raise ValueError("restored background job ownership conflicts")
                if any(
                    (bound := self._external.get((normalized_kind, alias))) is not None
                    and bound != token
                    for alias in aliases
                ):
                    raise ValueError("restored background job aliases conflict")
                for alias in aliases:
                    lease.external_ids.add(alias)
                    self._external[(normalized_kind, alias)] = token
                lease.expires_at = now + self.lease_ttl_seconds
                return token
            token = secrets.token_hex(16)
            while token in self._leases:
                token = secrets.token_hex(16)
            self._leases[token] = _BackgroundLease(
                bucket_hash=bucket,
                kind=normalized_kind,
                expires_at=now + self.lease_ttl_seconds,
                external_ids=set(aliases),
            )
            for alias in aliases:
                self._external[(normalized_kind, alias)] = token
            return token

    def bind(self, token: str, external_ids: Collection[str]) -> bool:
        """Bind provider/job identifiers to a lease for terminal release/renewal."""

        aliases = self._validated_ids(external_ids)
        now = float(self._clock())
        with self._lock:
            self._prune_locked(now)
            lease = self._leases.get(str(token))
            if lease is None:
                return False
            if any(
                (existing := self._external.get((lease.kind, alias))) is not None
                and existing != token
                for alias in aliases
            ):
                return False
            for alias in aliases:
                lease.external_ids.add(alias)
                self._external[(lease.kind, alias)] = token
            lease.expires_at = now + self.lease_ttl_seconds
            return True

    def renew_external(self, kind: str, external_id: str) -> bool:
        normalized_kind = self._validated_kind(kind)
        alias = self._validated_ids((external_id,))[0]
        now = float(self._clock())
        with self._lock:
            self._prune_locked(now)
            token = self._external.get((normalized_kind, alias))
            if token is None or token not in self._leases:
                return False
            self._leases[token].expires_at = now + self.lease_ttl_seconds
            return True

    def release(self, token: str) -> bool:
        with self._lock:
            self._prune_locked(float(self._clock()))
            return self._drop_locked(str(token))

    def release_external(self, kind: str, external_id: str) -> bool:
        normalized_kind = self._validated_kind(kind)
        alias = self._validated_ids((external_id,))[0]
        with self._lock:
            self._prune_locked(float(self._clock()))
            token = self._external.get((normalized_kind, alias))
            return self._drop_locked(token) if token is not None else False

    def is_active(self, token: str) -> bool:
        """Return whether an opaque lease token still owns live capacity."""

        with self._lock:
            self._prune_locked(float(self._clock()))
            return str(token) in self._leases

    def counts(self) -> dict[str, int]:
        """Return aggregate diagnostics without hashes, ids or lease tokens."""

        with self._lock:
            self._prune_locked(float(self._clock()))
            return {
                "active": len(self._leases),
                "capacity": self.max_global,
            }


_BACKGROUND_POOL_LOCK = threading.Lock()
_BACKGROUND_POOL = BackgroundJobLeasePool()


def configure_background_job_pool(
    *, max_global: int, max_per_key: int, lease_ttl_seconds: int
) -> BackgroundJobLeasePool:
    """Install the process-wide pool before gateway traffic is accepted."""

    pool = BackgroundJobLeasePool(
        max_global=max_global,
        max_per_key=max_per_key,
        lease_ttl_seconds=lease_ttl_seconds,
    )
    global _BACKGROUND_POOL
    with _BACKGROUND_POOL_LOCK:
        _BACKGROUND_POOL = pool
    return pool


def get_background_job_pool() -> BackgroundJobLeasePool:
    with _BACKGROUND_POOL_LOCK:
        return _BACKGROUND_POOL


class AdmissionControlMiddleware:
    """Pure ASGI admission gate for authenticated, expensive POST requests."""

    WINDOW_SECONDS = 60.0

    def __init__(
        self,
        app: Any,
        *,
        db_path: str | Path,
        valid_key_hashes: Collection[str] | None = None,
        valid_key_hashes_provider: Callable[[], Collection[str]] | None = None,
        max_concurrency_per_key: int = 8,
        max_concurrency_global: int = 32,
        rolling_minute_per_key: int = 120,
        daily_expensive_per_key: int = 2000,
        monotonic_clock: Callable[[], float] | None = None,
        wall_clock: Callable[[], datetime] | None = None,
        sqlite_busy_timeout_ms: int = 250,
    ) -> None:
        self.app = app
        self.max_concurrency_per_key = int(max_concurrency_per_key)
        self.max_concurrency_global = int(max_concurrency_global)
        self.rolling_minute_per_key = int(rolling_minute_per_key)
        self.daily_expensive_per_key = int(daily_expensive_per_key)
        if not 1 <= self.max_concurrency_per_key <= 64:
            raise ValueError("max_concurrency_per_key must be in [1, 64]")
        if not self.max_concurrency_per_key <= self.max_concurrency_global <= 512:
            raise ValueError("max_concurrency_global must be in [per-key, 512]")
        if not 1 <= self.rolling_minute_per_key <= 10_000:
            raise ValueError("rolling_minute_per_key must be in [1, 10000]")
        if not 0 <= self.daily_expensive_per_key <= 1_000_000:
            raise ValueError("daily_expensive_per_key must be in [0, 1000000]")

        if valid_key_hashes is None and valid_key_hashes_provider is None:
            raise ValueError("an admission key-hash source is required")
        hashes = self._validated_hashes(valid_key_hashes or ())
        self._valid_key_hashes = hashes
        self._valid_key_hashes_provider = valid_key_hashes_provider
        self._monotonic = monotonic_clock or time.monotonic
        self._wall_clock = wall_clock or datetime.now
        self._lock = asyncio.Lock()
        self._states: dict[str, _BucketState] = {}
        self._global_in_flight = 0
        self._sequence = 0
        self._storage_healthy = True
        self._daily = (
            _SQLiteDailyCounter(db_path, busy_timeout_ms=sqlite_busy_timeout_ms)
            if self.daily_expensive_per_key > 0
            else None
        )

    @property
    def storage_healthy(self) -> bool:
        """Whether the last persistent counter operation completed reliably."""

        return self._storage_healthy

    @staticmethod
    def _validated_hashes(values: Collection[str]) -> frozenset[str]:
        if len(values) > 10_000:
            raise ValueError("too many admission key hashes")
        hashes = frozenset(str(value) for value in values)
        if any(len(value) != 64 or any(ch not in _HEX for ch in value) for value in hashes):
            raise ValueError("valid key hashes must be lowercase SHA-256 digests")
        return hashes

    def _current_valid_hashes(self) -> frozenset[str]:
        if self._valid_key_hashes_provider is None:
            return self._valid_key_hashes
        return self._validated_hashes(self._valid_key_hashes_provider())

    @staticmethod
    def _bearer_bucket(scope: dict[str, Any]) -> str | None:
        state = scope.get("state") or {}
        sealed_bucket = state.get("nachuan_bridge_bucket_hash")
        if sealed_bucket is not None:
            value = str(sealed_bucket)
            if len(value) != 64 or any(ch not in _HEX for ch in value):
                return None
            return value
        authorization_values: list[bytes] = []
        for raw_name, raw_value in scope.get("headers") or []:
            if bytes(raw_name).lower() == b"authorization":
                authorization_values.append(bytes(raw_value))
        if len(authorization_values) > 1:
            # Scalar FastAPI header dependencies may select one duplicate while
            # another layer selects another.  Reject ambiguity instead of ever
            # allowing an authenticated request to bypass accounting.
            raise _AmbiguousAuthorization("duplicate authorization headers")
        if not authorization_values:
            return None
        try:
            value = authorization_values[0].decode("latin-1")
        except UnicodeDecodeError:
            return None
        scheme, separator, candidate = value.partition(" ")
        token = candidate.strip()
        if separator != " " or scheme.lower() != "bearer" or not token:
            return None
        return hash_bearer_token(token)

    async def _acquire_local(self, bucket_hash: str) -> tuple[_LocalLease | None, int]:
        now = float(self._monotonic())
        async with self._lock:
            if self._global_in_flight >= self.max_concurrency_global:
                return None, 1
            state = self._states.setdefault(bucket_hash, _BucketState())
            cutoff = now - self.WINDOW_SECONDS
            while state.recent and state.recent[0][0] <= cutoff:
                state.recent.popleft()
            if state.in_flight >= self.max_concurrency_per_key:
                return None, 1
            if len(state.recent) >= self.rolling_minute_per_key:
                retry = max(1, math.ceil(self.WINDOW_SECONDS - (now - state.recent[0][0])))
                return None, retry
            self._sequence += 1
            event = (now, self._sequence)
            state.in_flight += 1
            self._global_in_flight += 1
            state.recent.append(event)
            return _LocalLease(bucket_hash=bucket_hash, rate_event=event), 0

    async def _release_local(self, lease: _LocalLease, *, rollback_rate: bool) -> None:
        async with self._lock:
            state = self._states.get(lease.bucket_hash)
            if state is None:
                return
            state.in_flight = max(0, state.in_flight - 1)
            self._global_in_flight = max(0, self._global_in_flight - 1)
            if rollback_rate:
                try:
                    state.recent.remove(lease.rate_event)
                except ValueError:
                    pass
            now = float(self._monotonic())
            cutoff = now - self.WINDOW_SECONDS
            while state.recent and state.recent[0][0] <= cutoff:
                state.recent.popleft()
            if state.in_flight == 0 and not state.recent:
                self._states.pop(lease.bucket_hash, None)

    def _daily_bucket(self) -> tuple[str, int]:
        now = self._wall_clock()
        if not isinstance(now, datetime):
            raise AdmissionStoreUnavailable("admission clock is unavailable")
        tomorrow = datetime.combine(
            now.date() + timedelta(days=1),
            datetime_time.min,
            tzinfo=now.tzinfo,
        )
        retry_after = max(1, math.ceil((tomorrow - now).total_seconds()))
        return now.date().isoformat(), retry_after

    @staticmethod
    async def _reject(scope: dict, receive, send, *, status: int, detail: str, retry: int) -> None:
        await JSONResponse(
            {"detail": detail},
            status_code=status,
            headers={"Retry-After": str(max(1, int(retry))), "Cache-Control": "no-store"},
        )(scope, receive, send)

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        path = str(scope.get("path") or "")
        if (
            scope.get("type") == "http"
            and path.rstrip("/") == "/health"
            and self._daily is not None
        ):
            try:
                await asyncio.to_thread(self._daily.probe_writable)
                self._storage_healthy = True
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._reject(
                    scope,
                    receive,
                    send,
                    status=503,
                    detail="admission accounting unavailable",
                    retry=5,
                )
                return
        if scope.get("type") != "http" or not is_expensive_request(
            str(scope.get("method") or ""), path
        ):
            await self.app(scope, receive, send)
            return

        try:
            bucket_hash = self._bearer_bucket(scope)
        except _AmbiguousAuthorization:
            await JSONResponse(
                {"detail": "ambiguous authorization headers"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )(scope, receive, send)
            return
        # Authentication remains authoritative. Missing credentials go directly
        # to its 401 path; a broken dynamic key source fails closed rather than
        # allowing a newly-valid credential to bypass admission.
        if bucket_hash is None:
            await self.app(scope, receive, send)
            return
        try:
            current_hashes = self._current_valid_hashes()
        except Exception:
            await self._reject(
                scope,
                receive,
                send,
                status=503,
                detail="admission authentication state unavailable",
                retry=5,
            )
            return
        if bucket_hash not in current_hashes:
            await self.app(scope, receive, send)
            return

        lease, retry_after = await self._acquire_local(bucket_hash)
        if lease is None:
            await self._reject(
                scope,
                receive,
                send,
                status=429,
                detail="expensive request admission limit reached",
                retry=retry_after,
            )
            return

        if self._daily is not None:
            try:
                day, daily_retry = self._daily_bucket()
                allowed = await asyncio.to_thread(
                    self._daily.try_consume,
                    bucket_hash=bucket_hash,
                    day=day,
                    limit=self.daily_expensive_per_key,
                )
                self._storage_healthy = True
            except asyncio.CancelledError:
                await self._release_local(lease, rollback_rate=True)
                raise
            except Exception:  # fail closed; never expose database internals
                self._storage_healthy = False
                await self._release_local(lease, rollback_rate=True)
                await self._reject(
                    scope,
                    receive,
                    send,
                    status=503,
                    detail="admission accounting unavailable",
                    retry=5,
                )
                return
            if not allowed:
                await self._release_local(lease, rollback_rate=True)
                await self._reject(
                    scope,
                    receive,
                    send,
                    status=429,
                    detail="daily expensive request limit reached",
                    retry=daily_retry,
                )
                return

        context_token = _CURRENT_BUCKET.set(bucket_hash)
        try:
            # A streaming ASGI response keeps this await alive until its final body
            # frame.  Cancellation and downstream exceptions still enter finally.
            await self.app(scope, receive, send)
        finally:
            _CURRENT_BUCKET.reset(context_token)
            await self._release_local(lease, rollback_rate=False)


__all__ = [
    "AdmissionControlMiddleware",
    "AdmissionStoreUnavailable",
    "BackgroundJobLeasePool",
    "BackgroundJobLimitExceeded",
    "configure_background_job_pool",
    "current_admission_bucket",
    "current_background_job_lease",
    "get_background_job_pool",
    "hash_api_keys",
    "hash_bearer_token",
    "is_expensive_request",
    "reset_background_job_lease",
    "set_background_job_lease",
]
