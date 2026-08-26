"""Shared bounded SQLite runtime-profile convergence helpers."""

from __future__ import annotations

import math
import sqlite3
import time

_MIN_RETRY_SECONDS = 0.005
_MAX_RETRY_SECONDS = 0.05


def _is_transient_lock(exc: sqlite3.OperationalError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and (code & 0xFF) in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }:
        return True
    rendered = str(exc).casefold()
    return "locked" in rendered or "busy" in rendered


def enable_wal_with_deadline(
    connection: sqlite3.Connection,
    *,
    max_wait_seconds: float = 5.0,
    deadline_monotonic: float | None = None,
    error_message: str = "SQLite WAL mode is unavailable",
) -> None:
    """Enable WAL under one total busy budget and restore caller policy.

    SQLite's busy timeout applies to each statement.  Retrying
    ``PRAGMA journal_mode=WAL`` without shrinking that timeout multiplies the
    caller's startup bound.  This helper projects one absolute deadline into
    every retry while leaving the connection's original timeout in force on
    return or failure.
    """

    try:
        limit = float(max_wait_seconds)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("SQLite WAL wait limit is invalid") from exc
    if not math.isfinite(limit) or not 0.0 <= limit <= 60.0:
        raise ValueError("SQLite WAL wait limit is invalid")
    timeout_row = connection.execute("PRAGMA busy_timeout").fetchone()
    if (
        timeout_row is None
        or len(timeout_row) != 1
        or type(timeout_row[0]) is not int
        or timeout_row[0] < 0
    ):
        raise sqlite3.DatabaseError("SQLite busy timeout is invalid")
    original_busy_timeout_ms = int(timeout_row[0])
    now = time.monotonic()
    total_wait_seconds = min(limit, original_busy_timeout_ms / 1000.0)
    local_deadline = now + total_wait_seconds
    if deadline_monotonic is None:
        deadline = local_deadline
    else:
        try:
            external_deadline = float(deadline_monotonic)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("SQLite WAL deadline is invalid") from exc
        if not math.isfinite(external_deadline):
            raise ValueError("SQLite WAL deadline is invalid")
        deadline = min(local_deadline, external_deadline)
    delay = _MIN_RETRY_SECONDS
    last_lock_error: sqlite3.OperationalError | None = None
    try:
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            attempt_timeout_ms = min(
                original_busy_timeout_ms,
                max(0, int(remaining * 1000)),
            )
            connection.execute(f"PRAGMA busy_timeout={attempt_timeout_ms}")
            try:
                row = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            except sqlite3.OperationalError as exc:
                if not _is_transient_lock(exc):
                    raise
                last_lock_error = exc
            else:
                if row and str(row[0]).casefold() == "wal":
                    return
            remaining = deadline - time.monotonic()
            if remaining <= 0 or attempt_timeout_ms <= 0:
                if last_lock_error is not None:
                    raise last_lock_error
                raise sqlite3.DatabaseError(error_message)
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, _MAX_RETRY_SECONDS)
    finally:
        connection.execute(f"PRAGMA busy_timeout={original_busy_timeout_ms}")


__all__ = ["enable_wal_with_deadline"]
