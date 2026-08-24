"""Append-only financial evidence for individual upstream model calls.

The legacy ``usage`` table is a dashboard aggregate and is intentionally not
used as a financial source of truth.  This module records each real provider
attempt before it starts and permits exactly one transition to a terminal
state.  Unknown token or cost values remain SQL ``NULL``.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol


_TERMINAL_STATUSES = frozenset(
    {
        "success",
        "provider_error",
        "timeout",
        "cancelled",
        "empty_stream",
        "stream_interrupted",
    }
)
_MAX_CONTEXT_CHARS = 256
_MAX_IDENTITY_CHARS = 512
_MAX_CALL_ID_CHARS = 128
_MAX_COST_BASIS_CHARS = 96
_MAX_PROVIDER_EVIDENCE_JSON_BYTES = 16 * 1024
_SQLITE_INT64_MAX = (1 << 63) - 1
_DEFAULT_MAX_DB_BYTES = 1024 * 1024 * 1024
_WAL_JOURNAL_LIMIT_BYTES = 16 * 1024 * 1024
_TERMINAL_RESERVE_BYTES = 32 * 1024
_INIT_TIMEOUT_SECONDS = 30.0
_STALE_STARTED_AFTER_SECONDS = 24 * 60 * 60
# Bounded read-only window for a concurrent cold-start peer to finish
# materializing the schema before stable drift is rejected as an authority
# violation.  Rejection polls stay strictly read-only, so a tampered database
# is refused without a single byte of mutation.
_SCHEMA_AUTHORITY_STABILIZE_SECONDS = 5.0
# Materialized schema authority for the provider-call ledger.  An in-memory
# replay of this DDL freezes the accepted sqlite_master
# (type, name, tbl_name, sql) closed set for an existing ledger database;
# any drift is rejected read-only instead of being silently repaired.
_SCHEMA_DDL = """
                CREATE TABLE IF NOT EXISTS provider_calls (
                    call_id TEXT PRIMARY KEY,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    trace_id TEXT,
                    turn_id TEXT,
                    workflow_id TEXT,
                    role TEXT,
                    attempt INTEGER NOT NULL CHECK (attempt >= 1),
                    requested_model TEXT NOT NULL,
                    actual_model TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    upstream_model TEXT NOT NULL,
                    observed_model TEXT,
                    stream INTEGER NOT NULL CHECK (stream IN (0, 1)),
                    status TEXT NOT NULL CHECK (
                        status IN (
                            'started', 'success', 'provider_error', 'timeout',
                            'cancelled', 'empty_stream', 'stream_interrupted'
                        )
                    ),
                    error_type TEXT,
                    error_message TEXT,
                    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
                    prompt_tokens INTEGER CHECK (prompt_tokens IS NULL OR prompt_tokens >= 0),
                    completion_tokens INTEGER CHECK (completion_tokens IS NULL OR completion_tokens >= 0),
                    total_tokens INTEGER CHECK (total_tokens IS NULL OR total_tokens >= 0),
                    cached_tokens INTEGER CHECK (cached_tokens IS NULL OR cached_tokens >= 0),
                    cache_read_tokens INTEGER CHECK (cache_read_tokens IS NULL OR cache_read_tokens >= 0),
                    cache_creation_tokens INTEGER CHECK (cache_creation_tokens IS NULL OR cache_creation_tokens >= 0),
                    cost_microusd INTEGER CHECK (cost_microusd IS NULL OR cost_microusd >= 0),
                    cost_basis TEXT,
                    cost_attribution_basis TEXT,
                    provider_model_usage_json TEXT,
                    usage_validation_error TEXT,
                    billing_dimensions_json TEXT,
                    billing_dimensions_schema TEXT,
                    terminal_reserve BLOB,
                    CHECK (
                        (status = 'started' AND finished_at IS NULL AND latency_ms IS NULL)
                        OR
                        (status <> 'started' AND finished_at IS NOT NULL AND latency_ms IS NOT NULL)
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_provider_calls_trace
                    ON provider_calls(trace_id, started_at);
                CREATE INDEX IF NOT EXISTS idx_provider_calls_turn
                    ON provider_calls(turn_id, started_at);
                CREATE INDEX IF NOT EXISTS idx_provider_calls_started
                    ON provider_calls(started_at);
                CREATE TABLE IF NOT EXISTS provider_ledger_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS commercial_budget_entries (
                    entry_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    kind TEXT NOT NULL CHECK (
                        kind IN ('funding', 'hold', 'capture', 'release')
                    ),
                    call_id TEXT,
                    operation_id TEXT NOT NULL,
                    quote_id TEXT,
                    amount_microusd INTEGER NOT NULL CHECK (amount_microusd > 0),
                    currency TEXT NOT NULL CHECK (currency = 'USD'),
                    evidence_sha256 TEXT NOT NULL CHECK (
                        length(evidence_sha256) = 71
                        AND substr(evidence_sha256, 1, 7) = 'sha256:'
                        AND substr(evidence_sha256, 8) NOT GLOB '*[^0-9a-f]*'
                    ),
                    CHECK (
                        (kind = 'funding' AND call_id IS NULL AND quote_id IS NULL)
                        OR
                        (kind <> 'funding' AND call_id IS NOT NULL AND quote_id IS NOT NULL)
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_commercial_budget_entries_call
                    ON commercial_budget_entries(call_id, created_at);
                CREATE TABLE IF NOT EXISTS commercial_budget_reservations (
                    call_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    quote_id TEXT NOT NULL,
                    quote_fingerprint TEXT NOT NULL CHECK (
                        length(quote_fingerprint) = 71
                        AND substr(quote_fingerprint, 1, 7) = 'sha256:'
                        AND substr(quote_fingerprint, 8) NOT GLOB '*[^0-9a-f]*'
                    ),
                    reserved_microusd INTEGER NOT NULL CHECK (reserved_microusd > 0),
                    capture_microusd INTEGER NOT NULL CHECK (
                        capture_microusd > 0 AND capture_microusd <= reserved_microusd
                    ),
                    currency TEXT NOT NULL CHECK (currency = 'USD'),
                    state TEXT NOT NULL CHECK (
                        state IN ('reserved', 'captured', 'released', 'review_required')
                    ),
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL CHECK (updated_at >= created_at)
                );
                CREATE INDEX IF NOT EXISTS idx_commercial_budget_reservations_state
                    ON commercial_budget_reservations(state, created_at);
                CREATE TRIGGER IF NOT EXISTS commercial_budget_entries_no_update
                    BEFORE UPDATE ON commercial_budget_entries
                    BEGIN
                        SELECT RAISE(ABORT, 'commercial budget entries are append-only');
                    END;
                CREATE TRIGGER IF NOT EXISTS commercial_budget_entries_no_delete
                    BEFORE DELETE ON commercial_budget_entries
                    BEGIN
                        SELECT RAISE(ABORT, 'commercial budget entries are append-only');
                    END;
                CREATE TRIGGER IF NOT EXISTS commercial_budget_reservations_no_delete
                    BEFORE DELETE ON commercial_budget_reservations
                    BEGIN
                        SELECT RAISE(ABORT, 'commercial budget reservations cannot be deleted');
                    END;
                CREATE TRIGGER IF NOT EXISTS commercial_budget_reservations_identity_frozen
                    BEFORE UPDATE ON commercial_budget_reservations
                    WHEN NEW.call_id IS NOT OLD.call_id
                      OR NEW.operation_id IS NOT OLD.operation_id
                      OR NEW.quote_id IS NOT OLD.quote_id
                      OR NEW.quote_fingerprint IS NOT OLD.quote_fingerprint
                      OR NEW.reserved_microusd IS NOT OLD.reserved_microusd
                      OR NEW.capture_microusd IS NOT OLD.capture_microusd
                      OR NEW.currency IS NOT OLD.currency
                      OR NEW.created_at IS NOT OLD.created_at
                    BEGIN
                        SELECT RAISE(ABORT, 'commercial budget reservation identity is frozen');
                    END;
                CREATE TRIGGER IF NOT EXISTS commercial_budget_reservations_transition
                    BEFORE UPDATE ON commercial_budget_reservations
                    WHEN OLD.state <> 'reserved'
                      OR NEW.state NOT IN ('captured', 'released', 'review_required')
                      OR NEW.updated_at < OLD.updated_at
                    BEGIN
                        SELECT RAISE(ABORT, 'invalid commercial budget transition');
                    END;
                CREATE TRIGGER IF NOT EXISTS provider_calls_no_delete
                    BEFORE DELETE ON provider_calls
                    BEGIN
                        SELECT RAISE(ABORT, 'provider call ledger is append-only');
                    END;
                CREATE TRIGGER IF NOT EXISTS provider_calls_terminal_immutable
                    BEFORE UPDATE ON provider_calls
                    WHEN OLD.status <> 'started'
                    BEGIN
                        SELECT RAISE(ABORT, 'terminal provider call is immutable');
                    END;
                CREATE TRIGGER IF NOT EXISTS provider_calls_identity_frozen
                    BEFORE UPDATE ON provider_calls
                    WHEN NEW.call_id IS NOT OLD.call_id
                      OR NEW.started_at IS NOT OLD.started_at
                      OR NEW.trace_id IS NOT OLD.trace_id
                      OR NEW.turn_id IS NOT OLD.turn_id
                      OR NEW.workflow_id IS NOT OLD.workflow_id
                      OR NEW.role IS NOT OLD.role
                      OR NEW.attempt IS NOT OLD.attempt
                      OR NEW.requested_model IS NOT OLD.requested_model
                      OR NEW.actual_model IS NOT OLD.actual_model
                      OR NEW.provider IS NOT OLD.provider
                      OR NEW.upstream_model IS NOT OLD.upstream_model
                      OR NEW.stream IS NOT OLD.stream
                    BEGIN
                        SELECT RAISE(ABORT, 'provider call identity is frozen');
                    END;
                CREATE TRIGGER IF NOT EXISTS provider_calls_started_once
                    BEFORE UPDATE ON provider_calls
                    WHEN OLD.status = 'started' AND NEW.status = 'started'
                    BEGIN
                        SELECT RAISE(ABORT, 'provider call must become terminal');
                    END;
                CREATE TRIGGER IF NOT EXISTS provider_calls_error_message_insert_redacted
                    BEFORE INSERT ON provider_calls
                    WHEN NEW.error_message IS NOT NULL AND (
                        length(NEW.error_message) <> 71
                        OR substr(NEW.error_message, 1, 7) <> 'sha256:'
                        OR substr(NEW.error_message, 8) GLOB '*[^0-9a-f]*'
                    )
                    BEGIN
                        SELECT RAISE(ABORT, 'provider error text must be fingerprinted');
                    END;
                CREATE TRIGGER IF NOT EXISTS provider_calls_error_message_update_redacted
                    BEFORE UPDATE OF error_message ON provider_calls
                    WHEN NEW.error_message IS NOT NULL AND (
                        length(NEW.error_message) <> 71
                        OR substr(NEW.error_message, 1, 7) <> 'sha256:'
                        OR substr(NEW.error_message, 8) GLOB '*[^0-9a-f]*'
                    )
                    BEGIN
                        SELECT RAISE(ABORT, 'provider error text must be fingerprinted');
                    END;
                """


@functools.lru_cache(maxsize=1)
def _expected_schema_authority() -> dict[tuple[str, str, str], str | None]:
    """Freeze the exact sqlite_master authority by replaying the shipped DDL."""

    replay = sqlite3.connect(":memory:")
    try:
        replay.executescript(_SCHEMA_DDL)
        return {
            (str(row[0]), str(row[1]), str(row[2])): (
                None if row[3] is None else str(row[3])
            )
            for row in replay.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master"
            )
        }
    finally:
        replay.close()
_VERSIONED_ESTIMATE_RE = re.compile(r"^estimated_[a-z0-9][a-z0-9_.-]{0,79}$")
_ERROR_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXACT_COST_BASES = frozenset(
    {"provider_reported", "invoice_reconciled", "subscription_unallocated"}
)
_COST_ATTRIBUTION_BASES = frozenset(
    {
        "cli_invocation_total",
        "cli_invocation_total_includes_provider_internal_models",
    }
)
_BILLING_DIMENSIONS_SCHEMA = "media_billing_dimensions_v1"
_BILLING_DIMENSION_KEYS = frozenset(
    {
        "operation",
        "n",
        "size",
        "quality",
        "duration_seconds",
        "seconds",
        "resolution",
        "fps",
        "frame_count",
        "service_tier",
    }
)
_PROVEN_PRE_SUBMISSION_SQL = """
(
    (status = 'provider_error' AND COALESCE(error_type, '') IN (
        'ConnectError', 'ConnectTimeout', 'PoolTimeout'
    ))
    OR
    (status = 'cancelled' AND COALESCE(error_type, '') =
        'cancelled_before_provider_invocation')
)
""".strip()
_MAX_RECOVERY_ATTEMPTS = 256
_COMMERCIAL_BUDGET_CURRENCY = "USD"


class ProviderCallLedgerUnavailable(RuntimeError):
    """Raised when required accounting cannot durably record an attempt."""


class CommercialBudgetExceeded(ProviderCallLedgerUnavailable):
    """Raised before provider invocation when the trusted quote cannot be held."""


class CommercialBudgetAlreadyClaimed(ProviderCallLedgerUnavailable):
    """Raised when a stable commercial call id already owns an execution claim."""


@dataclass(frozen=True, slots=True)
class CommercialBudgetAuthorization:
    """Trusted, versioned fixed-price authority for one commercial operation.

    This object is an in-process authority.  It is deliberately absent from the
    public request schema, and its integer amounts are policy inputs rather than
    provider-reported or live prices.
    """

    operation_id: str
    quote_id: str
    reserve_microusd: int
    capture_microusd: int
    currency: str = _COMMERCIAL_BUDGET_CURRENCY

    def normalized(self) -> tuple[str, str, int, int, str]:
        operation_id = _required_text(
            self.operation_id, "commercial operation_id", max_chars=_MAX_CALL_ID_CHARS
        )
        quote_id = _required_text(
            self.quote_id, "commercial quote_id", max_chars=_MAX_CALL_ID_CHARS
        )
        if self.currency != _COMMERCIAL_BUDGET_CURRENCY:
            raise ProviderCallLedgerUnavailable(
                "commercial budget first slice supports USD only"
            )
        reserve = _optional_nonnegative_int(self.reserve_microusd)
        capture = _optional_nonnegative_int(self.capture_microusd)
        if reserve is None or reserve <= 0:
            raise ProviderCallLedgerUnavailable(
                "commercial reserve_microusd must be a positive integer"
            )
        if capture is None or capture <= 0 or capture > reserve:
            raise ProviderCallLedgerUnavailable(
                "commercial capture_microusd must be positive and no greater than reserve"
            )
        return operation_id, quote_id, reserve, capture, self.currency

    def call_id_for_attempt(self, attempt: int) -> str:
        operation_id, _quote_id, _reserve, _capture, _currency = self.normalized()
        try:
            attempt_number = int(attempt)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ProviderCallLedgerUnavailable(
                "commercial attempt must be an integer"
            ) from exc
        if not 1 <= attempt_number <= 2_147_483_647:
            raise ProviderCallLedgerUnavailable(
                "commercial attempt must be between 1 and 2147483647"
            )
        canonical = json.dumps(
            {
                "operation_id": operation_id,
                "attempt": attempt_number,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hashlib.sha256(b"nachuan-commercial-call-v1\0" + canonical).hexdigest()

    def quote_fingerprint(self) -> str:
        operation_id, quote_id, reserve, capture, currency = self.normalized()
        canonical = json.dumps(
            {
                "capture_microusd": capture,
                "currency": currency,
                "operation_id": operation_id,
                "quote_id": quote_id,
                "reserve_microusd": reserve,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return "sha256:" + hashlib.sha256(
            b"nachuan-commercial-quote-v1\0" + canonical
        ).hexdigest()


class _ExactIntegerSum:
    """SQLite aggregate returning decimal text so totals cannot overflow int64."""

    def __init__(self) -> None:
        self.total = 0

    def step(self, value: Any) -> None:
        if value is not None:
            self.total += int(value)

    def finalize(self) -> str:
        return str(self.total)


@dataclass(frozen=True, slots=True)
class ProviderCallContext:
    trace_id: str | None = None
    turn_id: str | None = None
    workflow_id: str | None = None
    role: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderRouteIdentity:
    requested_model: str
    actual_model: str
    provider: str
    upstream_model: str


class ProviderCallAttemptProtocol(Protocol):
    call_id: str

    def finish(
        self,
        *,
        status: str,
        observed_model: str | None = None,
        usage: Mapping[str, Any] | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> bool: ...


class ProviderCallLedgerProtocol(Protocol):
    required: bool

    def start_attempt(
        self,
        *,
        identity: ProviderRouteIdentity,
        context: ProviderCallContext,
        attempt: int,
        stream: bool,
        call_id: str | None = None,
        commercial_budget: CommercialBudgetAuthorization | None = None,
    ) -> ProviderCallAttemptProtocol: ...

    def financial_summary(self, *, period: str = "month") -> dict[str, Any]: ...

    def operational_snapshot(self) -> dict[str, Any]: ...

    def turn_requires_operator_recovery(
        self, turn_id: str, workflow_id: str
    ) -> bool: ...

    def recovery_snapshot(self, turn_id: str) -> dict[str, Any]: ...


def _optional_text(value: Any, *, max_chars: int | None = None) -> str | None:
    try:
        text = "" if value is None else str(value).strip()
    except Exception:  # noqa: BLE001 -- provider metadata must not strand a started row
        return None
    if max_chars is not None and len(text) > max_chars:
        return None
    return text or None


def _truncated_optional_text(value: Any, *, max_chars: int) -> str | None:
    try:
        text = "" if value is None else str(value).strip()
    except Exception:  # noqa: BLE001 -- error formatting is untrusted provider data
        return None
    return text[:max_chars] or None


def _error_message_fingerprint(value: Any) -> str | None:
    """Persist correlation evidence without retaining an upstream error body.

    Provider errors are untrusted and can echo prompts, credentials or remote
    task identifiers.  ``error_type`` and HTTP-derived status categories carry
    the operational classification; this one-way digest only lets operators
    correlate repeated failures without turning the financial ledger into a
    second secret store.
    """

    try:
        text = "" if value is None else str(value).strip()
    except Exception:  # noqa: BLE001 -- provider error formatting is untrusted
        return None
    if not text:
        return None
    if _ERROR_FINGERPRINT_RE.fullmatch(text):
        return text
    return f"sha256:{hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()}"


def _required_text(value: Any, label: str, *, max_chars: int) -> str:
    text = _optional_text(value, max_chars=max_chars)
    if text is None:
        raise ProviderCallLedgerUnavailable(
            f"provider-call {label} must be non-empty and at most {max_chars} characters"
        )
    return text


def _optional_nonnegative_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, Decimal):
        if not value.is_finite() or value != value.to_integral_value():
            return None
        number = int(value)
    elif isinstance(value, float):
        if not value.is_integer() or value < 0:
            return None
        number = int(value)
    elif isinstance(value, str):
        raw = value.strip()
        if len(raw) > 32 or re.fullmatch(r"[0-9]+", raw) is None:
            return None
        number = int(raw)
    else:
        return None
    return number if 0 <= number <= _SQLITE_INT64_MAX else None


def _cost_microusd(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        raw = str(value)
        if len(raw) > 128:
            return None
        amount = Decimal(raw)
    except (InvalidOperation, TypeError, ValueError, OverflowError):
        return None
    if not amount.is_finite() or amount < 0:
        return None
    try:
        microusd = int(
            (amount * Decimal(1_000_000)).quantize(
                Decimal("1"), rounding=ROUND_HALF_UP
            )
        )
    except (InvalidOperation, OverflowError, ValueError):
        return None
    return microusd if 0 <= microusd <= _SQLITE_INT64_MAX else None


def _cost_basis(value: Any) -> str | None:
    basis = _optional_text(value, max_chars=_MAX_COST_BASIS_CHARS)
    if basis is None:
        return None
    basis = basis.casefold()
    if basis in _EXACT_COST_BASES or _VERSIONED_ESTIMATE_RE.fullmatch(basis):
        return basis
    return None


def _provider_payload_cost_basis(value: Any) -> str | None:
    """Accept only response-level provenance a provider adapter can assert.

    Invoice reconciliation and versioned local estimates require a separate
    privileged local transaction; an upstream JSON response cannot grant
    itself either authority.
    """

    basis = _cost_basis(value)
    return basis if basis in {"provider_reported", "subscription_unallocated"} else None


def _provider_model_usage_json(value: Any) -> str | None:
    """Serialize only bounded per-model numeric evidence; never prompt text."""

    if not isinstance(value, Mapping) or len(value) > 16:
        return None
    allowed = {
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "cost_usd",
        "cost_microusd",
    }
    normalized: dict[str, dict[str, int | str]] = {}
    for raw_model, raw_usage in sorted(value.items(), key=lambda item: str(item[0])):
        model = _optional_text(raw_model, max_chars=160)
        if model is None or not isinstance(raw_usage, Mapping):
            continue
        row: dict[str, int | str] = {}
        for field in sorted(allowed - {"cost_usd"}):
            if field in raw_usage:
                parsed = _optional_nonnegative_int(raw_usage.get(field))
                if parsed is not None:
                    row[field] = parsed
        if "cost_usd" in raw_usage:
            parsed_cost = _cost_microusd(raw_usage.get("cost_usd"))
            if parsed_cost is not None:
                # Decimal text avoids a second binary-float round trip when the
                # evidence is inspected or reconciled later.
                row["cost_microusd"] = parsed_cost
        if row:
            normalized[model] = row
    if not normalized:
        return None
    encoded = json.dumps(
        normalized,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return encoded if len(encoded.encode("utf-8")) <= _MAX_PROVIDER_EVIDENCE_JSON_BYTES else None


def _normalized_provider_model_usage_json(value: Any) -> str | None:
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="ignore")) > _MAX_PROVIDER_EVIDENCE_JSON_BYTES:
            return None
        try:
            value = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    return _provider_model_usage_json(value)


def _billing_dimensions_json(value: Any) -> str | None:
    """Freeze only non-sensitive pricing dimensions, never prompts or task IDs."""

    if isinstance(value, str):
        if len(value.encode("utf-8", errors="ignore")) > 4096:
            return None
        try:
            value = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    if not isinstance(value, Mapping) or len(value) > len(_BILLING_DIMENSION_KEYS):
        return None
    normalized: dict[str, int | str] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if key not in _BILLING_DIMENSION_KEYS:
            continue
        integer = _optional_nonnegative_int(raw_value)
        if integer is not None:
            normalized[key] = integer
            continue
        text = _optional_text(raw_value, max_chars=64)
        if text is not None and re.fullmatch(r"[A-Za-z0-9_.:/+ -]+", text):
            normalized[key] = text
    if not normalized:
        return None
    encoded = json.dumps(
        normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return encoded if len(encoded.encode("utf-8")) <= 4096 else None


def financial_usage_from_payload(payload: Any) -> dict[str, Any]:
    """Extract only provider-reported usage; absence never becomes zero."""

    unknown = {
        "prompt_tokens": None,
        "completion_tokens": None,
        "total_tokens": None,
        "cached_tokens": None,
        "cache_read_tokens": None,
        "cache_creation_tokens": None,
        "cost_microusd": None,
        "cost_basis": None,
        "cost_attribution_basis": None,
        "provider_model_usage_json": None,
        "usage_validation_error": None,
    }
    try:
        usage = payload.get("usage") if isinstance(payload, Mapping) else None
        if not isinstance(usage, Mapping):
            usage = {}
        prompt = _optional_nonnegative_int(
            usage.get("prompt_tokens", usage.get("input_tokens"))
        )
        completion = _optional_nonnegative_int(
            usage.get("completion_tokens", usage.get("output_tokens"))
        )
        total = _optional_nonnegative_int(usage.get("total_tokens"))
        validation_error = None
        if total is not None and prompt is not None and completion is not None:
            combined = prompt + completion
            if combined > _SQLITE_INT64_MAX or total != combined:
                total = None
                validation_error = "total_tokens_mismatch"
        elif total is None and prompt is not None and completion is not None:
            combined = prompt + completion
            total = combined if combined <= _SQLITE_INT64_MAX else None
        details = usage.get("prompt_tokens_details")
        cached = _optional_nonnegative_int(usage.get("cached_tokens"))
        if cached is None and isinstance(details, Mapping):
            cached = _optional_nonnegative_int(details.get("cached_tokens"))
        cache_read = _optional_nonnegative_int(usage.get("cache_read_tokens"))
        if cache_read is None:
            cache_read = cached
        cache_creation = _optional_nonnegative_int(usage.get("cache_creation_tokens"))
        raw_basis = usage.get(
            "cost_basis",
            payload.get("cost_basis") if isinstance(payload, Mapping) else None,
        )
        attribution_basis = _optional_text(
            usage.get("cost_attribution_basis"), max_chars=_MAX_COST_BASIS_CHARS
        )
        if attribution_basis not in _COST_ATTRIBUTION_BASES:
            attribution_basis = None
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": total,
            "cached_tokens": cached,
            "cache_read_tokens": cache_read,
            "cache_creation_tokens": cache_creation,
            "cost_microusd": _cost_microusd(
                usage.get(
                    "cost_usd",
                    payload.get("cost_usd") if isinstance(payload, Mapping) else None,
                )
            ),
            "cost_basis": _provider_payload_cost_basis(raw_basis),
            "cost_attribution_basis": attribution_basis,
            "provider_model_usage_json": _provider_model_usage_json(
                usage.get("provider_model_usage")
            ),
            "usage_validation_error": validation_error,
        }
    except Exception:  # noqa: BLE001 -- malformed usage becomes explicitly unknown
        return unknown


def observed_model_from_payload(payload: Any) -> str | None:
    try:
        if not isinstance(payload, Mapping):
            return None
        return _optional_text(payload.get("model"), max_chars=_MAX_IDENTITY_CHARS)
    except Exception:  # noqa: BLE001 -- malformed provider metadata is non-authoritative
        return None


def _commercial_entry_id(kind: str, stable_id: str) -> str:
    return hashlib.sha256(
        b"nachuan-commercial-entry-v1\0"
        + kind.encode("ascii")
        + b"\0"
        + stable_id.encode("utf-8")
    ).hexdigest()


def _commercial_entry_evidence(
    *, kind: str, stable_id: str, amount_microusd: int, quote_fingerprint: str
) -> str:
    canonical = json.dumps(
        {
            "amount_microusd": amount_microusd,
            "kind": kind,
            "quote_fingerprint": quote_fingerprint,
            "stable_id": stable_id,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(
        b"nachuan-commercial-entry-evidence-v1\0" + canonical
    ).hexdigest()


def _commercial_failure_proven_pre_submission(status: str, error_type: str | None) -> bool:
    return bool(
        (status == "provider_error" and error_type in {"ConnectError", "ConnectTimeout", "PoolTimeout"})
        or (
            status == "cancelled"
            and error_type == "cancelled_before_provider_invocation"
        )
    )


class _NoopAttempt:
    def __init__(self, call_id: str | None = None) -> None:
        self.call_id = call_id or uuid.uuid4().hex

    def finish(self, **_fields: Any) -> bool:
        return False


class NoopProviderCallLedger:
    required = False
    closed = False

    def start_attempt(
        self,
        *,
        identity: ProviderRouteIdentity,
        context: ProviderCallContext,
        attempt: int,
        stream: bool,
        call_id: str | None = None,
        commercial_budget: CommercialBudgetAuthorization | None = None,
    ) -> _NoopAttempt:
        del identity, context, attempt, stream
        if commercial_budget is not None:
            raise ProviderCallLedgerUnavailable(
                "commercial budget requires a durable provider-call ledger"
            )
        return _NoopAttempt(call_id)

    def financial_summary(self, *, period: str = "month") -> dict[str, Any]:
        if period not in {"day", "month", "all"}:
            raise ValueError("financial summary period must be day, month, or all")
        return {
            "financial_source": False,
            "reason": "provider_call_ledger_disabled",
            "ledger_table": "provider_calls",
            "currency": "USD",
            "period": period,
            "models": [],
            "total_calls": 0,
            "terminal_calls": 0,
            "count_basis": "gateway_provider_attempt",
            "open_unresolved_calls": 0,
            "in_flight_calls": 0,
            "in_flight_semantics": "open_unresolved_not_proven_live",
            "outcome_unknown_calls": 0,
            "unknown_token_calls": 0,
            "unknown_cost_calls": 0,
            "known_cost_usd": 0.0,
            "known_cost_microusd": "0",
            "provider_reported_cost_usd": 0.0,
            "invoice_reconciled_cost_usd": 0.0,
            "billed_cost_usd": 0.0,
            "billed_cost_complete": False,
            "estimated_cost_usd": 0.0,
            "unclassified_cost_usd": 0.0,
            "provider_reported_cost_calls": 0,
            "invoice_reconciled_cost_calls": 0,
            "estimated_cost_calls": 0,
            "unverified_cost_calls": 0,
            "provider_internal_breakdown_calls": 0,
            "total_cost_usd": None,
            "cost_basis": "no_cost_evidence",
            "database_bytes": 0,
            "wal_bytes": 0,
            "storage_bytes": 0,
            "disk_free_bytes": 0,
            "max_database_bytes": 0,
            "capacity_ratio": 0.0,
            "capacity_status": "critical",
        }

    def operational_snapshot(self) -> dict[str, Any]:
        return {
            "required": False,
            "ready": False,
            "status": "disabled",
            "capacity_status": "disabled",
            "database_bytes": 0,
            "wal_bytes": 0,
            "max_database_bytes": 0,
            "disk_free_bytes": 0,
            "last_write_error_type": None,
            "last_write_error_at": None,
        }

    def turn_requires_operator_recovery(self, turn_id: str, workflow_id: str) -> bool:
        del turn_id, workflow_id
        return False

    def recovery_snapshot(self, turn_id: str) -> dict[str, Any]:
        if (
            not isinstance(turn_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", turn_id) is None
        ):
            raise ProviderCallLedgerUnavailable(
                "provider-call durable turn_id must be a lowercase SHA-256 digest"
            )
        return {"found": False}


class ProviderCallAttempt:
    def __init__(
        self,
        ledger: ProviderCallLedger,
        call_id: str,
        started_monotonic: float,
    ) -> None:
        self._ledger = ledger
        self.call_id = call_id
        self._started_monotonic = started_monotonic

    def finish(
        self,
        *,
        status: str,
        observed_model: str | None = None,
        usage: Mapping[str, Any] | None = None,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> bool:
        return self._ledger._finish_attempt(
            self.call_id,
            started_monotonic=self._started_monotonic,
            status=status,
            observed_model=observed_model,
            usage=usage,
            error_type=error_type,
            error_message=error_message,
        )


class ProviderCallLedger:
    """SQLite provider-attempt ledger with immutable terminal records."""

    required: bool

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._conn is None

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        required: bool = False,
        commercial_budget_required: bool = False,
        max_db_bytes: int = _DEFAULT_MAX_DB_BYTES,
        stale_started_after_seconds: float = _STALE_STARTED_AFTER_SECONDS,
    ) -> None:
        self.required = bool(required)
        self.commercial_budget_required = bool(commercial_budget_required)
        if self.commercial_budget_required and not self.required:
            raise ProviderCallLedgerUnavailable(
                "commercial budget requires provider-call ledger required mode"
            )
        self.path = Path(os.path.abspath(os.fspath(db_path)))
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._max_db_bytes = int(max_db_bytes)
        self._stale_started_after_seconds = float(stale_started_after_seconds)
        self._local_revision = 0
        self._summary_cache_key: tuple[Any, ...] | None = None
        self._summary_cache: dict[str, Any] | None = None
        self._last_write_error_type: str | None = None
        self._last_write_error_at: float | None = None
        if self._max_db_bytes < 1024 * 1024:
            raise ProviderCallLedgerUnavailable(
                "provider-call ledger max_db_bytes must be at least 1 MiB"
            )
        if not (60.0 <= self._stale_started_after_seconds <= 30 * 24 * 60 * 60):
            raise ProviderCallLedgerUnavailable(
                "provider-call stale-start threshold must be between 60 seconds and 30 days"
            )
        try:
            self._assert_database_path()
            self._reject_unrelated_existing_database()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_database_path()
            self._open_with_retry()
        except Exception as exc:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            if isinstance(exc, ProviderCallLedgerUnavailable):
                raise
            raise ProviderCallLedgerUnavailable(
                f"provider-call ledger initialization failed: {type(exc).__name__}"
            ) from exc

    def _reject_unrelated_existing_database(self) -> None:
        """Classify an existing file read-only before any persistent PRAGMA/DDL.

        A database that already carries provider-ledger objects must match the
        exact materialized schema authority — application identity, closed
        sqlite_master object set and per-object SQL — or it is rejected as
        schema-authority drift instead of being silently repaired.  A foreign
        database is adopted only when it carries no identity, no schema
        objects besides plain tables and no rows; anything else stays
        byte-exact untouched.  Rejection must never mutate the rejected
        database: while WAL/SHM sidecars exist a direct read-only handle
        would let SQLite coordinate and rewrite SHM bytes, so the authority
        is verified on a private byte copy of the main database and its WAL.
        """

        if not self.path.exists() or self.path.stat().st_size == 0:
            return
        deadline = time.monotonic() + _SCHEMA_AUTHORITY_STABILIZE_SECONDS
        delay = 0.025
        while True:
            verdict = self._classify_existing_database()
            if verdict != "converging":
                break
            if time.monotonic() >= deadline:
                raise sqlite3.OperationalError(
                    "provider-call ledger existing database did not stabilize"
                )
            time.sleep(delay)
            delay = min(0.25, delay * 2)
        if verdict == "accept":
            return
        if verdict == "unrecognized":
            raise ProviderCallLedgerUnavailable(
                "provider-call ledger unrecognized database"
            )
        if verdict == "identity_drift":
            raise ProviderCallLedgerUnavailable(
                "provider-call ledger schema authority mismatch: "
                "application_id/user_version drift"
            )
        raise ProviderCallLedgerUnavailable(
            "provider-call ledger schema authority mismatch: "
            "materialized sqlite_master drift"
        )

    def _classify_existing_database(self) -> str:
        """One read-only classification poll for the existing database file."""

        presence = {
            suffix: Path(f"{self.path}{suffix}").is_file()
            for suffix in ("-wal", "-shm", "-journal")
        }
        if presence["-journal"]:
            # A hot rollback journal means another writer is mid-transaction;
            # recovering it would mutate the file, so wait for quiescence.
            return "converging"
        if presence["-wal"] or presence["-shm"]:
            return self._classify_copied_database()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self.path.as_uri()}?mode=ro",
                uri=True,
                check_same_thread=False,
                timeout=5.0,
            )
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            return self._classify_database_objects(connection)
        finally:
            if connection is not None:
                connection.close()

    def _classify_copied_database(self) -> str:
        """Classify a private byte copy so WAL/SHM sidecars stay byte-exact."""

        temp_dir = Path(tempfile.mkdtemp(prefix="nachuan-ledger-preflight-"))
        try:
            copied = temp_dir / self.path.name
            shutil.copyfile(self.path, copied)
            wal_path = Path(f"{self.path}-wal")
            if wal_path.is_file():
                shutil.copyfile(wal_path, Path(f"{copied}-wal"))
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(str(copied), timeout=5.0)
                connection.execute("PRAGMA trusted_schema=OFF")
                return self._classify_database_objects(connection)
            except sqlite3.DatabaseError as exc:
                rendered = str(exc).casefold()
                if "not a database" in rendered or "locked" in rendered or "busy" in rendered:
                    # Torn copy taken while a peer writer was checkpointing;
                    # SQLite WAL recovery already truncates torn frames, so a
                    # clean prefix is classified normally and only an unreadable
                    # main image asks for a later poll.
                    return "converging"
                raise
            finally:
                if connection is not None:
                    connection.close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _classify_database_objects(self, connection: sqlite3.Connection) -> str:
        """Map application identity plus exact sqlite_master state to a verdict."""

        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        objects = {
            (str(row[0]), str(row[1]), str(row[2])): (
                None if row[3] is None else str(row[3])
            )
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master"
            )
        }
        expected = _expected_schema_authority()
        ledger_identities = {(kind, name) for kind, name, _tbl in expected}
        if not any(
            (kind, name) in ledger_identities for kind, name, _tbl in objects
        ):
            # Foreign database: only an identity-free, row-free plain-table
            # file may be adopted; any carried data or object stays untouched.
            if application_id != 0 or user_version != 0:
                return "unrecognized"
            for kind, name, _tbl_name in objects:
                if name.startswith("sqlite_"):
                    continue
                if kind != "table":
                    return "unrecognized"
                has_rows = bool(
                    connection.execute(
                        'SELECT EXISTS(SELECT 1 FROM "'
                        + name.replace('"', '""')
                        + '" LIMIT 1)'
                    ).fetchone()[0]
                )
                if has_rows:
                    return "unrecognized"
            return "accept"
        if application_id != 0 or user_version != 0:
            return "identity_drift"
        if objects == expected:
            return "accept"
        if set(objects) < set(expected) and all(
            sql == expected[identity] for identity, sql in objects.items()
        ):
            # An exact prefix of the authority is either a concurrent
            # cold-start peer still materializing the schema or a genuinely
            # pre-migration ledger; initialization converges both.  Once the
            # fingerprint migration marker is complete, however, a missing
            # materialized object is stable drift, never a legacy shape, and
            # must be rejected instead of silently repaired.
            meta_identity = ("table", "provider_ledger_meta", "provider_ledger_meta")
            migration_complete = meta_identity in objects and connection.execute(
                "SELECT value FROM provider_ledger_meta WHERE key = ?",
                ("error_message_fingerprint_v1",),
            ).fetchone() == ("complete",)
            if migration_complete:
                return "schema_drift"
            return "accept"
        return "schema_drift"

    @staticmethod
    def _is_reparse_or_symlink(info: os.stat_result) -> bool:
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return stat.S_ISLNK(info.st_mode) or bool(
            int(getattr(info, "st_file_attributes", 0)) & reparse_flag
        )

    def _assert_database_path(self) -> None:
        """Reject symlink/junction indirection for the DB and its sidecars."""

        components = [self.path, *self.path.parents]
        for component in reversed(components):
            try:
                info = os.lstat(component)
            except FileNotFoundError:
                continue
            if self._is_reparse_or_symlink(info):
                raise OSError(f"provider-call ledger path contains a reparse point: {component}")
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
            if self._is_reparse_or_symlink(info):
                raise OSError("provider-call ledger files must not be reparse points")
            if candidate == self.path and not stat.S_ISREG(info.st_mode):
                raise OSError("provider-call ledger path is not a regular file")

    def _open_with_retry(self) -> None:
        """Serialize concurrent cold starts through SQLite's bounded busy retry."""

        deadline = time.monotonic() + _INIT_TIMEOUT_SECONDS
        delay = 0.01
        while True:
            connection: sqlite3.Connection | None = None
            try:
                self._assert_database_path()
                connection = sqlite3.connect(
                    str(self.path),
                    check_same_thread=False,
                    timeout=5.0,
                )
                connection.create_aggregate("EXACT_INT_SUM", 1, _ExactIntegerSum)
                connection.create_function(
                    "ERROR_MESSAGE_FINGERPRINT",
                    1,
                    _error_message_fingerprint,
                    deterministic=True,
                )
                self._conn = connection
                connection.execute("PRAGMA busy_timeout=5000")
                self._assert_database_path()
                self._init_schema()
                return
            except sqlite3.OperationalError as exc:
                if connection is not None:
                    connection.close()
                self._conn = None
                locked = "locked" in str(exc).casefold() or "busy" in str(exc).casefold()
                if not locked or time.monotonic() >= deadline:
                    raise
                time.sleep(delay)
                delay = min(0.25, delay * 2)
            except BaseException:
                if connection is not None:
                    connection.close()
                self._conn = None
                raise

    def _open_read_connection(self) -> sqlite3.Connection:
        """Open a short-lived read-only snapshot without holding the write lock.

        WAL readers can aggregate a large ledger concurrently with provider
        start/finalize commits.  Opening happens while the ledger lock protects
        close/path validation; the expensive query runs on the returned
        connection after that lock is released.
        """

        connection: sqlite3.Connection | None = None
        with self._lock:
            if self._conn is None:
                raise ProviderCallLedgerUnavailable("provider-call ledger is closed")
            try:
                self._assert_database_path()
                connection = sqlite3.connect(
                    f"{self.path.as_uri()}?mode=ro",
                    uri=True,
                    check_same_thread=False,
                    timeout=5.0,
                )
                connection.create_aggregate("EXACT_INT_SUM", 1, _ExactIntegerSum)
                connection.execute("PRAGMA busy_timeout=5000")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA query_only=ON")
                self._assert_database_path()
                return connection
            except BaseException:
                if connection is not None:
                    connection.close()
                raise

    def _init_schema(self) -> None:
        with self._lock:
            assert self._conn is not None
            mode = str(self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]).casefold()
            if mode != "wal":
                raise sqlite3.DatabaseError("provider-call ledger requires SQLite WAL mode")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA trusted_schema=OFF")
            self._conn.execute("PRAGMA secure_delete=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute(f"PRAGMA journal_size_limit={_WAL_JOURNAL_LIMIT_BYTES}")
            self._conn.execute("PRAGMA wal_autocheckpoint=1000")
            page_size = int(self._conn.execute("PRAGMA page_size").fetchone()[0])
            max_pages = max(1, self._max_db_bytes // page_size)
            actual_max_pages = int(
                self._conn.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
            )
            if actual_max_pages * page_size > self._max_db_bytes:
                raise sqlite3.DatabaseError(
                    "provider-call ledger already exceeds its hard size limit"
                )
            self._conn.executescript(_SCHEMA_DDL)
            columns = {
                str(row[1]) for row in self._conn.execute("PRAGMA table_info(provider_calls)")
            }
            if "terminal_reserve" not in columns:
                try:
                    self._conn.execute(
                        "ALTER TABLE provider_calls ADD COLUMN terminal_reserve BLOB"
                    )
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc).casefold():
                        raise
            for column, column_type in (
                ("cost_basis", "TEXT"),
                ("cost_attribution_basis", "TEXT"),
                ("provider_model_usage_json", "TEXT"),
                ("usage_validation_error", "TEXT"),
                ("billing_dimensions_json", "TEXT"),
                ("billing_dimensions_schema", "TEXT"),
                ("cache_read_tokens", "INTEGER"),
                ("cache_creation_tokens", "INTEGER"),
            ):
                if column in columns:
                    continue
                try:
                    self._conn.execute(
                        f"ALTER TABLE provider_calls ADD COLUMN {column} {column_type}"
                    )
                except sqlite3.OperationalError as exc:
                    if "duplicate column" not in str(exc).casefold():
                        raise
            self._conn.commit()
            self._migrate_legacy_error_messages()
            integrity = self._conn.execute("PRAGMA quick_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise sqlite3.DatabaseError("provider-call ledger integrity check failed")
            self.reconcile_stale_started()

    def _migrate_legacy_error_messages(self) -> None:
        """One-time logical scrub of pre-fingerprint provider error bodies."""

        assert self._conn is not None
        migration_key = "error_message_fingerprint_v1"
        completed = self._conn.execute(
            "SELECT value FROM provider_ledger_meta WHERE key = ?", (migration_key,)
        ).fetchone()
        if completed == ("complete",):
            return
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            completed = self._conn.execute(
                "SELECT value FROM provider_ledger_meta WHERE key = ?", (migration_key,)
            ).fetchone()
            if completed == ("complete",):
                self._conn.commit()
                return
            self._conn.execute("DROP TRIGGER IF EXISTS provider_calls_terminal_immutable")
            self._conn.execute("DROP TRIGGER IF EXISTS provider_calls_started_once")
            cursor = self._conn.execute(
                """
                UPDATE provider_calls
                SET error_message = ERROR_MESSAGE_FINGERPRINT(error_message)
                WHERE error_message IS NOT NULL AND (
                    length(error_message) <> 71
                    OR substr(error_message, 1, 7) <> 'sha256:'
                    OR substr(error_message, 8) GLOB '*[^0-9a-f]*'
                )
                """
            )
            self._conn.execute(
                """
                CREATE TRIGGER provider_calls_terminal_immutable
                    BEFORE UPDATE ON provider_calls
                    WHEN OLD.status <> 'started'
                    BEGIN
                        SELECT RAISE(ABORT, 'terminal provider call is immutable');
                    END
                """
            )
            self._conn.execute(
                """
                CREATE TRIGGER provider_calls_started_once
                    BEFORE UPDATE ON provider_calls
                    WHEN OLD.status = 'started' AND NEW.status = 'started'
                    BEGIN
                        SELECT RAISE(ABORT, 'provider call must become terminal');
                    END
                """
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO provider_ledger_meta(key, value) VALUES (?, 'complete')",
                (migration_key,),
            )
            self._conn.commit()
            if cursor.rowcount:
                self._local_revision += 1
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except BaseException:
            self._conn.rollback()
            raise

    def reconcile_stale_started(self, *, now: float | None = None) -> int:
        """Close stale crash residue without inventing a provider result or usage."""

        current = time.time() if now is None else float(now)
        cutoff = current - self._stale_started_after_seconds
        try:
            with self._lock:
                assert self._conn is not None
                self._assert_database_path()
                cursor = self._conn.execute(
                    """
                    UPDATE provider_calls
                    SET finished_at = ?, status = 'provider_error',
                        error_type = 'stale_started_reconciled',
                        error_message = ?,
                        latency_ms = MIN(?, MAX(0, CAST((? - started_at) * 1000 AS INTEGER))),
                        terminal_reserve = NULL
                    WHERE status = 'started' AND started_at <= ?
                    """,
                    (
                        current,
                        _error_message_fingerprint(
                            "provider terminal result unknown after process interruption"
                        ),
                        _SQLITE_INT64_MAX,
                        current,
                        cutoff,
                    ),
                )
                if cursor.rowcount:
                    self._conn.execute(
                        """
                        UPDATE commercial_budget_reservations
                        SET state = 'review_required', updated_at = ?
                        WHERE state = 'reserved' AND call_id IN (
                            SELECT call_id FROM provider_calls
                            WHERE status = 'provider_error'
                              AND error_type = 'stale_started_reconciled'
                              AND finished_at = ?
                        )
                        """,
                        (current, current),
                    )
                self._conn.commit()
                if cursor.rowcount:
                    self._local_revision += 1
                return int(cursor.rowcount)
        except Exception as exc:
            raise self._write_failure("stale reconciliation", exc) from exc

    def _write_failure(self, operation: str, exc: Exception) -> ProviderCallLedgerUnavailable:
        self._last_write_error_type = type(exc).__name__[:128]
        self._last_write_error_at = time.time()
        return ProviderCallLedgerUnavailable(
            f"provider-call ledger {operation} failed: {type(exc).__name__}"
        )

    def _write_succeeded(self) -> None:
        self._last_write_error_type = None
        self._last_write_error_at = None

    def operational_snapshot(self) -> dict[str, Any]:
        """Return a cheap, non-secret readiness and capacity snapshot.

        This does not insert a synthetic provider call.  It proves the live
        handle/path are usable for reads, checks that the connection is not in
        query-only mode, and applies the same bounded-capacity policy exposed
        by the financial summary.  A real write failure remains visible until
        a later real ledger mutation succeeds.
        """

        try:
            with self._lock:
                if self._conn is None:
                    raise sqlite3.ProgrammingError("provider-call ledger is closed")
                self._assert_database_path()
                if self._conn.execute("SELECT 1").fetchone() != (1,):
                    raise sqlite3.DatabaseError("provider-call ledger probe failed")
                query_only = int(self._conn.execute("PRAGMA query_only").fetchone()[0])
                page_size = int(self._conn.execute("PRAGMA page_size").fetchone()[0])
                page_count = int(self._conn.execute("PRAGMA page_count").fetchone()[0])
                max_page_count = int(
                    self._conn.execute("PRAGMA max_page_count").fetchone()[0]
                )
                database_bytes = page_size * page_count
                max_database_bytes = page_size * max_page_count
                wal_path = Path(f"{self.path}-wal")
                try:
                    wal_bytes = int(os.lstat(wal_path).st_size)
                except FileNotFoundError:
                    wal_bytes = 0
                disk = shutil.disk_usage(self.path.parent)
                last_error_type = self._last_write_error_type
                last_error_at = self._last_write_error_at
        except Exception as exc:  # noqa: BLE001 -- health degrades without leaking details
            return {
                "required": bool(self.required),
                "ready": False,
                "status": "unavailable",
                "capacity_status": "unknown",
                "database_bytes": 0,
                "wal_bytes": 0,
                "max_database_bytes": int(self._max_db_bytes),
                "disk_free_bytes": 0,
                "last_write_error_type": (
                    self._last_write_error_type or type(exc).__name__[:128]
                ),
                "last_write_error_at": self._last_write_error_at,
            }

        capacity_ratio = database_bytes / max(1, max_database_bytes)
        disk_warning = disk.free < max(1024 * 1024 * 1024, int(disk.total * 0.05))
        disk_critical = disk.free < max(256 * 1024 * 1024, int(disk.total * 0.01))
        wal_warning = wal_bytes >= 128 * 1024 * 1024
        capacity_status = (
            "critical"
            if capacity_ratio >= 0.9 or disk_critical
            else "warning"
            if capacity_ratio >= 0.75 or disk_warning or wal_warning
            else "ok"
        )
        ready = bool(
            query_only == 0
            and capacity_status != "critical"
            and last_error_type is None
        )
        return {
            "required": bool(self.required),
            "ready": ready,
            "status": (
                "critical"
                if not ready
                else "warning"
                if capacity_status == "warning"
                else "ok"
            ),
            "capacity_status": capacity_status,
            "database_bytes": database_bytes,
            "wal_bytes": wal_bytes,
            "max_database_bytes": max_database_bytes,
            "disk_free_bytes": int(disk.free),
            "last_write_error_type": last_error_type,
            "last_write_error_at": last_error_at,
        }

    def turn_requires_operator_recovery(self, turn_id: str, workflow_id: str) -> bool:
        """Block a durable Turn replay after any possibly submitted call.

        A pre-call ledger claim is committed before every provider invocation.
        Therefore a prior claim with no locally replayable Turn result is a
        conservative crash-recovery boundary.  Only failures that prove the
        request could not have been submitted are safe to retry automatically.
        """

        normalized = _required_text(
            turn_id, "durable turn_id", max_chars=_MAX_CONTEXT_CHARS
        )
        if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
            raise ProviderCallLedgerUnavailable(
                "provider-call durable turn_id must be a lowercase SHA-256 digest"
            )
        normalized_workflow = _required_text(
            workflow_id, "durable workflow_id", max_chars=_MAX_CONTEXT_CHARS
        )
        if normalized_workflow not in {"weixin:agent_chat", "feishu:agent_chat"}:
            raise ProviderCallLedgerUnavailable(
                "provider-call durable workflow_id is not a persistent channel"
            )
        try:
            with self._lock:
                if self._conn is None:
                    raise sqlite3.ProgrammingError("provider-call ledger is closed")
                self._assert_database_path()
                row = self._conn.execute(
                    f"""
                    SELECT 1
                    FROM provider_calls
                    WHERE turn_id = ?
                      AND workflow_id = ?
                      AND NOT {_PROVEN_PRE_SUBMISSION_SQL}
                    LIMIT 1
                    """,
                    (normalized, normalized_workflow),
                ).fetchone()
                return row is not None
        except ProviderCallLedgerUnavailable:
            raise
        except Exception as exc:
            raise ProviderCallLedgerUnavailable(
                "provider-call durable Turn recovery preflight failed: "
                f"{type(exc).__name__}"
            ) from exc

    def recovery_snapshot(self, turn_id: str) -> dict[str, Any]:
        """Aggregate non-sensitive provider-attempt state for one durable Turn."""

        normalized = _required_text(
            turn_id, "durable turn_id", max_chars=_MAX_CONTEXT_CHARS
        )
        if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
            raise ProviderCallLedgerUnavailable(
                "provider-call durable turn_id must be a lowercase SHA-256 digest"
            )
        statuses = (
            "started",
            "success",
            "provider_error",
            "timeout",
            "cancelled",
            "empty_stream",
            "stream_interrupted",
        )
        try:
            with self._lock:
                if self._conn is None:
                    raise sqlite3.ProgrammingError("provider-call ledger is closed")
                self._assert_database_path()
                rows = self._conn.execute(
                    f"""
                    SELECT status,
                           COUNT(*),
                           SUM(CASE WHEN {_PROVEN_PRE_SUBMISSION_SQL}
                               THEN 1 ELSE 0 END)
                    FROM provider_calls
                    WHERE turn_id = ?
                      AND workflow_id IN ('weixin:agent_chat','feishu:agent_chat')
                    GROUP BY status
                    """,
                    (normalized,),
                ).fetchall()
                attempt_rows = self._conn.execute(
                    """
                    SELECT call_id,started_at,finished_at,attempt,provider,
                           upstream_model,status,error_type,trace_id,observed_model
                    FROM provider_calls
                    WHERE turn_id = ?
                      AND workflow_id IN ('weixin:agent_chat','feishu:agent_chat')
                    ORDER BY started_at,rowid
                    LIMIT ?
                    """,
                    (normalized, _MAX_RECOVERY_ATTEMPTS + 1),
                ).fetchall()
            status_counts = {status: 0 for status in statuses}
            total_calls = 0
            proven_pre_submission_failures = 0
            for status, count, safe_count in rows:
                normalized_status = str(status)
                if normalized_status not in status_counts:
                    raise sqlite3.DatabaseError(
                        "provider-call ledger contains an invalid status"
                    )
                status_counts[normalized_status] = int(count)
                total_calls += int(count)
                proven_pre_submission_failures += int(safe_count or 0)
            possibly_submitted_calls = max(
                0, total_calls - proven_pre_submission_failures
            )
            attempts_truncated = len(attempt_rows) > _MAX_RECOVERY_ATTEMPTS
            attempts = [
                {
                    "call_id": str(call_id),
                    "started_at": float(started_at),
                    "finished_at": (
                        None if finished_at is None else float(finished_at)
                    ),
                    "attempt": int(attempt),
                    "provider": str(provider),
                    "upstream_model": str(upstream_model),
                    "status": str(status),
                    "error_type": None if error_type is None else str(error_type),
                    "trace_id": None if trace_id is None else str(trace_id),
                    "observed_model": (
                        None if observed_model is None else str(observed_model)
                    ),
                }
                for (
                    call_id,
                    started_at,
                    finished_at,
                    attempt,
                    provider,
                    upstream_model,
                    status,
                    error_type,
                    trace_id,
                    observed_model,
                ) in attempt_rows[:_MAX_RECOVERY_ATTEMPTS]
            ]
            return {
                "found": total_calls > 0,
                "total_calls": total_calls,
                "terminal_calls": total_calls - status_counts["started"],
                "open_unresolved_calls": status_counts["started"],
                "status_counts": status_counts,
                "proven_pre_submission_failures": proven_pre_submission_failures,
                "possibly_submitted_calls": possibly_submitted_calls,
                "requires_operator_recovery": possibly_submitted_calls > 0,
                "attempts": attempts,
                "attempts_truncated": attempts_truncated,
            }
        except ProviderCallLedgerUnavailable:
            raise
        except Exception as exc:
            raise ProviderCallLedgerUnavailable(
                "provider-call durable Turn recovery query failed: "
                f"{type(exc).__name__}"
            ) from exc

    def _commercial_available_locked(self) -> int:
        assert self._conn is not None
        available = 0
        for kind, raw_amount in self._conn.execute(
            "SELECT kind, amount_microusd FROM commercial_budget_entries"
        ):
            amount = int(raw_amount)
            if kind == "funding" or kind == "release":
                available += amount
            elif kind == "hold":
                available -= amount
        if available < 0:
            raise sqlite3.DatabaseError("commercial budget available balance is negative")
        return available

    def _insert_commercial_entry_locked(
        self,
        *,
        kind: str,
        stable_id: str,
        operation_id: str,
        amount_microusd: int,
        quote_fingerprint: str,
        call_id: str | None = None,
        quote_id: str | None = None,
        created_at: float | None = None,
    ) -> None:
        assert self._conn is not None
        if kind not in {"funding", "hold", "capture", "release"}:
            raise sqlite3.IntegrityError("invalid commercial budget entry kind")
        self._conn.execute(
            """
            INSERT INTO commercial_budget_entries (
                entry_id, created_at, kind, call_id, operation_id, quote_id,
                amount_microusd, currency, evidence_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'USD', ?)
            """,
            (
                _commercial_entry_id(kind, stable_id),
                time.time() if created_at is None else float(created_at),
                kind,
                call_id,
                operation_id,
                quote_id,
                int(amount_microusd),
                _commercial_entry_evidence(
                    kind=kind,
                    stable_id=stable_id,
                    amount_microusd=int(amount_microusd),
                    quote_fingerprint=quote_fingerprint,
                ),
            ),
        )

    def fund_commercial_budget(self, *, funding_id: str, amount_microusd: int) -> bool:
        """Append one idempotent synthetic/admin funding entry for the USD account."""

        if not self.commercial_budget_required:
            raise ProviderCallLedgerUnavailable("commercial budget mode is not enabled")
        normalized_id = _required_text(
            funding_id, "commercial funding_id", max_chars=_MAX_CALL_ID_CHARS
        )
        amount = _optional_nonnegative_int(amount_microusd)
        if amount is None or amount <= 0:
            raise ProviderCallLedgerUnavailable(
                "commercial funding amount_microusd must be a positive integer"
            )
        entry_id = _commercial_entry_id("funding", normalized_id)
        evidence = _commercial_entry_evidence(
            kind="funding",
            stable_id=normalized_id,
            amount_microusd=amount,
            quote_fingerprint="synthetic-or-admin-funding",
        )
        try:
            with self._lock:
                assert self._conn is not None
                self._assert_database_path()
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    existing = self._conn.execute(
                        """
                        SELECT operation_id, amount_microusd, currency, evidence_sha256
                        FROM commercial_budget_entries WHERE entry_id = ?
                        """,
                        (entry_id,),
                    ).fetchone()
                    if existing is not None:
                        self._conn.rollback()
                        if existing == (normalized_id, amount, "USD", evidence):
                            return False
                        raise ProviderCallLedgerUnavailable(
                            "commercial funding id is already bound to different evidence"
                        )
                    self._insert_commercial_entry_locked(
                        kind="funding",
                        stable_id=normalized_id,
                        operation_id=normalized_id,
                        amount_microusd=amount,
                        quote_fingerprint="synthetic-or-admin-funding",
                    )
                    self._conn.commit()
                except Exception:
                    self._conn.rollback()
                    raise
                self._write_succeeded()
                return True
        except ProviderCallLedgerUnavailable:
            raise
        except Exception as exc:
            raise self._write_failure("commercial funding", exc) from exc

    def commercial_budget_snapshot(self) -> dict[str, Any]:
        """Return exact integer customer-budget state; no provider price inference."""

        if not self.commercial_budget_required:
            raise ProviderCallLedgerUnavailable("commercial budget mode is not enabled")
        try:
            with self._lock:
                assert self._conn is not None
                self._assert_database_path()
                entries = self._conn.execute(
                    "SELECT kind, amount_microusd FROM commercial_budget_entries"
                ).fetchall()
                reservations = self._conn.execute(
                    """
                    SELECT state, COUNT(*),
                           EXACT_INT_SUM(CASE WHEN state IN ('reserved','review_required')
                                              THEN reserved_microusd ELSE 0 END)
                    FROM commercial_budget_reservations GROUP BY state
                    """
                ).fetchall()
        except Exception as exc:
            raise ProviderCallLedgerUnavailable(
                f"commercial budget snapshot unavailable: {type(exc).__name__}"
            ) from exc

        totals = {"funding": 0, "hold": 0, "capture": 0, "release": 0}
        for kind, raw_amount in entries:
            totals[str(kind)] += int(raw_amount)
        available = totals["funding"] - totals["hold"] + totals["release"]
        if available < 0:
            raise ProviderCallLedgerUnavailable(
                "commercial budget snapshot found a negative available balance"
            )
        states = {str(state): int(count) for state, count, _held in reservations}
        active_hold = sum(int(held) for _state, _count, held in reservations)
        return {
            "currency": _COMMERCIAL_BUDGET_CURRENCY,
            "funded_microusd": totals["funding"],
            "historical_hold_microusd": totals["hold"],
            "captured_microusd": totals["capture"],
            "released_microusd": totals["release"],
            "active_hold_microusd": active_hold,
            "available_microusd": available,
            "reservation_states": states,
        }

    def start_attempt(
        self,
        *,
        identity: ProviderRouteIdentity,
        context: ProviderCallContext,
        attempt: int,
        stream: bool,
        call_id: str | None = None,
        commercial_budget: CommercialBudgetAuthorization | None = None,
    ) -> ProviderCallAttemptProtocol:
        started_at = time.time()
        started_monotonic = time.monotonic()
        try:
            attempt_number = int(attempt)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ProviderCallLedgerUnavailable("provider-call attempt must be an integer") from exc
        if not 1 <= attempt_number <= 2_147_483_647:
            raise ProviderCallLedgerUnavailable(
                "provider-call attempt must be between 1 and 2147483647"
            )
        if self.commercial_budget_required and commercial_budget is None:
            raise ProviderCallLedgerUnavailable(
                "commercial budget authorization is required before provider invocation"
            )
        if commercial_budget is not None and not self.commercial_budget_required:
            raise ProviderCallLedgerUnavailable(
                "commercial budget authorization requires explicit commercial budget mode"
            )
        if commercial_budget is not None:
            expected_call_id = commercial_budget.call_id_for_attempt(attempt_number)
            if call_id is not None and str(call_id) != expected_call_id:
                raise ProviderCallLedgerUnavailable(
                    "commercial call_id does not match the trusted operation quote"
                )
            call_id = expected_call_id
        else:
            call_id = (
                _required_text(call_id, "call_id", max_chars=_MAX_CALL_ID_CHARS)
                if call_id is not None
                else uuid.uuid4().hex
            )
        frozen = (
            _optional_text(context.trace_id, max_chars=_MAX_CONTEXT_CHARS),
            _optional_text(context.turn_id, max_chars=_MAX_CONTEXT_CHARS),
            _optional_text(context.workflow_id, max_chars=_MAX_CONTEXT_CHARS),
            _optional_text(context.role, max_chars=_MAX_CONTEXT_CHARS),
            attempt_number,
            _required_text(
                identity.requested_model,
                "requested_model",
                max_chars=_MAX_IDENTITY_CHARS,
            ),
            _required_text(identity.actual_model, "actual_model", max_chars=_MAX_IDENTITY_CHARS),
            _required_text(identity.provider, "provider", max_chars=_MAX_IDENTITY_CHARS),
            _required_text(
                identity.upstream_model,
                "upstream_model",
                max_chars=_MAX_IDENTITY_CHARS,
            ),
            int(bool(stream)),
        )
        for label, raw, normalized in (
            ("trace_id", context.trace_id, frozen[0]),
            ("turn_id", context.turn_id, frozen[1]),
            ("workflow_id", context.workflow_id, frozen[2]),
            ("role", context.role, frozen[3]),
        ):
            if raw is not None and str(raw).strip() and normalized is None:
                raise ProviderCallLedgerUnavailable(
                    f"provider-call {label} exceeds {_MAX_CONTEXT_CHARS} characters"
                )
        try:
            with self._lock:
                assert self._conn is not None
                self._assert_database_path()
                if commercial_budget is None:
                    self._conn.execute(
                        """
                        INSERT INTO provider_calls (
                            call_id, started_at, trace_id, turn_id, workflow_id, role,
                            attempt, requested_model, actual_model, provider,
                            upstream_model, stream, status, terminal_reserve
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'started', zeroblob(?))
                        """,
                        (call_id, started_at, *frozen, _TERMINAL_RESERVE_BYTES),
                    )
                    self._conn.commit()
                else:
                    operation_id, quote_id, reserve, capture, currency = (
                        commercial_budget.normalized()
                    )
                    quote_fingerprint = commercial_budget.quote_fingerprint()
                    self._conn.execute("BEGIN IMMEDIATE")
                    try:
                        existing = self._conn.execute(
                            """
                            SELECT operation_id, quote_id, quote_fingerprint,
                                   reserved_microusd, capture_microusd, currency
                            FROM commercial_budget_reservations WHERE call_id = ?
                            """,
                            (call_id,),
                        ).fetchone()
                        expected = (
                            operation_id,
                            quote_id,
                            quote_fingerprint,
                            reserve,
                            capture,
                            currency,
                        )
                        if existing is not None:
                            if existing == expected:
                                raise CommercialBudgetAlreadyClaimed(
                                    "commercial call_id has already claimed execution"
                                )
                            raise ProviderCallLedgerUnavailable(
                                "commercial call_id is bound to different quote evidence"
                            )
                        orphan = self._conn.execute(
                            "SELECT 1 FROM provider_calls WHERE call_id = ?", (call_id,)
                        ).fetchone()
                        if orphan is not None:
                            raise ProviderCallLedgerUnavailable(
                                "commercial call_id conflicts with an existing provider attempt"
                            )
                        available = self._commercial_available_locked()
                        if available < reserve:
                            raise CommercialBudgetExceeded(
                                "commercial budget is insufficient for the trusted quote"
                            )
                        self._conn.execute(
                            """
                            INSERT INTO provider_calls (
                                call_id, started_at, trace_id, turn_id, workflow_id, role,
                                attempt, requested_model, actual_model, provider,
                                upstream_model, stream, status, terminal_reserve
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'started', zeroblob(?))
                            """,
                            (call_id, started_at, *frozen, _TERMINAL_RESERVE_BYTES),
                        )
                        self._conn.execute(
                            """
                            INSERT INTO commercial_budget_reservations (
                                call_id, operation_id, quote_id, quote_fingerprint,
                                reserved_microusd, capture_microusd, currency, state,
                                created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                            """,
                            (
                                call_id,
                                operation_id,
                                quote_id,
                                quote_fingerprint,
                                reserve,
                                capture,
                                currency,
                                started_at,
                                started_at,
                            ),
                        )
                        self._insert_commercial_entry_locked(
                            kind="hold",
                            stable_id=call_id,
                            operation_id=operation_id,
                            amount_microusd=reserve,
                            quote_fingerprint=quote_fingerprint,
                            call_id=call_id,
                            quote_id=quote_id,
                            created_at=started_at,
                        )
                        self._conn.commit()
                    except Exception:
                        self._conn.rollback()
                        raise
                self._local_revision += 1
                self._write_succeeded()
        except ProviderCallLedgerUnavailable:
            raise
        except sqlite3.IntegrityError as exc:
            with self._lock:
                if self._conn is not None and self._conn.in_transaction:
                    self._conn.rollback()
            if "UNIQUE" in str(exc).upper() or "PRIMARY KEY" in str(exc).upper():
                raise ProviderCallLedgerUnavailable(
                    "provider-call call_id has already claimed execution"
                ) from exc
            if self.required:
                raise self._write_failure("start", exc) from exc
            self._write_failure("start", exc)
            return _NoopAttempt(call_id)
        except Exception as exc:
            with self._lock:
                if self._conn is not None and self._conn.in_transaction:
                    self._conn.rollback()
            if self.required:
                raise self._write_failure("start", exc) from exc
            self._write_failure("start", exc)
            return _NoopAttempt(call_id)
        return ProviderCallAttempt(self, call_id, started_monotonic)

    def _finish_attempt(
        self,
        call_id: str,
        *,
        started_monotonic: float,
        status: str,
        observed_model: str | None,
        usage: Mapping[str, Any] | None,
        error_type: str | None,
        error_message: str | None,
    ) -> bool:
        if status not in _TERMINAL_STATUSES:
            raise ValueError(f"invalid provider-call terminal status: {status}")
        values = dict(usage or {})
        prompt_tokens = _optional_nonnegative_int(values.get("prompt_tokens"))
        completion_tokens = _optional_nonnegative_int(values.get("completion_tokens"))
        total_tokens = _optional_nonnegative_int(values.get("total_tokens"))
        usage_validation_error = (
            values.get("usage_validation_error")
            if values.get("usage_validation_error") in {"total_tokens_mismatch"}
            else None
        )
        if (
            prompt_tokens is not None
            and completion_tokens is not None
            and total_tokens is not None
        ):
            combined = prompt_tokens + completion_tokens
            if combined > _SQLITE_INT64_MAX or total_tokens != combined:
                total_tokens = None
                usage_validation_error = "total_tokens_mismatch"
        billing_dimensions_schema = (
            _BILLING_DIMENSIONS_SCHEMA
            if values.get("billing_dimensions_schema") == _BILLING_DIMENSIONS_SCHEMA
            else None
        )
        billing_dimensions_json = (
            _billing_dimensions_json(values.get("billing_dimensions_json"))
            if billing_dimensions_schema is not None
            else None
        )
        if billing_dimensions_json is None:
            billing_dimensions_schema = None
        finished_at = time.time()
        latency_ms = max(0, int((time.monotonic() - started_monotonic) * 1000))
        try:
            with self._lock:
                assert self._conn is not None
                self._assert_database_path()
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    normalized_error_type = _truncated_optional_text(
                        error_type, max_chars=_MAX_CONTEXT_CHARS
                    )
                    cursor = self._conn.execute(
                        """
                        UPDATE provider_calls
                        SET finished_at = ?, observed_model = ?, status = ?,
                            error_type = ?, error_message = ?, latency_ms = ?,
                            prompt_tokens = ?, completion_tokens = ?, total_tokens = ?,
                            cached_tokens = ?, cache_read_tokens = ?,
                            cache_creation_tokens = ?, cost_microusd = ?, cost_basis = ?,
                            cost_attribution_basis = ?, provider_model_usage_json = ?,
                            usage_validation_error = ?,
                            billing_dimensions_json = ?, billing_dimensions_schema = ?,
                            terminal_reserve = NULL
                        WHERE call_id = ? AND status = 'started'
                        """,
                        (
                            finished_at,
                            _optional_text(observed_model, max_chars=_MAX_IDENTITY_CHARS),
                            status,
                            normalized_error_type,
                            _error_message_fingerprint(error_message),
                            latency_ms,
                            prompt_tokens,
                            completion_tokens,
                            total_tokens,
                            _optional_nonnegative_int(values.get("cached_tokens")),
                            _optional_nonnegative_int(values.get("cache_read_tokens")),
                            _optional_nonnegative_int(values.get("cache_creation_tokens")),
                            _optional_nonnegative_int(values.get("cost_microusd")),
                            _cost_basis(values.get("cost_basis")),
                            (
                                values.get("cost_attribution_basis")
                                if values.get("cost_attribution_basis")
                                in _COST_ATTRIBUTION_BASES
                                else None
                            ),
                            _normalized_provider_model_usage_json(
                                values.get("provider_model_usage_json")
                            ),
                            usage_validation_error,
                            billing_dimensions_json,
                            billing_dimensions_schema,
                            call_id,
                        ),
                    )
                    if cursor.rowcount == 1:
                        reservation = self._conn.execute(
                            """
                            SELECT operation_id, quote_id, quote_fingerprint,
                                   reserved_microusd, capture_microusd, state
                            FROM commercial_budget_reservations WHERE call_id = ?
                            """,
                            (call_id,),
                        ).fetchone()
                        if reservation is not None:
                            (
                                operation_id,
                                quote_id,
                                quote_fingerprint,
                                reserve,
                                capture,
                                reservation_state,
                            ) = reservation
                            if reservation_state != "reserved":
                                raise sqlite3.IntegrityError(
                                    "commercial reservation was already terminal"
                                )
                            if status == "success":
                                self._insert_commercial_entry_locked(
                                    kind="capture",
                                    stable_id=call_id,
                                    operation_id=str(operation_id),
                                    amount_microusd=int(capture),
                                    quote_fingerprint=str(quote_fingerprint),
                                    call_id=call_id,
                                    quote_id=str(quote_id),
                                    created_at=finished_at,
                                )
                                remainder = int(reserve) - int(capture)
                                if remainder:
                                    self._insert_commercial_entry_locked(
                                        kind="release",
                                        stable_id=call_id,
                                        operation_id=str(operation_id),
                                        amount_microusd=remainder,
                                        quote_fingerprint=str(quote_fingerprint),
                                        call_id=call_id,
                                        quote_id=str(quote_id),
                                        created_at=finished_at,
                                    )
                                next_state = "captured"
                            elif _commercial_failure_proven_pre_submission(
                                status, normalized_error_type
                            ):
                                self._insert_commercial_entry_locked(
                                    kind="release",
                                    stable_id=call_id,
                                    operation_id=str(operation_id),
                                    amount_microusd=int(reserve),
                                    quote_fingerprint=str(quote_fingerprint),
                                    call_id=call_id,
                                    quote_id=str(quote_id),
                                    created_at=finished_at,
                                )
                                next_state = "released"
                            else:
                                next_state = "review_required"
                            self._conn.execute(
                                """
                                UPDATE commercial_budget_reservations
                                SET state = ?, updated_at = ?
                                WHERE call_id = ? AND state = 'reserved'
                                """,
                                (next_state, finished_at, call_id),
                            )
                        self._conn.commit()
                        self._local_revision += 1
                        self._write_succeeded()
                        return True
                    existing = self._conn.execute(
                        "SELECT status FROM provider_calls WHERE call_id = ?", (call_id,)
                    ).fetchone()
                    self._conn.rollback()
                    if existing is None:
                        raise ProviderCallLedgerUnavailable(
                            "provider call disappeared before finalize"
                        )
                    return False
                except Exception:
                    self._conn.rollback()
                    raise
        except ProviderCallLedgerUnavailable:
            raise
        except Exception as exc:
            if self.required:
                raise self._write_failure("finalize", exc) from exc
            self._write_failure("finalize", exc)
            return False

    def list_calls(self) -> list[dict[str, Any]]:
        columns = (
            "call_id",
            "started_at",
            "finished_at",
            "trace_id",
            "turn_id",
            "workflow_id",
            "role",
            "attempt",
            "requested_model",
            "actual_model",
            "provider",
            "upstream_model",
            "observed_model",
            "stream",
            "status",
            "error_type",
            "error_message",
            "latency_ms",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "cached_tokens",
            "cache_read_tokens",
            "cache_creation_tokens",
            "cost_microusd",
            "cost_basis",
            "cost_attribution_basis",
            "provider_model_usage_json",
            "usage_validation_error",
            "billing_dimensions_json",
            "billing_dimensions_schema",
        )
        with self._lock:
            if self._conn is None:
                raise ProviderCallLedgerUnavailable("provider-call ledger is closed")
            self._assert_database_path()
            rows = self._conn.execute(
                f"SELECT {', '.join(columns)} FROM provider_calls"
                # started_at shares one wall-clock tick (15.6 ms on Windows)
                # for rapid sequential attempts; break ties by rowid so the
                # audit order always matches durable insertion (execution)
                # order instead of the random call_id.
                " ORDER BY started_at, rowid"
            ).fetchall()
        return [
            {**dict(zip(columns, row)), "stream": bool(row[13])}
            for row in rows
        ]

    def financial_summary(self, *, period: str = "month") -> dict[str, Any]:
        """Aggregate only immutable provider-attempt rows for financial UI.

        ``actual_model`` is deliberately exposed as ``resolved_model``: it is
        the gateway route alias, not a claim that a generic provider proved the
        physical model identity.  Missing usage/cost in any call keeps the
        corresponding aggregate unknown instead of silently becoming zero.
        """

        normalized_period = str(period).strip().lower()
        if normalized_period not in {"day", "month", "all"}:
            raise ValueError("financial summary period must be day, month, or all")
        now = datetime.now(UTC)
        if normalized_period == "day":
            period_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            period_end = period_start + timedelta(days=1)
        elif normalized_period == "month":
            period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            period_end = (
                period_start.replace(year=period_start.year + 1, month=1)
                if period_start.month == 12
                else period_start.replace(month=period_start.month + 1)
            )
        else:
            period_start = None
            period_end = None
        where_sql = ""
        query_params: tuple[Any, ...] = ()
        if period_start is not None and period_end is not None:
            where_sql = "WHERE started_at >= ? AND started_at < ?"
            query_params = (period_start.timestamp(), period_end.timestamp())

        try:
            with self._lock:
                if self._conn is None:
                    raise ProviderCallLedgerUnavailable("provider-call ledger is closed")
                self._assert_database_path()
                data_version = int(
                    self._conn.execute("PRAGMA data_version").fetchone()[0]
                )
                cache_key = (
                    self._local_revision,
                    data_version,
                    normalized_period,
                    period_start.timestamp() if period_start is not None else None,
                    period_end.timestamp() if period_end is not None else None,
                )
                if (
                    cache_key == self._summary_cache_key
                    and self._summary_cache is not None
                ):
                    return copy.deepcopy(self._summary_cache)
        except ProviderCallLedgerUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ProviderCallLedgerUnavailable(
                f"provider-call financial summary unavailable: {type(exc).__name__}"
            ) from exc

        try:
            reader = self._open_read_connection()
            try:
                rows = reader.execute(
                    f"""
                SELECT provider, upstream_model, actual_model,
                       COUNT(*) AS calls,
                       SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS success_calls,
                       SUM(CASE WHEN status='started' THEN 1 ELSE 0 END) AS open_calls,
                       SUM(CASE WHEN error_type IN (
                                   'stale_started_reconciled',
                                   'submission_outcome_unknown',
                                   'chat_submission_outcome_unknown',
                                   'stream_submission_outcome_unknown',
                                   'image_submission_outcome_unknown',
                                   'video_submission_outcome_unknown'
                                ) THEN 1 ELSE 0 END) AS outcome_unknown_calls,
                       SUM(CASE WHEN status NOT IN ('success','started')
                                     AND COALESCE(error_type, '') NOT IN (
                                        'stale_started_reconciled',
                                        'submission_outcome_unknown',
                                        'chat_submission_outcome_unknown',
                                        'stream_submission_outcome_unknown',
                                        'image_submission_outcome_unknown',
                                        'video_submission_outcome_unknown'
                                     )
                                THEN 1 ELSE 0 END) AS failed_calls,
                       SUM(CASE WHEN prompt_tokens IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(prompt_tokens),
                       SUM(CASE WHEN completion_tokens IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(completion_tokens),
                       SUM(CASE WHEN total_tokens IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(total_tokens),
                       SUM(CASE WHEN cached_tokens IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(cached_tokens),
                       SUM(CASE WHEN cache_read_tokens IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(cache_read_tokens),
                       SUM(CASE WHEN cache_creation_tokens IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(cache_creation_tokens),
                       SUM(CASE WHEN cost_microusd IS NULL THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(cost_microusd),
                       SUM(CASE WHEN cost_microusd IS NOT NULL
                                     AND cost_basis='provider_reported' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN cost_microusd IS NOT NULL
                                     AND cost_basis='invoice_reconciled' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN cost_microusd IS NOT NULL
                                     AND cost_basis LIKE 'estimated_%' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN cost_microusd IS NOT NULL
                                     AND (cost_basis IS NULL OR cost_basis NOT IN (
                                         'provider_reported', 'invoice_reconciled'
                                     ) AND cost_basis NOT LIKE 'estimated_%')
                                THEN 1 ELSE 0 END),
                       EXACT_INT_SUM(CASE WHEN cost_basis='provider_reported'
                                          THEN cost_microusd ELSE 0 END),
                       EXACT_INT_SUM(CASE WHEN cost_basis='invoice_reconciled'
                                          THEN cost_microusd ELSE 0 END),
                       EXACT_INT_SUM(CASE WHEN cost_basis LIKE 'estimated_%'
                                          THEN cost_microusd ELSE 0 END),
                       EXACT_INT_SUM(CASE WHEN cost_microusd IS NOT NULL
                                             AND (cost_basis IS NULL OR cost_basis NOT IN (
                                                 'provider_reported', 'invoice_reconciled'
                                             ) AND cost_basis NOT LIKE 'estimated_%')
                                          THEN cost_microusd ELSE 0 END),
                       SUM(CASE WHEN provider_model_usage_json IS NOT NULL THEN 1 ELSE 0 END)
                FROM provider_calls
                {where_sql}
                GROUP BY provider, upstream_model, actual_model
                ORDER BY provider, upstream_model, actual_model
                    """,
                    query_params,
                ).fetchall()
                page_size = int(reader.execute("PRAGMA page_size").fetchone()[0])
                page_count = int(reader.execute("PRAGMA page_count").fetchone()[0])
                max_page_count = int(
                    reader.execute("PRAGMA max_page_count").fetchone()[0]
                )
            finally:
                reader.close()
            database_bytes = page_size * page_count
            max_database_bytes = page_size * max_page_count
            wal_path = Path(f"{self.path}-wal")
            try:
                wal_bytes = int(os.lstat(wal_path).st_size)
            except FileNotFoundError:
                wal_bytes = 0
            disk = shutil.disk_usage(self.path.parent)
        except ProviderCallLedgerUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ProviderCallLedgerUnavailable(
                f"provider-call financial summary unavailable: {type(exc).__name__}"
            ) from exc

        models: list[dict[str, Any]] = []
        totals = {
            "calls": 0,
            "success": 0,
            "open": 0,
            "outcome_unknown": 0,
            "failed": 0,
            "unknown_tokens": 0,
            "unknown_cost": 0,
            "known_cost_microusd": 0,
            "provider_reported_cost": 0,
            "invoice_reconciled_cost": 0,
            "estimated_cost": 0,
            "unverified_cost": 0,
            "provider_reported_cost_microusd": 0,
            "invoice_reconciled_cost_microusd": 0,
            "estimated_cost_microusd": 0,
            "unclassified_cost_microusd": 0,
            "provider_internal_breakdown": 0,
        }

        def cost_label(
            *, unknown: int, provider_reported: int, invoice: int, estimated: int, unverified: int
        ) -> str:
            if unknown:
                return "incomplete_cost_evidence"
            if unverified:
                return "unverified_cost_evidence"
            populated = sum(int(value > 0) for value in (provider_reported, invoice, estimated))
            if populated > 1:
                return "mixed_cost_evidence_complete"
            if provider_reported:
                return "provider_reported_complete"
            if invoice:
                return "invoice_reconciled_complete"
            if estimated:
                return "versioned_estimate_complete"
            return "no_cost_evidence"

        for row in rows:
            (
                provider,
                upstream_model,
                resolved_model,
                calls,
                success_calls,
                open_calls,
                outcome_unknown_calls,
                failed_calls,
                unknown_prompt_calls,
                known_prompt_tokens,
                unknown_completion_calls,
                known_completion_tokens,
                unknown_token_calls,
                known_total_tokens,
                unknown_cached_calls,
                known_cached_tokens,
                unknown_cache_read_calls,
                known_cache_read_tokens,
                unknown_cache_creation_calls,
                known_cache_creation_tokens,
                unknown_cost_calls,
                known_cost_microusd,
                provider_reported_cost_calls,
                invoice_reconciled_cost_calls,
                estimated_cost_calls,
                unverified_cost_calls,
                provider_reported_cost_microusd,
                invoice_reconciled_cost_microusd,
                estimated_cost_microusd,
                unclassified_cost_microusd,
                provider_internal_breakdown_calls,
            ) = row
            known_cost_usd = round(int(known_cost_microusd) / 1_000_000, 6)
            models.append(
                {
                    "model": str(upstream_model),
                    "resolved_model": str(resolved_model),
                    "provider": str(provider),
                    "identity_basis": "configured_upstream_unverified",
                    "calls": int(calls),
                    "count_basis": "gateway_provider_attempt",
                    "success_calls": int(success_calls),
                    "failed_calls": int(failed_calls),
                    "open_unresolved_calls": int(open_calls),
                    # Compatibility alias.  The semantic label is deliberately
                    # explicit because a crash residue is not proven in-flight.
                    "in_flight_calls": int(open_calls),
                    "outcome_unknown_calls": int(outcome_unknown_calls),
                    "prompt_tokens": (
                        None if int(unknown_prompt_calls) else int(known_prompt_tokens)
                    ),
                    "known_prompt_tokens": int(known_prompt_tokens),
                    "completion_tokens": (
                        None
                        if int(unknown_completion_calls)
                        else int(known_completion_tokens)
                    ),
                    "known_completion_tokens": int(known_completion_tokens),
                    "total_tokens": (
                        None if int(unknown_token_calls) else int(known_total_tokens)
                    ),
                    "known_total_tokens": int(known_total_tokens),
                    "cached_tokens": (
                        None if int(unknown_cached_calls) else int(known_cached_tokens)
                    ),
                    "known_cached_tokens": int(known_cached_tokens),
                    "cache_read_tokens": (
                        None
                        if int(unknown_cache_read_calls)
                        else int(known_cache_read_tokens)
                    ),
                    "known_cache_read_tokens": int(known_cache_read_tokens),
                    "cache_creation_tokens": (
                        None
                        if int(unknown_cache_creation_calls)
                        else int(known_cache_creation_tokens)
                    ),
                    "known_cache_creation_tokens": int(known_cache_creation_tokens),
                    "unknown_token_calls": int(unknown_token_calls),
                    "unknown_cost_calls": int(unknown_cost_calls),
                    "provider_reported_cost_calls": int(provider_reported_cost_calls),
                    "invoice_reconciled_cost_calls": int(invoice_reconciled_cost_calls),
                    "estimated_cost_calls": int(estimated_cost_calls),
                    "unverified_cost_calls": int(unverified_cost_calls),
                    "provider_internal_breakdown_calls": int(
                        provider_internal_breakdown_calls
                    ),
                    "known_cost_usd": known_cost_usd,
                    "known_cost_microusd": str(int(known_cost_microusd)),
                    "provider_reported_cost_usd": round(
                        int(provider_reported_cost_microusd) / 1_000_000, 6
                    ),
                    "invoice_reconciled_cost_usd": round(
                        int(invoice_reconciled_cost_microusd) / 1_000_000, 6
                    ),
                    "billed_cost_usd": round(
                        int(invoice_reconciled_cost_microusd) / 1_000_000, 6
                    ),
                    "estimated_cost_usd": round(
                        int(estimated_cost_microusd) / 1_000_000, 6
                    ),
                    "unclassified_cost_usd": round(
                        int(unclassified_cost_microusd) / 1_000_000, 6
                    ),
                    "cost_usd": (
                        round(int(invoice_reconciled_cost_microusd) / 1_000_000, 6)
                        if (
                            not int(unknown_cost_calls)
                            and not int(unverified_cost_calls)
                            and not int(estimated_cost_calls)
                            and not int(provider_reported_cost_calls)
                            and int(invoice_reconciled_cost_calls) == int(calls)
                        )
                        else None
                    ),
                    "billed_cost_complete": (
                        not int(unknown_cost_calls)
                        and not int(unverified_cost_calls)
                        and not int(estimated_cost_calls)
                        and not int(provider_reported_cost_calls)
                        and int(invoice_reconciled_cost_calls) == int(calls)
                    ),
                    "cost_basis": cost_label(
                        unknown=int(unknown_cost_calls),
                        provider_reported=int(provider_reported_cost_calls),
                        invoice=int(invoice_reconciled_cost_calls),
                        estimated=int(estimated_cost_calls),
                        unverified=int(unverified_cost_calls),
                    ),
                }
            )
            totals["calls"] += int(calls)
            totals["success"] += int(success_calls)
            totals["open"] += int(open_calls)
            totals["outcome_unknown"] += int(outcome_unknown_calls)
            totals["failed"] += int(failed_calls)
            totals["unknown_tokens"] += int(unknown_token_calls)
            totals["unknown_cost"] += int(unknown_cost_calls)
            totals["known_cost_microusd"] += int(known_cost_microusd)
            totals["provider_reported_cost"] += int(provider_reported_cost_calls)
            totals["invoice_reconciled_cost"] += int(invoice_reconciled_cost_calls)
            totals["estimated_cost"] += int(estimated_cost_calls)
            totals["unverified_cost"] += int(unverified_cost_calls)
            totals["provider_reported_cost_microusd"] += int(
                provider_reported_cost_microusd
            )
            totals["invoice_reconciled_cost_microusd"] += int(
                invoice_reconciled_cost_microusd
            )
            totals["estimated_cost_microusd"] += int(estimated_cost_microusd)
            totals["unclassified_cost_microusd"] += int(unclassified_cost_microusd)
            totals["provider_internal_breakdown"] += int(provider_internal_breakdown_calls)

        known_total_cost_usd = round(totals["known_cost_microusd"] / 1_000_000, 6)
        capacity_ratio = database_bytes / max(1, max_database_bytes)
        disk_warning = disk.free < max(1024 * 1024 * 1024, int(disk.total * 0.05))
        disk_critical = disk.free < max(256 * 1024 * 1024, int(disk.total * 0.01))
        wal_warning = wal_bytes >= 128 * 1024 * 1024
        billed_cost_complete = (
            not totals["unknown_cost"]
            and not totals["unverified_cost"]
            and not totals["estimated_cost"]
            and not totals["provider_reported_cost"]
            and totals["invoice_reconciled_cost"] == totals["calls"]
        )
        summary = {
            "financial_source": bool(self.required),
            "reason": None if self.required else "best_effort_ledger_is_not_financial_truth",
            "ledger_table": "provider_calls",
            "currency": "USD",
            "period": normalized_period,
            "period_start_utc": (
                period_start.isoformat().replace("+00:00", "Z")
                if period_start is not None
                else None
            ),
            "period_end_utc": (
                period_end.isoformat().replace("+00:00", "Z")
                if period_end is not None
                else None
            ),
            "models": models,
            "total_calls": totals["calls"],
            "count_basis": "gateway_provider_attempt",
            "terminal_calls": totals["calls"] - totals["open"],
            "success_calls": totals["success"],
            "failed_calls": totals["failed"],
            "open_unresolved_calls": totals["open"],
            "in_flight_calls": totals["open"],
            "in_flight_semantics": "open_unresolved_not_proven_live",
            "outcome_unknown_calls": totals["outcome_unknown"],
            "unknown_token_calls": totals["unknown_tokens"],
            "unknown_cost_calls": totals["unknown_cost"],
            "provider_reported_cost_calls": totals["provider_reported_cost"],
            "invoice_reconciled_cost_calls": totals["invoice_reconciled_cost"],
            "estimated_cost_calls": totals["estimated_cost"],
            "unverified_cost_calls": totals["unverified_cost"],
            "provider_internal_breakdown_calls": totals["provider_internal_breakdown"],
            "known_cost_usd": known_total_cost_usd,
            "known_cost_microusd": str(totals["known_cost_microusd"]),
            "provider_reported_cost_usd": round(
                totals["provider_reported_cost_microusd"] / 1_000_000, 6
            ),
            "invoice_reconciled_cost_usd": round(
                totals["invoice_reconciled_cost_microusd"] / 1_000_000, 6
            ),
            "billed_cost_usd": round(
                totals["invoice_reconciled_cost_microusd"] / 1_000_000, 6
            ),
            "billed_cost_complete": billed_cost_complete,
            "estimated_cost_usd": round(
                totals["estimated_cost_microusd"] / 1_000_000, 6
            ),
            "unclassified_cost_usd": round(
                totals["unclassified_cost_microusd"] / 1_000_000, 6
            ),
            "total_cost_usd": (
                round(totals["invoice_reconciled_cost_microusd"] / 1_000_000, 6)
                if billed_cost_complete
                else None
            ),
            "cost_basis": cost_label(
                unknown=totals["unknown_cost"],
                provider_reported=totals["provider_reported_cost"],
                invoice=totals["invoice_reconciled_cost"],
                estimated=totals["estimated_cost"],
                unverified=totals["unverified_cost"],
            ),
            "database_bytes": database_bytes,
            "wal_bytes": wal_bytes,
            "storage_bytes": database_bytes + wal_bytes,
            "disk_free_bytes": int(disk.free),
            "max_database_bytes": max_database_bytes,
            "capacity_ratio": round(capacity_ratio, 6),
            "capacity_status": (
                "critical"
                if capacity_ratio >= 0.9 or disk_critical
                else "warning"
                if capacity_ratio >= 0.75 or disk_warning or wal_warning
                else "ok"
            ),
        }
        try:
            with self._lock:
                if self._conn is None:
                    raise ProviderCallLedgerUnavailable(
                        "provider-call ledger closed during summary"
                    )
                current_key = (
                    self._local_revision,
                    int(self._conn.execute("PRAGMA data_version").fetchone()[0]),
                    normalized_period,
                    period_start.timestamp() if period_start is not None else None,
                    period_end.timestamp() if period_end is not None else None,
                )
                if current_key == cache_key:
                    self._summary_cache_key = cache_key
                    self._summary_cache = copy.deepcopy(summary)
        except ProviderCallLedgerUnavailable:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise ProviderCallLedgerUnavailable(
                f"provider-call financial summary unavailable: {type(exc).__name__}"
            ) from exc
        return summary

    def close(self) -> None:
        with self._lock:
            connection, self._conn = self._conn, None
            if connection is not None:
                connection.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


_NOOP_LEDGER = NoopProviderCallLedger()
_CURRENT_CONTEXT: ContextVar[ProviderCallContext] = ContextVar(
    "nachuan_provider_call_context", default=ProviderCallContext()
)
_CONFIG_LOCK = threading.Lock()
_CONFIG_SIGNATURE: tuple[str, str, str] | None = None
_CONFIG_LEDGER: ProviderCallLedgerProtocol = _NOOP_LEDGER


@contextmanager
def bind_provider_call_context(context: ProviderCallContext) -> Iterator[None]:
    """Propagate trace/turn/workflow/role through nested async provider calls."""

    token = _CURRENT_CONTEXT.set(context)
    try:
        yield
    finally:
        _CURRENT_CONTEXT.reset(token)


def current_provider_call_context() -> ProviderCallContext:
    return _CURRENT_CONTEXT.get()


@contextmanager
def bind_provider_call_scope(
    *,
    trace_id: str | None = None,
    turn_id: str | None = None,
    workflow_id: str | None = None,
    role: str | None = None,
) -> Iterator[ProviderCallContext]:
    """Overlay business attribution while preserving the parent request trace."""

    base = current_provider_call_context()
    scoped = replace(
        base,
        trace_id=base.trace_id if trace_id is None else trace_id,
        turn_id=base.turn_id if turn_id is None else turn_id,
        workflow_id=base.workflow_id if workflow_id is None else workflow_id,
        role=base.role if role is None else role,
    )
    with bind_provider_call_context(scoped):
        yield scoped


async def start_provider_attempt_durable(
    ledger: ProviderCallLedgerProtocol,
    *,
    identity: ProviderRouteIdentity,
    context: ProviderCallContext,
    attempt: int,
    stream: bool,
    call_id: str | None = None,
    commercial_budget: CommercialBudgetAuthorization | None = None,
) -> ProviderCallAttemptProtocol:
    """Persist a pre-call claim off the event loop, even under SQLite lock wait."""

    start_fields: dict[str, Any] = {
        "identity": identity,
        "context": context,
        "attempt": attempt,
        "stream": stream,
        "call_id": call_id,
    }
    if commercial_budget is not None:
        # Preserve compatibility with narrow test/extension ledgers when the
        # explicitly configured commercial gate is not in use.
        start_fields["commercial_budget"] = commercial_budget
    task = asyncio.create_task(
        asyncio.to_thread(
            ledger.start_attempt,
            **start_fields,
        )
    )
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # The worker thread cannot be force-cancelled.  If it committed a row,
        # close it as cancelled before propagating cancellation; never leave a
        # pre-call accounting claim without a corresponding provider invocation.
        try:
            claimed = await asyncio.shield(task)
        except Exception:
            pass
        else:
            try:
                await finish_provider_attempt_durable(
                    claimed,
                    status="cancelled",
                    error_type="cancelled_before_provider_invocation",
                    error_message="request cancelled while accounting claim was being committed",
                )
            except Exception:
                pass
        raise


async def finish_provider_attempt_durable(
    provider_attempt: ProviderCallAttemptProtocol,
    *,
    status: str,
    observed_model: str | None = None,
    usage: Mapping[str, Any] | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
) -> bool:
    """Commit one terminal transition off-loop and drain it on cancellation."""

    task = asyncio.create_task(
        asyncio.to_thread(
            provider_attempt.finish,
            status=status,
            observed_model=observed_model,
            usage=usage,
            error_type=error_type,
            error_message=error_message,
        )
    )
    try:
        return bool(await asyncio.shield(task))
    except asyncio.CancelledError:
        # Shield keeps the thread-backed task alive.  Wait for the durable write
        # before allowing request cancellation to escape.
        await asyncio.shield(task)
        raise


def configured_provider_call_ledger() -> ProviderCallLedgerProtocol:
    """Resolve the process ledger; default development/test mode is no-op."""

    global _CONFIG_LEDGER, _CONFIG_SIGNATURE
    mode = str(os.getenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "off") or "off").strip().lower()
    commercial_mode = str(
        os.getenv("NACHUAN_COMMERCIAL_BUDGET_MODE", "off") or "off"
    ).strip().lower()
    if commercial_mode not in {"off", "required"}:
        raise ProviderCallLedgerUnavailable(
            "NACHUAN_COMMERCIAL_BUDGET_MODE must be off or required"
        )
    if commercial_mode == "required" and mode != "required":
        raise ProviderCallLedgerUnavailable(
            "commercial budget required mode needs provider-call ledger required mode"
        )
    path = str(
        os.getenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH")
        or os.getenv("USAGE_DB_PATH")
        or "./data/usage.db"
    )
    signature = (mode, path, commercial_mode)
    with _CONFIG_LOCK:
        if signature == _CONFIG_SIGNATURE and not bool(
            getattr(_CONFIG_LEDGER, "closed", False)
        ):
            return _CONFIG_LEDGER
        if mode == "off":
            ledger: ProviderCallLedgerProtocol = _NOOP_LEDGER
        elif mode in {"best_effort", "required"}:
            try:
                ledger = ProviderCallLedger(
                    path,
                    required=mode == "required",
                    commercial_budget_required=commercial_mode == "required",
                )
            except ProviderCallLedgerUnavailable:
                if mode == "required":
                    raise
                ledger = _NOOP_LEDGER
        else:
            raise ProviderCallLedgerUnavailable(
                "NACHUAN_PROVIDER_CALL_LEDGER_MODE must be off, best_effort, or required"
            )
        _CONFIG_SIGNATURE = signature
        _CONFIG_LEDGER = ledger
        return ledger


def resolve_provider_call_ledger(
    explicit: ProviderCallLedgerProtocol | None,
) -> ProviderCallLedgerProtocol:
    return explicit if explicit is not None else configured_provider_call_ledger()


async def resolve_provider_call_ledger_durable(
    explicit: ProviderCallLedgerProtocol | None,
) -> ProviderCallLedgerProtocol:
    """Resolve lazy SQLite configuration without blocking the event loop."""

    if explicit is not None:
        return explicit
    return await asyncio.to_thread(configured_provider_call_ledger)
