"""执行脊柱·任务台账（Plan→Execute→Reflect→Improve 里最缺的那节 Execute）。

把一个目标分解成有序步骤，每步落 SQLite（状态+产出+重试次数），逐步执行、异常捕获、
**重启可从断点续跑**——治"任务碎片化 / 无状态追踪 / 缺乏自我纠错"这三大执行缺失。

设计要点：
- 状态全在 SQLite（`data/ledger.db`），所以 `run_job` 可反复调用：done 的步骤自动跳过，
  崩溃/失败的步骤 `recover()` 后重置为 pending → 真·断点续跑。
- 执行器 `executor` 注入（`async (step) -> str`），便于测试与多后端（Codex/模型对话）。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import closing
from functools import lru_cache
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from gateway.sqlite_runtime import enable_wal_with_deadline

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planning',
  user_id TEXT DEFAULT '',
  result TEXT DEFAULT '',
  execution_spec TEXT NOT NULL DEFAULT '{}',
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_until REAL NOT NULL DEFAULT 0,
  lease_epoch INTEGER NOT NULL DEFAULT 0,
  created REAL, updated REAL
);
CREATE TABLE IF NOT EXISTS steps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  kind TEXT DEFAULT 'action',
  deps TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending',
  output TEXT DEFAULT '',
  error TEXT DEFAULT '',
  attempts INTEGER DEFAULT 0,
  lease_owner TEXT NOT NULL DEFAULT '',
  lease_until REAL NOT NULL DEFAULT 0,
  claim_token TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL DEFAULT '',
  updated REAL
);
CREATE INDEX IF NOT EXISTS ix_steps_job ON steps(job_id, idx);
"""

# Exact schema shipped by aa0025a.  It is retained as a migration authority,
# not as a permissive column checklist.  1cbc955, 72ea2a3, and 2821cc4 all
# shipped the complete schema above, so there are two distinct unversioned
# historical object generations to classify.
_LEGACY_AA0025A_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planning',
  user_id TEXT DEFAULT '',
  result TEXT DEFAULT '',
  created REAL, updated REAL
);
CREATE TABLE IF NOT EXISTS steps (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  idx INTEGER NOT NULL,
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  kind TEXT DEFAULT 'action',
  deps TEXT DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending',
  output TEXT DEFAULT '',
  error TEXT DEFAULT '',
  attempts INTEGER DEFAULT 0,
  updated REAL
);
CREATE INDEX IF NOT EXISTS ix_steps_job ON steps(job_id, idx);
"""

# Verified from the installed development authority (1 job / 2 steps): an
# aa0025a database opened by the historical ALTER-based migrator.  SQLite
# appends these columns to sqlite_master SQL in this exact order, so this is a
# distinct complete generation rather than a column-compatible wildcard.
_LEGACY_INSTALLED_APPEND_SCHEMA = _LEGACY_AA0025A_SCHEMA + """
ALTER TABLE jobs ADD COLUMN lease_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN lease_until REAL NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN lease_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN execution_spec TEXT NOT NULL DEFAULT '{}';
ALTER TABLE steps ADD COLUMN lease_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE steps ADD COLUMN lease_until REAL NOT NULL DEFAULT 0;
ALTER TABLE steps ADD COLUMN claim_token TEXT NOT NULL DEFAULT '';
ALTER TABLE steps ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT '';
"""

StepExecutor = Callable[[dict], Awaitable[str]]

_MAX_LEDGER_BYTES = 256 * 1024 * 1024
_WAL_JOURNAL_LIMIT_BYTES = 16 * 1024 * 1024
_BUSY_TIMEOUT_MS = 5_000
_PREFLIGHT_STABILIZATION_SECONDS = _BUSY_TIMEOUT_MS / 1000.0
_PREFLIGHT_RETRY_SECONDS = 0.01
_MAX_LEASE_OWNER_CHARS = 128
_MAX_LEASE_SECONDS = 24 * 60 * 60
_APPLICATION_ID = 0x4E43544C  # "NCTL"
_SCHEMA_VERSION = 3
_PREVIOUS_SCHEMA_VERSION = 2
_MAX_JOB_ROWS = 4_096
_MAX_STEP_ROWS = 65_536
_MAX_LOGICAL_PAYLOAD_BYTES = 192 * 1024 * 1024
_MAX_JOB_ID_BYTES = 128
_MAX_STEP_ID_BYTES = 128
_MAX_GOAL_BYTES = 128_000
_MAX_USER_ID_BYTES = 1_024
_MAX_EXECUTION_SPEC_BYTES = 256_000
_MAX_JOB_RESULT_BYTES = 192 * 1024
_MAX_STEP_TITLE_BYTES = 640
_MAX_STEP_DETAIL_BYTES = 8_000
_MAX_STEP_DEPS_BYTES = 2_048
_MAX_STEP_OUTPUT_BYTES = 32_000
_MAX_STEP_ERROR_BYTES = 8_000
_MAX_IDEMPOTENCY_KEY_BYTES = 256
_JOB_RESULT_RESERVATION_BYTES = _MAX_JOB_RESULT_BYTES + 8_192
_STEP_TERMINAL_RESERVATION_BYTES = (
    _MAX_STEP_OUTPUT_BYTES + _MAX_STEP_ERROR_BYTES + 8_192
)
_MAX_WAL_BYTES = 64 * 1024 * 1024
_MAX_SHM_BYTES = 16 * 1024 * 1024
_MAX_ROLLBACK_JOURNAL_BYTES = 64 * 1024 * 1024
_MAX_DATABASE_FAMILY_BYTES = (
    _MAX_LEDGER_BYTES + _MAX_WAL_BYTES + _MAX_SHM_BYTES + _MAX_ROLLBACK_JOURNAL_BYTES
)
_TERMINAL_HEADROOM_SAFETY_PAGES = 8
_TERMINAL_HEADROOM_INLINE_SLACK_PAGES = 2
_MAX_TERMINAL_HEADROOM_BYTES = 2 * 1024 * 1024
_JOB_TERMINAL_RECORD_MAX_BYTES = (
    _MAX_JOB_ID_BYTES
    + _MAX_GOAL_BYTES
    + 16  # status and serial-type slack
    + _MAX_USER_ID_BYTES
    + _MAX_JOB_RESULT_BYTES
    + _MAX_EXECUTION_SPEC_BYTES
    + (_MAX_LEASE_OWNER_CHARS * 4)
    + 32 * 1024  # row header, varints, timestamps, and b-tree cell slack
)
_STEP_TERMINAL_RECORD_MAX_BYTES = (
    _MAX_STEP_ID_BYTES
    + _MAX_JOB_ID_BYTES
    + _MAX_STEP_TITLE_BYTES
    + _MAX_STEP_DETAIL_BYTES
    + 32  # kind/status and serial-type slack
    + _MAX_STEP_DEPS_BYTES
    + _MAX_STEP_OUTPUT_BYTES
    + _MAX_STEP_ERROR_BYTES
    + (_MAX_LEASE_OWNER_CHARS * 4)
    + 128  # claim token
    + _MAX_IDEMPOTENCY_KEY_BYTES
    + 32 * 1024  # row header, varints, timestamps, and b-tree cell slack
)


class _DatabaseFamilyChanged(sqlite3.DatabaseError):
    """A read-only preflight snapshot raced a database-family transition."""


class _RollbackJournalPresent(sqlite3.DatabaseError):
    """A rollback journal may be live briefly, but is never consumed here."""


def _payload_sql(alias: str, fields: tuple[str, ...], *, fixed: int) -> str:
    terms = [str(fixed)]
    terms.extend(f"length(CAST({alias}.{field} AS BLOB))" for field in fields)
    return " + ".join(terms)


_JOB_PAYLOAD_NEW = _payload_sql(
    "NEW",
    (
        "id",
        "goal",
        "status",
        "user_id",
        "result",
        "execution_spec",
        "lease_owner",
        "result_reservation",
    ),
    fixed=512,
)
_JOB_PAYLOAD_OLD = _payload_sql(
    "OLD",
    (
        "id",
        "goal",
        "status",
        "user_id",
        "result",
        "execution_spec",
        "lease_owner",
        "result_reservation",
    ),
    fixed=512,
)
_STEP_PAYLOAD_NEW = _payload_sql(
    "NEW",
    (
        "id",
        "job_id",
        "title",
        "detail",
        "kind",
        "deps",
        "status",
        "output",
        "error",
        "lease_owner",
        "claim_token",
        "idempotency_key",
        "terminal_reservation",
    ),
    fixed=512,
)
_STEP_PAYLOAD_OLD = _payload_sql(
    "OLD",
    (
        "id",
        "job_id",
        "title",
        "detail",
        "kind",
        "deps",
        "status",
        "output",
        "error",
        "lease_owner",
        "claim_token",
        "idempotency_key",
        "terminal_reservation",
    ),
    fixed=512,
)


_CURRENT_JOBS_DDL = f"""
CREATE TABLE jobs (
  id TEXT PRIMARY KEY CHECK(typeof(id)='text' AND length(CAST(id AS BLOB)) BETWEEN 1 AND {_MAX_JOB_ID_BYTES}),
  goal TEXT NOT NULL CHECK(typeof(goal)='text' AND length(CAST(goal AS BLOB)) BETWEEN 1 AND {_MAX_GOAL_BYTES}),
  status TEXT NOT NULL DEFAULT 'planning' CHECK(status IN ('planning','running','failed','done','paused')),
  user_id TEXT NOT NULL DEFAULT '' CHECK(typeof(user_id)='text' AND length(CAST(user_id AS BLOB))<={_MAX_USER_ID_BYTES}),
  result TEXT NOT NULL DEFAULT '' CHECK(typeof(result)='text' AND length(CAST(result AS BLOB))<={_MAX_JOB_RESULT_BYTES}),
  execution_spec TEXT NOT NULL DEFAULT '{{}}' CHECK(typeof(execution_spec)='text' AND length(CAST(execution_spec AS BLOB)) BETWEEN 2 AND {_MAX_EXECUTION_SPEC_BYTES}),
  lease_owner TEXT NOT NULL DEFAULT '' CHECK(typeof(lease_owner)='text' AND length(CAST(lease_owner AS BLOB))<={_MAX_LEASE_OWNER_CHARS * 4}),
  lease_until REAL NOT NULL DEFAULT 0 CHECK(typeof(lease_until) IN ('integer','real') AND lease_until>=0 AND lease_until<=9007199254740991),
  lease_epoch INTEGER NOT NULL DEFAULT 0 CHECK(typeof(lease_epoch)='integer' AND lease_epoch>=0),
  created REAL CHECK(created IS NULL OR (typeof(created) IN ('integer','real') AND created>=0)),
  updated REAL CHECK(updated IS NULL OR (typeof(updated) IN ('integer','real') AND updated>=0)),
  result_reservation BLOB NOT NULL DEFAULT X'' CHECK(typeof(result_reservation)='blob' AND length(result_reservation) IN (0,{_JOB_RESULT_RESERVATION_BYTES}))
)
""".strip()

_CURRENT_STEPS_DDL = f"""
CREATE TABLE steps (
  id TEXT PRIMARY KEY CHECK(typeof(id)='text' AND length(CAST(id AS BLOB)) BETWEEN 1 AND {_MAX_STEP_ID_BYTES}),
  job_id TEXT NOT NULL CHECK(typeof(job_id)='text' AND length(CAST(job_id AS BLOB)) BETWEEN 1 AND {_MAX_JOB_ID_BYTES}),
  idx INTEGER NOT NULL CHECK(typeof(idx)='integer' AND idx>=0 AND idx<100),
  title TEXT NOT NULL CHECK(typeof(title)='text' AND length(CAST(title AS BLOB)) BETWEEN 1 AND {_MAX_STEP_TITLE_BYTES}),
  detail TEXT NOT NULL DEFAULT '' CHECK(typeof(detail)='text' AND length(CAST(detail AS BLOB))<={_MAX_STEP_DETAIL_BYTES}),
  kind TEXT NOT NULL DEFAULT 'action' CHECK(kind IN ('action','reason')),
  deps TEXT NOT NULL DEFAULT '[]' CHECK(typeof(deps)='text' AND length(CAST(deps AS BLOB)) BETWEEN 2 AND {_MAX_STEP_DEPS_BYTES}),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','failed','done')),
  output TEXT NOT NULL DEFAULT '' CHECK(typeof(output)='text' AND length(CAST(output AS BLOB))<={_MAX_STEP_OUTPUT_BYTES}),
  error TEXT NOT NULL DEFAULT '' CHECK(typeof(error)='text' AND length(CAST(error AS BLOB))<={_MAX_STEP_ERROR_BYTES}),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(typeof(attempts)='integer' AND attempts>=0 AND attempts<=1000000),
  lease_owner TEXT NOT NULL DEFAULT '' CHECK(typeof(lease_owner)='text' AND length(CAST(lease_owner AS BLOB))<={_MAX_LEASE_OWNER_CHARS * 4}),
  lease_until REAL NOT NULL DEFAULT 0 CHECK(typeof(lease_until) IN ('integer','real') AND lease_until>=0 AND lease_until<=9007199254740991),
  claim_token TEXT NOT NULL DEFAULT '' CHECK(typeof(claim_token)='text' AND length(CAST(claim_token AS BLOB))<=128),
  idempotency_key TEXT NOT NULL CHECK(typeof(idempotency_key)='text' AND length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND {_MAX_IDEMPOTENCY_KEY_BYTES}),
  updated REAL CHECK(updated IS NULL OR (typeof(updated) IN ('integer','real') AND updated>=0)),
  terminal_reservation BLOB NOT NULL DEFAULT X'' CHECK(typeof(terminal_reservation)='blob' AND length(terminal_reservation) IN (0,{_STEP_TERMINAL_RESERVATION_BYTES}))
)
""".strip()

_CURRENT_CAPACITY_DDL = f"""
CREATE TABLE ledger_capacity (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  job_rows INTEGER NOT NULL CHECK(job_rows BETWEEN 0 AND {_MAX_JOB_ROWS}),
  step_rows INTEGER NOT NULL CHECK(step_rows BETWEEN 0 AND {_MAX_STEP_ROWS}),
  payload_bytes INTEGER NOT NULL CHECK(payload_bytes BETWEEN 0 AND {_MAX_LOGICAL_PAYLOAD_BYTES})
) WITHOUT ROWID
""".strip()

_CURRENT_INDEX_DDL = "CREATE UNIQUE INDEX ix_steps_job ON steps(job_id, idx)"

_CURRENT_TRIGGER_DDLS = (
    f"""CREATE TRIGGER trg_jobs_capacity_before_insert BEFORE INSERT ON jobs
WHEN (SELECT COUNT(*) FROM ledger_capacity WHERE singleton=1)<>1
  OR (SELECT job_rows FROM ledger_capacity WHERE singleton=1)>={_MAX_JOB_ROWS}
  OR (SELECT payload_bytes FROM ledger_capacity WHERE singleton=1)+({_JOB_PAYLOAD_NEW})>{_MAX_LOGICAL_PAYLOAD_BYTES}
BEGIN
  SELECT RAISE(ABORT,'TaskLedger job capacity exceeded');
END""",
    f"""CREATE TRIGGER trg_jobs_capacity_after_insert AFTER INSERT ON jobs
BEGIN
  UPDATE ledger_capacity SET job_rows=job_rows+1,payload_bytes=payload_bytes+({_JOB_PAYLOAD_NEW}) WHERE singleton=1;
END""",
    f"""CREATE TRIGGER trg_jobs_capacity_before_update BEFORE UPDATE OF status,result,lease_owner,result_reservation,updated ON jobs
WHEN (SELECT COUNT(*) FROM ledger_capacity WHERE singleton=1)<>1
  OR (SELECT payload_bytes FROM ledger_capacity WHERE singleton=1)-({_JOB_PAYLOAD_OLD})+({_JOB_PAYLOAD_NEW})>{_MAX_LOGICAL_PAYLOAD_BYTES}
BEGIN
  SELECT RAISE(ABORT,'TaskLedger job payload capacity exceeded');
END""",
    f"""CREATE TRIGGER trg_jobs_capacity_after_update AFTER UPDATE OF status,result,lease_owner,result_reservation,updated ON jobs
BEGIN
  UPDATE ledger_capacity SET payload_bytes=payload_bytes-({_JOB_PAYLOAD_OLD})+({_JOB_PAYLOAD_NEW}) WHERE singleton=1;
END""",
    """CREATE TRIGGER trg_jobs_execution_spec_immutable BEFORE UPDATE OF id,goal,user_id,execution_spec,created ON jobs
WHEN NEW.id IS NOT OLD.id OR NEW.goal IS NOT OLD.goal OR NEW.user_id IS NOT OLD.user_id OR NEW.execution_spec IS NOT OLD.execution_spec OR NEW.created IS NOT OLD.created
BEGIN
  SELECT RAISE(ABORT,'TaskLedger execution specification is immutable');
END""",
    """CREATE TRIGGER trg_jobs_delete_guard BEFORE DELETE ON jobs
WHEN EXISTS(SELECT 1 FROM steps WHERE job_id=OLD.id)
BEGIN
  SELECT RAISE(ABORT,'TaskLedger job still owns steps');
END""",
    f"""CREATE TRIGGER trg_jobs_capacity_after_delete AFTER DELETE ON jobs
BEGIN
  UPDATE ledger_capacity SET job_rows=job_rows-1,payload_bytes=payload_bytes-({_JOB_PAYLOAD_OLD}) WHERE singleton=1;
END""",
    f"""CREATE TRIGGER trg_steps_capacity_before_insert BEFORE INSERT ON steps
WHEN (SELECT COUNT(*) FROM ledger_capacity WHERE singleton=1)<>1
  OR (SELECT step_rows FROM ledger_capacity WHERE singleton=1)>={_MAX_STEP_ROWS}
  OR (SELECT COUNT(*) FROM steps WHERE job_id=NEW.job_id)>=100
  OR NOT EXISTS(SELECT 1 FROM jobs WHERE id=NEW.job_id)
  OR (SELECT payload_bytes FROM ledger_capacity WHERE singleton=1)+({_STEP_PAYLOAD_NEW})>{_MAX_LOGICAL_PAYLOAD_BYTES}
BEGIN
  SELECT RAISE(ABORT,'TaskLedger step capacity exceeded');
END""",
    f"""CREATE TRIGGER trg_steps_capacity_after_insert AFTER INSERT ON steps
BEGIN
  UPDATE ledger_capacity SET step_rows=step_rows+1,payload_bytes=payload_bytes+({_STEP_PAYLOAD_NEW}) WHERE singleton=1;
END""",
    f"""CREATE TRIGGER trg_steps_capacity_before_update BEFORE UPDATE OF status,output,error,attempts,lease_owner,lease_until,claim_token,updated,terminal_reservation ON steps
WHEN (SELECT COUNT(*) FROM ledger_capacity WHERE singleton=1)<>1
  OR (SELECT payload_bytes FROM ledger_capacity WHERE singleton=1)-({_STEP_PAYLOAD_OLD})+({_STEP_PAYLOAD_NEW})>{_MAX_LOGICAL_PAYLOAD_BYTES}
BEGIN
  SELECT RAISE(ABORT,'TaskLedger step payload capacity exceeded');
END""",
    f"""CREATE TRIGGER trg_steps_capacity_after_update AFTER UPDATE OF status,output,error,attempts,lease_owner,lease_until,claim_token,updated,terminal_reservation ON steps
BEGIN
  UPDATE ledger_capacity SET payload_bytes=payload_bytes-({_STEP_PAYLOAD_OLD})+({_STEP_PAYLOAD_NEW}) WHERE singleton=1;
END""",
    """CREATE TRIGGER trg_steps_definition_immutable BEFORE UPDATE OF id,job_id,idx,title,detail,kind,deps,idempotency_key ON steps
WHEN NEW.id IS NOT OLD.id OR NEW.job_id IS NOT OLD.job_id OR NEW.idx IS NOT OLD.idx OR NEW.title IS NOT OLD.title OR NEW.detail IS NOT OLD.detail OR NEW.kind IS NOT OLD.kind OR NEW.deps IS NOT OLD.deps OR NEW.idempotency_key IS NOT OLD.idempotency_key
BEGIN
  SELECT RAISE(ABORT,'TaskLedger step definition is immutable');
END""",
    f"""CREATE TRIGGER trg_steps_capacity_after_delete AFTER DELETE ON steps
BEGIN
  UPDATE ledger_capacity SET step_rows=step_rows-1,payload_bytes=payload_bytes-({_STEP_PAYLOAD_OLD}) WHERE singleton=1;
END""",
    """CREATE TRIGGER trg_capacity_no_delete BEFORE DELETE ON ledger_capacity
BEGIN
  SELECT RAISE(ABORT,'TaskLedger capacity authority cannot be deleted');
END""",
)

_CURRENT_SCHEMA_DDLS = (
    _CURRENT_JOBS_DDL,
    _CURRENT_STEPS_DDL,
    _CURRENT_CAPACITY_DDL,
    _CURRENT_INDEX_DDL,
    *_CURRENT_TRIGGER_DDLS,
)

# Schema v2 stored a zeroblob in the same row that would later receive the
# terminal text.  SQLite may allocate the replacement cell/overflow chain
# before reclaiming that blob, so those bytes are not terminal write headroom.
# Keep the exact generation as an explicit migration authority.
_V2_SCHEMA_DDLS = _CURRENT_SCHEMA_DDLS

_CURRENT_HEADROOM_DDL = f"""
CREATE TABLE ledger_terminal_headroom (
  kind TEXT NOT NULL CHECK(kind IN ('job','step')),
  owner_id TEXT NOT NULL CHECK(typeof(owner_id)='text' AND length(CAST(owner_id AS BLOB)) BETWEEN 1 AND {_MAX_JOB_ID_BYTES}),
  reserved_pages INTEGER NOT NULL CHECK(typeof(reserved_pages)='integer' AND reserved_pages BETWEEN 1 AND 4096),
  payload BLOB NOT NULL CHECK(typeof(payload)='blob' AND length(payload) BETWEEN 1 AND {_MAX_TERMINAL_HEADROOM_BYTES}),
  PRIMARY KEY(kind,owner_id)
) WITHOUT ROWID
""".strip()

_HEADROOM_PAYLOAD_NEW = (
    "256 + length(CAST(NEW.kind AS BLOB)) + "
    "length(CAST(NEW.owner_id AS BLOB)) + length(NEW.payload)"
)
_HEADROOM_PAYLOAD_OLD = (
    "256 + length(CAST(OLD.kind AS BLOB)) + "
    "length(CAST(OLD.owner_id AS BLOB)) + length(OLD.payload)"
)
_CURRENT_HEADROOM_TRIGGER_DDLS = (
    f"""CREATE TRIGGER trg_terminal_headroom_before_insert BEFORE INSERT ON ledger_terminal_headroom
WHEN (SELECT COUNT(*) FROM ledger_capacity WHERE singleton=1)<>1
  OR (SELECT payload_bytes FROM ledger_capacity WHERE singleton=1)+({_HEADROOM_PAYLOAD_NEW})>{_MAX_LOGICAL_PAYLOAD_BYTES}
  OR (NEW.kind='job' AND NOT EXISTS(SELECT 1 FROM jobs WHERE id=NEW.owner_id AND status IN ('planning','running')))
  OR (NEW.kind='step' AND NOT EXISTS(SELECT 1 FROM steps WHERE id=NEW.owner_id AND status='running'))
BEGIN
  SELECT RAISE(ABORT,'TaskLedger terminal headroom capacity or owner is invalid');
END""",
    f"""CREATE TRIGGER trg_terminal_headroom_after_insert AFTER INSERT ON ledger_terminal_headroom
BEGIN
  UPDATE ledger_capacity SET payload_bytes=payload_bytes+({_HEADROOM_PAYLOAD_NEW}) WHERE singleton=1;
END""",
    """CREATE TRIGGER trg_terminal_headroom_immutable BEFORE UPDATE ON ledger_terminal_headroom
BEGIN
  SELECT RAISE(ABORT,'TaskLedger terminal headroom is immutable');
END""",
    f"""CREATE TRIGGER trg_terminal_headroom_after_delete AFTER DELETE ON ledger_terminal_headroom
BEGIN
  UPDATE ledger_capacity SET payload_bytes=payload_bytes-({_HEADROOM_PAYLOAD_OLD}) WHERE singleton=1;
END""",
)

_CURRENT_SCHEMA_DDLS = (
    *_V2_SCHEMA_DDLS,
    _CURRENT_HEADROOM_DDL,
    *_CURRENT_HEADROOM_TRIGGER_DDLS,
)


def _schema_sql(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise sqlite3.DatabaseError("TaskLedger schema SQL is missing")
    return value


def _materialize_schema(script: str) -> dict[tuple[str, str, str], str | None]:
    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        reference.executescript(script)
        return {
            (str(row[0]), str(row[1]), str(row[2])): _schema_sql(row[3])
            for row in reference.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name"
            ).fetchall()
        }
    finally:
        reference.close()


@lru_cache(maxsize=1)
def _legacy_schema_generations() -> dict[
    str, dict[tuple[str, str, str], str | None]
]:
    return {
        "aa0025a": _materialize_schema(_LEGACY_AA0025A_SCHEMA),
        "installed-lease-append": _materialize_schema(
            _LEGACY_INSTALLED_APPEND_SCHEMA
        ),
        "1cbc955/72ea2a3/2821cc4": _materialize_schema(_SCHEMA),
    }


@lru_cache(maxsize=1)
def _expected_current_schema() -> dict[tuple[str, str, str], str | None]:
    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        for ddl in _CURRENT_SCHEMA_DDLS:
            reference.execute(ddl)
        return {
            (str(row[0]), str(row[1]), str(row[2])): _schema_sql(row[3])
            for row in reference.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name"
            ).fetchall()
        }
    finally:
        reference.close()


@lru_cache(maxsize=1)
def _expected_v2_schema() -> dict[tuple[str, str, str], str | None]:
    reference = sqlite3.connect(":memory:", isolation_level=None)
    try:
        for ddl in _V2_SCHEMA_DDLS:
            reference.execute(ddl)
        return {
            (str(row[0]), str(row[1]), str(row[2])): _schema_sql(row[3])
            for row in reference.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name"
            ).fetchall()
        }
    finally:
        reference.close()


def _terminal_headroom_spec(
    connection: sqlite3.Connection, kind: str
) -> tuple[int, int]:
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    if page_size < 512 or page_size > 65_536 or page_size & (page_size - 1):
        raise sqlite3.DatabaseError("TaskLedger SQLite page size is unsupported")
    if kind == "job":
        terminal_bytes = _JOB_TERMINAL_RECORD_MAX_BYTES
    elif kind == "step":
        terminal_bytes = _STEP_TERMINAL_RECORD_MAX_BYTES
    else:
        raise sqlite3.DatabaseError("TaskLedger terminal headroom kind is invalid")
    required_pages = (
        (terminal_bytes + page_size - 1) // page_size
        + _TERMINAL_HEADROOM_SAFETY_PAGES
    )
    blob_bytes = (
        required_pages + _TERMINAL_HEADROOM_INLINE_SLACK_PAGES
    ) * page_size
    if blob_bytes > _MAX_TERMINAL_HEADROOM_BYTES:
        raise sqlite3.DatabaseError("TaskLedger terminal headroom is unrepresentable")
    return required_pages, blob_bytes


def _validated_lease_owner(owner: Any) -> str:
    if not isinstance(owner, str) or not owner or len(owner) > _MAX_LEASE_OWNER_CHARS:
        raise ValueError("lease owner must be a non-empty bounded string")
    if owner != owner.strip() or not owner.isprintable():
        raise ValueError("lease owner must not contain whitespace padding or controls")
    return owner


def _validated_lease_seconds(value: Any) -> float:
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("lease seconds must be a finite positive number") from exc
    if not math.isfinite(seconds) or seconds <= 0 or seconds > _MAX_LEASE_SECONDS:
        raise ValueError("lease seconds must be a finite positive number")
    return max(seconds, 0.05)


def _validated_epoch(epoch: Any) -> int:
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch <= 0:
        raise ValueError("lease epoch must be a positive integer")
    return epoch


def _validated_claim_token(token: Any) -> str:
    if not isinstance(token, str) or not token or len(token) > 128:
        raise ValueError("claim token must be a non-empty bounded string")
    return token


def _bounded_text(value: Any, field: str, max_bytes: int) -> str:
    text = str(value)
    if len(text.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field} exceeds its UTF-8 byte limit")
    return text


def _truncate_utf8(value: Any, max_bytes: int) -> str:
    encoded = str(value).encode("utf-8")
    if len(encoded) <= max_bytes:
        return str(value)
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _normalise_execution_steps(steps: Any) -> list[dict[str, Any]]:
    """Return the immutable, JSON-safe step definitions used by a job.

    Runtime fields (status/output/attempts/leases) deliberately do not belong to the
    execution specification. Dependencies may only point backwards, which prevents a
    malformed client plan from creating an un-runnable cycle.
    """
    if not isinstance(steps, list) or not steps:
        raise ValueError("execution spec requires at least one step")
    if len(steps) > 100:
        raise ValueError("execution spec supports at most 100 steps")
    out: list[dict[str, Any]] = []
    for i, raw in enumerate(steps):
        if not isinstance(raw, dict):
            raise ValueError(f"step {i + 1} must be an object")
        title = str(raw.get("title") or f"步骤{i + 1}")[:160]
        detail = str(raw.get("detail") or "")[:2000]
        kind = "reason" if raw.get("kind") == "reason" else "action"
        deps_raw = raw.get("deps")
        if deps_raw is None:
            deps = [i - 1] if i else []
        else:
            if not isinstance(deps_raw, list):
                raise ValueError(f"step {i + 1} deps must be an array")
            deps = []
            for dep in deps_raw:
                if isinstance(dep, bool) or not isinstance(dep, int) or dep < 0 or dep >= i:
                    raise ValueError(f"step {i + 1} has an invalid dependency")
                if dep not in deps:
                    deps.append(dep)
        out.append({"title": title, "detail": detail, "kind": kind, "deps": deps})
    return out


def freeze_execution_spec(
    *,
    goal: str,
    steps: Any,
    workdir: str,
    backend: str,
    mode: str,
) -> dict[str, Any]:
    """Build a canonical, hash-bound job specification.

    This is the authority consumed after approval and by resume. Request bodies are
    never allowed to replace any of these fields once the specification is frozen.
    """
    backend_norm = str(backend or "auto").strip().lower()
    mode_norm = str(mode or "plan").strip().lower()
    if backend_norm not in {"auto", "codex"}:
        raise ValueError("backend must be auto or codex")
    if mode_norm not in {"plan", "auto", "full"}:
        raise ValueError("mode must be plan, auto, or full")
    base: dict[str, Any] = {
        "version": 1,
        "goal": str(goal or "").strip(),
        "steps": _normalise_execution_steps(steps),
        "workdir": os.path.realpath(str(workdir)) if str(workdir or "").strip() else "",
        "backend": backend_norm,
        "mode": mode_norm,
    }
    if not base["goal"]:
        raise ValueError("execution spec requires a goal")
    if len(base["goal"]) > 32_000:
        raise ValueError("execution spec goal exceeds 32KB")
    encoded = json.dumps(base, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 256_000:
        raise ValueError("execution spec exceeds 256KB")
    return {**base, "manifest_hash": hashlib.sha256(encoded.encode("utf-8")).hexdigest()}


def validate_execution_spec(raw: Any) -> dict[str, Any]:
    """Validate and canonicalise a previously frozen execution specification."""
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError("missing or unsupported execution spec")
    frozen = freeze_execution_spec(
        goal=str(raw.get("goal") or ""),
        steps=raw.get("steps"),
        workdir=str(raw.get("workdir") or ""),
        backend=str(raw.get("backend") or ""),
        mode=str(raw.get("mode") or ""),
    )
    if str(raw.get("manifest_hash") or "") != frozen["manifest_hash"]:
        raise ValueError("execution spec manifest hash mismatch")
    return frozen


class _ReaderLease:
    """A query-only snapshot that retains the TaskLedger lifecycle fence."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        release_lifecycle: Callable[[], None],
    ) -> None:
        self._connection = connection
        self._release_lifecycle = release_lifecycle
        self._closed = False

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        return self._connection.execute(sql, parameters)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._connection.close()
        finally:
            self._release_lifecycle()


class TaskLedger:
    """多步任务的持久化台账。"""

    def __init__(self, path: str | Path = "data/ledger.db") -> None:
        self.path = os.path.abspath(os.fspath(path))
        self._assert_database_path(require_main=False)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._assert_database_path(require_main=False)
        # One writer connection is serialized in-process. Reads intentionally use
        # short-lived, query-only connections so a lease heartbeat never blocks job
        # status polling and no reader can observe this connection's uncommitted state.
        self._write_lock = threading.RLock()
        self._reader_condition = threading.Condition()
        self._active_readers = 0
        self._closed = False
        self._db = self._open_authority_writer()

    @staticmethod
    def _is_reparse_or_symlink(info: os.stat_result) -> bool:
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return stat.S_ISLNK(info.st_mode) or bool(
            int(getattr(info, "st_file_attributes", 0)) & reparse_flag
        )

    def _assert_database_path(self, *, require_main: bool) -> None:
        lexical = Path(self.path)
        for component in reversed([lexical.parent, *lexical.parent.parents]):
            try:
                info = os.lstat(component)
            except FileNotFoundError:
                continue
            if self._is_reparse_or_symlink(info) or not stat.S_ISDIR(info.st_mode):
                raise OSError("TaskLedger path components must be real directories")
        for candidate in (
            lexical,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
            Path(f"{self.path}-journal"),
        ):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                if require_main and candidate == lexical:
                    raise OSError("TaskLedger database is missing")
                continue
            if self._is_reparse_or_symlink(info) or not stat.S_ISREG(info.st_mode):
                raise OSError("TaskLedger database files must be regular non-reparse files")

    def _database_path_identity(self) -> tuple[int, int]:
        self._assert_database_path(require_main=True)
        info = os.lstat(self.path)
        return int(info.st_dev), int(info.st_ino)

    def _database_family_presence(self) -> dict[str, bool]:
        self._assert_database_path(require_main=False)
        presence: dict[str, bool] = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                os.lstat(f"{self.path}{suffix}")
            except FileNotFoundError:
                presence[suffix] = False
            else:
                presence[suffix] = True
        return presence

    def _assert_live_database_identity(self) -> None:
        if self._database_path_identity() != self._database_identity:
            raise sqlite3.DatabaseError("TaskLedger database pathname identity changed")

    @staticmethod
    def _schema_snapshot(
        connection: sqlite3.Connection,
    ) -> dict[tuple[str, str, str], str | None]:
        return {
            (str(row[0]), str(row[1]), str(row[2])): _schema_sql(row[3])
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "ORDER BY type,name,tbl_name"
            ).fetchall()
        }

    def _assert_database_family_bounds(self) -> None:
        limits = {
            "": _MAX_LEDGER_BYTES,
            "-wal": _MAX_WAL_BYTES,
            "-shm": _MAX_SHM_BYTES,
            "-journal": _MAX_ROLLBACK_JOURNAL_BYTES,
        }
        total = 0
        for suffix, limit in limits.items():
            candidate = Path(f"{self.path}{suffix}")
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                continue
            size = int(info.st_size)
            if (
                self._is_reparse_or_symlink(info)
                or not stat.S_ISREG(info.st_mode)
                or size > limit
            ):
                raise sqlite3.DatabaseError(
                    "TaskLedger database family exceeds its bounded profile"
                )
            total += size
        if total > _MAX_DATABASE_FAMILY_BYTES:
            raise sqlite3.DatabaseError(
                "TaskLedger database family exceeds its total byte limit"
            )

    def _classify_database(self, connection: sqlite3.Connection) -> str:
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        actual = self._schema_snapshot(connection)
        if application_id == 0 and user_version == 0:
            if not actual:
                return "empty"
            for generation, expected in _legacy_schema_generations().items():
                if actual == expected:
                    return f"legacy:{generation}"
            raise sqlite3.DatabaseError(
                "TaskLedger database is incompatible, partial, or mixed"
            )
        if (
            application_id == _APPLICATION_ID
            and user_version == _PREVIOUS_SCHEMA_VERSION
        ):
            self._validate_v2_database(connection)
            return "legacy:current-v2"
        if application_id == _APPLICATION_ID and user_version == _SCHEMA_VERSION:
            self._validate_current_database(connection)
            return "current"
        raise sqlite3.DatabaseError("TaskLedger database identity is incompatible")

    def _preflight_database_kind(self) -> tuple[str, tuple[int, int] | None]:
        path = Path(self.path)
        presence = self._database_family_presence()
        if not presence[""]:
            if any(presence[suffix] for suffix in ("-wal", "-shm", "-journal")):
                raise sqlite3.DatabaseError(
                    "TaskLedger main database is missing beside orphan sidecars"
                )
            self._preflight_family_presence = presence
            return "missing", None
        if presence["-journal"]:
            raise _RollbackJournalPresent(
                "TaskLedger rollback journal requires explicit forensic recovery"
            )
        if presence["-wal"] != presence["-shm"]:
            raise sqlite3.DatabaseError(
                "TaskLedger WAL and SHM sidecars must be present together"
            )
        identity = self._database_path_identity()
        self._assert_database_family_bounds()
        uri = f"{path.as_uri()}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        try:
            connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            kind = self._classify_database(connection)
            presence_after = self._database_family_presence()
            if presence_after != presence:
                raise _DatabaseFamilyChanged(
                    "TaskLedger database family changed during immutable preflight"
                )
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "TaskLedger path changed during immutable preflight"
                )
        finally:
            connection.close()

        if presence_after["-wal"]:
            # immutable=1 deliberately ignores WAL.  A complete WAL+SHM pair
            # must therefore be classified through a read-only SQLite snapshot
            # before any read-write handle can recover or checkpoint it.  This
            # accepts an exact committed migration/provisioning transaction in
            # WAL while an unknown logical schema remains mutation-free.
            wal_uri = f"{path.as_uri()}?mode=ro"
            connection = sqlite3.connect(wal_uri, uri=True, isolation_level=None)
            try:
                connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("BEGIN")
                try:
                    kind = self._classify_database(connection)
                finally:
                    connection.rollback()
            finally:
                connection.close()
            presence_after_wal = self._database_family_presence()
            if presence_after_wal != presence_after:
                raise _DatabaseFamilyChanged(
                    "TaskLedger database family changed during WAL-aware preflight"
                )
            if self._database_path_identity() != identity:
                raise sqlite3.DatabaseError(
                    "TaskLedger path changed during WAL-aware preflight"
                )
            presence_after = presence_after_wal

        self._preflight_family_presence = presence_after
        return kind, identity

    def _stabilized_preflight_database_kind(
        self,
    ) -> tuple[str, tuple[int, int] | None]:
        last_change: sqlite3.DatabaseError | None = None
        deadline = time.monotonic() + _PREFLIGHT_STABILIZATION_SECONDS
        while True:
            try:
                return self._preflight_database_kind()
            except (_DatabaseFamilyChanged, _RollbackJournalPresent) as exc:
                # A peer may have completed a valid cold start between the two
                # read-only family snapshots, or may still own a transient
                # rollback journal. Reclassify from the beginning; never open
                # RW merely to decide whether the transition is legitimate.
                # A persistent or adversarial journal remains untouched and is
                # rejected at the same bounded deadline.
                last_change = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(_PREFLIGHT_RETRY_SECONDS, remaining))
        if isinstance(last_change, _RollbackJournalPresent):
            raise sqlite3.DatabaseError(str(last_change)) from last_change
        raise sqlite3.DatabaseError(
            "TaskLedger database family did not stabilize during preflight"
        ) from last_change

    def _open_authority_writer(self) -> sqlite3.Connection:
        preflight_kind, preflight_identity = (
            self._stabilized_preflight_database_kind()
        )
        presence_before_writer = self._database_family_presence()
        if presence_before_writer != self._preflight_family_presence:
            # Re-run the immutable classifier so any family member arriving or
            # disappearing after the first snapshot cannot be consumed by the
            # writer open below.
            preflight_kind, preflight_identity = (
                self._stabilized_preflight_database_kind()
            )
        connection = sqlite3.connect(
            self.path,
            timeout=_BUSY_TIMEOUT_MS / 1000.0,
            check_same_thread=False,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            self._assert_database_path(require_main=True)
            opened_identity = self._database_path_identity()
            if preflight_identity is not None and opened_identity != preflight_identity:
                raise sqlite3.DatabaseError(
                    "TaskLedger path changed between preflight and locked open"
                )
            connection.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE")
            try:
                locked_kind = self._classify_database(connection)
                if preflight_kind in {"missing", "empty"}:
                    if locked_kind == "empty":
                        self._provision_current(connection)
                    elif locked_kind != "current":
                        raise sqlite3.DatabaseError(
                            "TaskLedger changed during cold-start provisioning"
                        )
                elif preflight_kind.startswith("legacy:"):
                    if locked_kind == preflight_kind:
                        self._migrate_legacy_database(connection, locked_kind)
                    elif locked_kind != "current":
                        raise sqlite3.DatabaseError(
                            "TaskLedger changed during legacy migration"
                        )
                elif preflight_kind == "current":
                    if locked_kind != "current":
                        raise sqlite3.DatabaseError(
                            "TaskLedger changed during current-schema open"
                        )
                else:
                    raise sqlite3.DatabaseError("unsupported TaskLedger preflight state")
                self._validate_current_identity(connection)
                connection.commit()
            except Exception:
                connection.rollback()
                raise

            # WAL is persistent and cannot be rolled back.  It is changed only
            # after exact identity/schema acceptance under the write lock.
            enable_wal_with_deadline(
                connection,
                error_message="TaskLedger requires SQLite WAL mode",
            )
            self._apply_storage_profile(connection)
            self._validate_current_identity(connection)
            self._assert_database_family_bounds()
            if self._database_path_identity() != opened_identity:
                raise sqlite3.DatabaseError(
                    "TaskLedger path changed while opening the authority"
                )
            self._database_identity = opened_identity
            self._trusted_data_version = int(
                connection.execute("PRAGMA data_version").fetchone()[0]
            )
            self._trusted_schema_version = int(
                connection.execute("PRAGMA schema_version").fetchone()[0]
            )
            return connection
        except Exception:
            connection.close()
            raise

    def _provision_current(self, connection: sqlite3.Connection) -> None:
        if self._schema_snapshot(connection):
            raise sqlite3.DatabaseError("TaskLedger provisioning requires an empty database")
        for ddl in _CURRENT_SCHEMA_DDLS:
            connection.execute(ddl)
        connection.execute(
            "INSERT INTO ledger_capacity(singleton,job_rows,step_rows,payload_bytes) "
            "VALUES(1,0,0,0)"
        )
        connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        self._validate_current_identity(connection)

    def _migrate_legacy_database(
        self, connection: sqlite3.Connection, generation: str
    ) -> None:
        if generation == "legacy:current-v2":
            self._migrate_current_v2_database(connection)
            return
        self._validate_legacy_rows(connection, generation)
        connection.execute("DROP INDEX ix_steps_job")
        connection.execute("ALTER TABLE jobs RENAME TO jobs_legacy")
        connection.execute("ALTER TABLE steps RENAME TO steps_legacy")
        for ddl in _CURRENT_SCHEMA_DDLS:
            connection.execute(ddl)
        connection.execute(
            "INSERT INTO ledger_capacity(singleton,job_rows,step_rows,payload_bytes) "
            "VALUES(1,0,0,0)"
        )
        if generation == "legacy:aa0025a":
            connection.execute(
                "INSERT INTO jobs(id,goal,status,user_id,result,execution_spec,"
                "lease_owner,lease_until,lease_epoch,created,updated,result_reservation) "
                "SELECT id,goal,status,user_id,result,'{}','',0,0,created,updated,X'' "
                "FROM jobs_legacy"
            )
            connection.execute(
                "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,output,error,"
                "attempts,lease_owner,lease_until,claim_token,idempotency_key,updated,terminal_reservation) "
                "SELECT id,job_id,idx,title,detail,kind,deps,status,output,error,attempts,"
                "'',0,'',job_id || ':' || id,updated,X'' FROM steps_legacy"
            )
        else:
            connection.execute(
                "INSERT INTO jobs(id,goal,status,user_id,result,execution_spec,"
                "lease_owner,lease_until,lease_epoch,created,updated,result_reservation) "
                "SELECT id,goal,status,user_id,result,execution_spec,lease_owner,lease_until,"
                "lease_epoch,created,updated,X'' FROM jobs_legacy"
            )
            connection.execute(
                "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,output,error,"
                "attempts,lease_owner,lease_until,claim_token,idempotency_key,updated,terminal_reservation) "
                "SELECT id,job_id,idx,title,detail,kind,deps,status,output,error,attempts,"
                "lease_owner,lease_until,claim_token,"
                "CASE WHEN idempotency_key='' THEN job_id || ':' || id ELSE idempotency_key END,"
                "updated,X'' FROM steps_legacy"
            )
        connection.execute("DROP TABLE steps_legacy")
        connection.execute("DROP TABLE jobs_legacy")
        connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        self._populate_required_terminal_headroom_locked(connection)
        self._validate_current_identity(connection)

    def _migrate_current_v2_database(self, connection: sqlite3.Connection) -> None:
        self._validate_v2_database(connection)
        # Retire the same-row blobs before allocating independent pages.  Their
        # freed overflow pages can fund the v3 reservation transaction itself.
        connection.execute("UPDATE jobs SET result_reservation=X''")
        connection.execute("UPDATE steps SET terminal_reservation=X''")
        connection.execute(_CURRENT_HEADROOM_DDL)
        for ddl in _CURRENT_HEADROOM_TRIGGER_DDLS:
            connection.execute(ddl)
        self._populate_required_terminal_headroom_locked(connection)
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        self._validate_current_identity(connection)

    def _populate_required_terminal_headroom_locked(
        self, connection: sqlite3.Connection
    ) -> None:
        for row in connection.execute(
            "SELECT id FROM jobs WHERE status IN ('planning','running') ORDER BY id"
        ).fetchall():
            self._ensure_terminal_headroom_locked(connection, "job", str(row[0]))
        for row in connection.execute(
            "SELECT id FROM steps WHERE status='running' ORDER BY id"
        ).fetchall():
            self._ensure_terminal_headroom_locked(connection, "step", str(row[0]))

    def _validate_legacy_rows(
        self, connection: sqlite3.Connection, generation: str
    ) -> None:
        job_rows = int(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
        step_rows = int(connection.execute("SELECT COUNT(*) FROM steps").fetchone()[0])
        if job_rows > _MAX_JOB_ROWS or step_rows > _MAX_STEP_ROWS:
            raise sqlite3.DatabaseError("legacy TaskLedger row capacity is exceeded")
        if connection.execute(
            "SELECT 1 FROM steps LEFT JOIN jobs ON jobs.id=steps.job_id "
            "WHERE jobs.id IS NULL LIMIT 1"
        ).fetchone():
            raise sqlite3.DatabaseError("legacy TaskLedger contains orphan steps")
        if connection.execute(
            "SELECT 1 FROM steps GROUP BY job_id,idx HAVING COUNT(*)<>1 LIMIT 1"
        ).fetchone():
            raise sqlite3.DatabaseError("legacy TaskLedger step ordering is ambiguous")
        # New CHECK constraints and capacity triggers are the migration validator:
        # every row is copied verbatim (apart from explicit historical defaults)
        # inside this same transaction, so any oversized or malformed value aborts
        # and rolls the complete DDL migration back to the exact legacy generation.

    def _validate_current_identity(self, connection: sqlite3.Connection) -> None:
        if int(connection.execute("PRAGMA application_id").fetchone()[0]) != _APPLICATION_ID:
            raise sqlite3.DatabaseError("TaskLedger application id is invalid")
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != _SCHEMA_VERSION:
            raise sqlite3.DatabaseError("TaskLedger schema version is invalid")
        self._validate_current_database(connection)

    def _validate_v2_database(self, connection: sqlite3.Connection) -> None:
        if self._schema_snapshot(connection) != _expected_v2_schema():
            raise sqlite3.DatabaseError("TaskLedger v2 exact schema is invalid")
        self._validate_integrity_and_capacity(connection, include_headroom=False)

    def _validate_current_database(self, connection: sqlite3.Connection) -> None:
        if self._schema_snapshot(connection) != _expected_current_schema():
            raise sqlite3.DatabaseError("TaskLedger exact schema is invalid")
        self._validate_integrity_and_capacity(connection, include_headroom=True)
        if connection.execute(
            "SELECT 1 FROM jobs WHERE length(result_reservation)<>0 LIMIT 1"
        ).fetchone() or connection.execute(
            "SELECT 1 FROM steps WHERE length(terminal_reservation)<>0 LIMIT 1"
        ).fetchone():
            raise sqlite3.DatabaseError(
                "TaskLedger deprecated same-row reservation is populated"
            )

        expected = {
            ("job", str(row[0]))
            for row in connection.execute(
                "SELECT id FROM jobs WHERE status IN ('planning','running')"
            ).fetchall()
        }
        expected.update(
            ("step", str(row[0]))
            for row in connection.execute(
                "SELECT id FROM steps WHERE status='running'"
            ).fetchall()
        )
        actual: set[tuple[str, str]] = set()
        for row in connection.execute(
            "SELECT kind,owner_id,reserved_pages,length(payload) "
            "FROM ledger_terminal_headroom"
        ).fetchall():
            kind = str(row[0])
            owner_id = str(row[1])
            required_pages, blob_bytes = _terminal_headroom_spec(connection, kind)
            if int(row[2]) != required_pages or int(row[3]) != blob_bytes:
                raise sqlite3.DatabaseError(
                    "TaskLedger terminal headroom shape is invalid"
                )
            actual.add((kind, owner_id))
        if actual != expected:
            raise sqlite3.DatabaseError(
                "TaskLedger terminal headroom ownership is inconsistent"
            )

    def _validate_integrity_and_capacity(
        self, connection: sqlite3.Connection, *, include_headroom: bool
    ) -> None:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()
        if quick_check is None or str(quick_check[0]) != "ok":
            raise sqlite3.DatabaseError("TaskLedger integrity check failed")
        capacity = connection.execute(
            "SELECT job_rows,step_rows,payload_bytes FROM ledger_capacity WHERE singleton=1"
        ).fetchall()
        if len(capacity) != 1:
            raise sqlite3.DatabaseError("TaskLedger capacity authority is invalid")
        job_count = int(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
        step_count = int(connection.execute("SELECT COUNT(*) FROM steps").fetchone()[0])
        job_payload = int(
            connection.execute(
                "SELECT COALESCE(SUM(512+length(CAST(id AS BLOB))+length(CAST(goal AS BLOB))+"
                "length(CAST(status AS BLOB))+length(CAST(user_id AS BLOB))+"
                "length(CAST(result AS BLOB))+length(CAST(execution_spec AS BLOB))+"
                "length(CAST(lease_owner AS BLOB))+length(result_reservation)),0) FROM jobs"
            ).fetchone()[0]
        )
        step_payload = int(
            connection.execute(
                "SELECT COALESCE(SUM(512+length(CAST(id AS BLOB))+length(CAST(job_id AS BLOB))+"
                "length(CAST(title AS BLOB))+length(CAST(detail AS BLOB))+"
                "length(CAST(kind AS BLOB))+length(CAST(deps AS BLOB))+"
                "length(CAST(status AS BLOB))+length(CAST(output AS BLOB))+"
                "length(CAST(error AS BLOB))+length(CAST(lease_owner AS BLOB))+"
                "length(CAST(claim_token AS BLOB))+length(CAST(idempotency_key AS BLOB))+"
                "length(terminal_reservation)),0) FROM steps"
            ).fetchone()[0]
        )
        headroom_payload = 0
        if include_headroom:
            headroom_payload = int(
                connection.execute(
                    "SELECT COALESCE(SUM(256+length(CAST(kind AS BLOB))+"
                    "length(CAST(owner_id AS BLOB))+length(payload)),0) "
                    "FROM ledger_terminal_headroom"
                ).fetchone()[0]
            )
        recorded = capacity[0]
        if (
            int(recorded[0]) != job_count
            or int(recorded[1]) != step_count
            or int(recorded[2]) != job_payload + step_payload + headroom_payload
        ):
            raise sqlite3.DatabaseError("TaskLedger capacity counters are inconsistent")

    @staticmethod
    def _apply_storage_profile(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(f"PRAGMA journal_size_limit={_WAL_JOURNAL_LIMIT_BYTES}")
        connection.execute("PRAGMA wal_autocheckpoint=256")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size <= 0 or page_count * page_size > _MAX_LEDGER_BYTES:
            raise sqlite3.DatabaseError("TaskLedger main database exceeds its byte limit")
        max_pages = max(1, _MAX_LEDGER_BYTES // page_size)
        actual = int(
            connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
        )
        if actual > max_pages:
            raise sqlite3.DatabaseError("TaskLedger max page count was not constrained")

    @staticmethod
    def _ensure_terminal_headroom_locked(
        connection: sqlite3.Connection, kind: str, owner_id: str
    ) -> bool:
        required_pages, blob_bytes = _terminal_headroom_spec(connection, kind)
        existing = connection.execute(
            "SELECT reserved_pages,length(payload) FROM ledger_terminal_headroom "
            "WHERE kind=? AND owner_id=?",
            (kind, owner_id),
        ).fetchone()
        if existing is not None:
            if int(existing[0]) != required_pages or int(existing[1]) != blob_bytes:
                raise sqlite3.DatabaseError(
                    "TaskLedger terminal headroom shape is invalid"
                )
            return False
        connection.execute(
            "INSERT INTO ledger_terminal_headroom(kind,owner_id,reserved_pages,payload) "
            "VALUES(?,?,?,zeroblob(?))",
            (kind, owner_id, required_pages, blob_bytes),
        )
        stored = connection.execute(
            "SELECT reserved_pages,length(payload) FROM ledger_terminal_headroom "
            "WHERE kind=? AND owner_id=?",
            (kind, owner_id),
        ).fetchone()
        if stored is None or tuple(stored) != (required_pages, blob_bytes):
            raise sqlite3.DatabaseError(
                "TaskLedger terminal headroom was not materialized"
            )
        return True

    @staticmethod
    def _terminal_page_budget_baseline(
        connection: sqlite3.Connection,
    ) -> tuple[int, int]:
        return (
            int(connection.execute("PRAGMA page_count").fetchone()[0]),
            int(connection.execute("PRAGMA freelist_count").fetchone()[0]),
        )

    @staticmethod
    def _consume_terminal_headroom_locked(
        connection: sqlite3.Connection, kind: str, owner_id: str
    ) -> None:
        required_pages, blob_bytes = _terminal_headroom_spec(connection, kind)
        row = connection.execute(
            "SELECT reserved_pages,length(payload) FROM ledger_terminal_headroom "
            "WHERE kind=? AND owner_id=?",
            (kind, owner_id),
        ).fetchone()
        if row is None or tuple(row) != (required_pages, blob_bytes):
            raise sqlite3.DatabaseError(
                "TaskLedger terminal headroom is missing or invalid"
            )
        page_before, free_before = TaskLedger._terminal_page_budget_baseline(
            connection
        )
        deleted = connection.execute(
            "DELETE FROM ledger_terminal_headroom WHERE kind=? AND owner_id=?",
            (kind, owner_id),
        )
        if deleted.rowcount != 1:
            raise sqlite3.DatabaseError(
                "TaskLedger terminal headroom release was not exclusive"
            )
        page_after, free_after = TaskLedger._terminal_page_budget_baseline(connection)
        released_pages = free_after - free_before + max(0, page_before - page_after)
        if released_pages < required_pages:
            raise sqlite3.DatabaseError(
                "TaskLedger terminal headroom did not release enough physical pages"
            )

    @staticmethod
    def _assert_terminal_page_budget_consumed(
        connection: sqlite3.Connection, baseline: tuple[int, int]
    ) -> None:
        page_before, free_before = baseline
        page_after, free_after = TaskLedger._terminal_page_budget_baseline(connection)
        if page_after > page_before or (
            free_after + max(0, page_before - page_after) < free_before
        ):
            raise sqlite3.DatabaseError(
                "TaskLedger terminal write exceeded its owned physical headroom"
            )

    def _begin_authoritative_write(self) -> None:
        """Lock first, then reject any external authority drift before mutation."""
        if self._closed:
            raise sqlite3.ProgrammingError("TaskLedger is closed")
        self._assert_live_database_identity()
        self._assert_database_family_bounds()
        self._db.execute("BEGIN IMMEDIATE")
        self._assert_live_database_identity()
        self._reconcile_external_drift_locked()

    def _reconcile_external_drift_locked(self) -> None:
        data_version = int(self._db.execute("PRAGMA data_version").fetchone()[0])
        schema_version = int(
            self._db.execute("PRAGMA schema_version").fetchone()[0]
        )
        if (
            data_version != self._trusted_data_version
            or schema_version != self._trusted_schema_version
        ):
            self._validate_current_identity(self._db)
            self._trusted_data_version = data_version
            self._trusted_schema_version = schema_version

    def _validate_reader_identity_cheap(self, connection: sqlite3.Connection) -> None:
        if int(connection.execute("PRAGMA application_id").fetchone()[0]) != _APPLICATION_ID:
            raise sqlite3.DatabaseError("TaskLedger reader application id is invalid")
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != _SCHEMA_VERSION:
            raise sqlite3.DatabaseError("TaskLedger reader schema version is invalid")
        if self._schema_snapshot(connection) != _expected_current_schema():
            raise sqlite3.DatabaseError("TaskLedger reader exact schema is invalid")

    def _release_reader_lifecycle(self) -> None:
        with self._reader_condition:
            if self._active_readers <= 0:
                raise RuntimeError("TaskLedger reader lifecycle counter underflow")
            self._active_readers -= 1
            if self._active_readers == 0:
                self._reader_condition.notify_all()

    def _reader(self) -> _ReaderLease:
        self._write_lock.acquire()
        db: sqlite3.Connection | None = None
        started_barrier = False
        lifecycle_registered = False
        try:
            if self._closed:
                raise sqlite3.ProgrammingError("TaskLedger is closed")
            self._assert_live_database_identity()
            self._assert_database_family_bounds()
            if not self._db.in_transaction:
                self._db.execute("BEGIN IMMEDIATE")
                started_barrier = True
            try:
                self._reconcile_external_drift_locked()
                uri = f"{Path(self.path).as_uri()}?mode=ro"
                db = sqlite3.connect(
                    uri,
                    uri=True,
                    timeout=_BUSY_TIMEOUT_MS / 1000.0,
                    isolation_level=None,
                )
                db.row_factory = sqlite3.Row
                db.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
                db.execute("PRAGMA trusted_schema=OFF")
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                self._validate_reader_identity_cheap(db)
                self._assert_live_database_identity()
            finally:
                if started_barrier:
                    self._db.rollback()
            assert db is not None
            with self._reader_condition:
                self._active_readers += 1
                lifecycle_registered = True
            reader = _ReaderLease(db, self._release_reader_lifecycle)
            db = None
            return reader
        except Exception:
            try:
                if started_barrier and not self._closed and self._db.in_transaction:
                    self._db.rollback()
            except sqlite3.Error:
                pass
            if db is not None:
                db.close()
            if lifecycle_registered:
                self._release_reader_lifecycle()
            raise
        finally:
            self._write_lock.release()

    # ---------- 建 / 查 ----------
    def create_job(
        self,
        goal: str,
        steps: list[dict],
        *,
        user_id: str = "",
        execution_spec: Optional[dict[str, Any]] = None,
    ) -> str:
        spec = (
            validate_execution_spec(execution_spec)
            if execution_spec is not None
            else freeze_execution_spec(
                goal=goal,
                steps=steps,
                workdir="",
                backend="auto",
                mode="plan",
            )
        )
        # The definitions inserted into ``steps`` must be byte-for-byte derived from
        # the same frozen authority later used by resume.
        goal = str(spec["goal"])
        steps = list(spec["steps"])
        user_id = _bounded_text(user_id, "user id", _MAX_USER_ID_BYTES)
        jid = uuid.uuid4().hex[:12]
        now = time.time()
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                self._db.execute(
                    "INSERT INTO jobs(id,goal,status,user_id,execution_spec,created,updated) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        jid,
                        goal,
                        "running" if steps else "planning",
                        user_id,
                        json.dumps(
                            spec,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                        now,
                    ),
                )
                for i, s in enumerate(steps):
                    step_id = uuid.uuid4().hex[:12]
                    deps = s.get("deps")
                    if deps is None:
                        deps = [i - 1] if i else []
                    self._db.execute(
                        "INSERT INTO steps(id,job_id,idx,title,detail,kind,deps,status,idempotency_key,updated) "
                        "VALUES(?,?,?,?,?,?,?,'pending',?,?)",
                        (
                            step_id, jid, i,
                            str(s.get("title") or f"步骤{i + 1}")[:160],
                            str(s.get("detail") or "")[:2000],
                            "reason" if s.get("kind") == "reason" else "action",
                            json.dumps(deps), f"{jid}:{step_id}", now,
                        ),
                    )
                # A job can fail before any worker claim (configuration,
                # capability, or executor bootstrap).  Commit its independent
                # terminal pages together with creation so that failure never
                # depends on later database growth.
                self._ensure_terminal_headroom_locked(self._db, "job", jid)
                self._db.commit()
            except Exception:
                self._db.rollback()
                raise
        return jid

    def _job(self, jid: str) -> Optional[sqlite3.Row]:
        with closing(self._reader()) as db:
            return db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()

    def _steps(self, jid: str) -> list[sqlite3.Row]:
        with closing(self._reader()) as db:
            return db.execute(
                "SELECT * FROM steps WHERE job_id=? ORDER BY idx", (jid,)
            ).fetchall()

    def get_execution_spec(self, jid: str) -> Optional[dict[str, Any]]:
        """Return the verified server-side authority for execution/resume.

        Legacy rows created before this schema intentionally return ``None`` instead
        of reconstructing permissions from a new request body.
        """
        with closing(self._reader()) as db:
            row = db.execute(
                "SELECT execution_spec FROM jobs WHERE id=?", (jid,)
            ).fetchone()
        if not row:
            return None
        try:
            return validate_execution_spec(json.loads(row["execution_spec"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def next_ready(self, jid: str) -> Optional[sqlite3.Row]:
        """下一个可执行步骤：未完成且依赖全 done。无则 None。"""
        rows = self._steps(jid)
        done = {r["idx"] for r in rows if r["status"] == "done"}
        for r in rows:
            if r["status"] in ("pending", "failed"):
                deps = json.loads(r["deps"] or "[]")
                if all(d in done for d in deps):
                    return r
        return None

    def all_done(self, jid: str) -> bool:
        rows = self._steps(jid)
        return bool(rows) and all(r["status"] == "done" for r in rows)

    # ---------- worker 租约 ----------
    def claim_job(self, jid: str, owner: str, *, lease_seconds: float = 60.0) -> Optional[int]:
        """原子认领一个 job；已有未过期 worker 时返回 None。返回值是 fencing epoch。"""
        owner = _validated_lease_owner(owner)
        duration = _validated_lease_seconds(lease_seconds)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                until = now + duration
                row = self._db.execute(
                    "SELECT status,lease_owner,lease_until,lease_epoch,"
                    "length(result_reservation) AS reservation_bytes "
                    "FROM jobs WHERE id=?",
                    (jid,),
                ).fetchone()
                if not row or row["status"] == "done":
                    self._db.rollback()
                    return None
                if row["lease_owner"] and float(row["lease_until"] or 0) > now:
                    self._db.rollback()
                    return None
                reservation_bytes = int(row["reservation_bytes"] or 0)
                if reservation_bytes != 0:
                    raise sqlite3.DatabaseError(
                        "TaskLedger deprecated job reservation is populated"
                    )
                current_epoch = int(row["lease_epoch"] or 0)
                if current_epoch >= (1 << 63) - 1:
                    raise sqlite3.DatabaseError("TaskLedger job lease epoch is exhausted")
                epoch = current_epoch + 1
                # A new root epoch invalidates every child claim from the old
                # epoch, even if a child lease was configured longer than the
                # root lease or the new worker happens to reuse the same name.
                reset_step_ids = [
                    str(item[0])
                    for item in self._db.execute(
                        "SELECT id FROM steps WHERE job_id=? "
                        "AND status IN ('running','failed')",
                        (jid,),
                    ).fetchall()
                ]
                for reset_step_id in reset_step_ids:
                    self._db.execute(
                        "DELETE FROM ledger_terminal_headroom "
                        "WHERE kind='step' AND owner_id=?",
                        (reset_step_id,),
                    )
                self._db.execute(
                    "UPDATE steps SET status='pending',"
                    "attempts=CASE WHEN status='failed' THEN 0 ELSE attempts END,"
                    "lease_owner='',lease_until=0,claim_token='',terminal_reservation=X'' "
                    "WHERE job_id=? AND status IN ('running','failed')",
                    (jid,),
                )
                self._db.execute(
                    "UPDATE jobs SET status='running',lease_owner=?,lease_until=?,lease_epoch=?,"
                    "result_reservation=X'',updated=? WHERE id=?",
                    (owner, until, epoch, now, jid),
                )
                self._ensure_terminal_headroom_locked(self._db, "job", jid)
                self._db.commit()
                return epoch
            except Exception:
                self._db.rollback()
                raise

    def renew_job(self, jid: str, owner: str, epoch: int, *, lease_seconds: float = 60.0) -> bool:
        """只有当前 epoch 的 worker 能续租，旧 worker 被 fencing。"""
        owner = _validated_lease_owner(owner)
        epoch = _validated_epoch(epoch)
        duration = _validated_lease_seconds(lease_seconds)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                cur = self._db.execute(
                    "UPDATE jobs SET lease_until=?,updated=? "
                    "WHERE id=? AND status='running' AND lease_owner=? AND lease_epoch=? "
                    "AND lease_until>?",
                    (
                        now + duration,
                        now,
                        jid,
                        owner,
                        epoch,
                        now,
                    ),
                )
                self._db.commit()
                return cur.rowcount == 1
            except Exception:
                self._db.rollback()
                raise

    def release_job(self, jid: str, owner: str, epoch: int) -> bool:
        """释放自己的租约；仍有活跃 child claim 时等待其自然到期。"""
        owner = _validated_lease_owner(owner)
        epoch = _validated_epoch(epoch)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                cur = self._db.execute(
                    "UPDATE jobs SET lease_owner='',lease_until=0,updated=? "
                    "WHERE id=? AND lease_owner=? AND lease_epoch=? "
                    "AND NOT EXISTS (SELECT 1 FROM steps WHERE steps.job_id=jobs.id "
                    "AND steps.status='running' AND steps.lease_owner=? "
                    "AND steps.lease_until>?)",
                    (now, jid, owner, epoch, owner, now),
                )
                self._db.commit()
                return cur.rowcount == 1
            except Exception:
                self._db.rollback()
                raise

    def claim_next_step(
        self,
        jid: str,
        owner: str,
        epoch: int,
        *,
        lease_seconds: float = 60.0,
    ) -> Optional[dict[str, Any]]:
        """在 job 租约内原子认领下一步，并返回带稳定 idempotency_key 的快照。"""
        owner = _validated_lease_owner(owner)
        epoch = _validated_epoch(epoch)
        duration = _validated_lease_seconds(lease_seconds)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                job = self._db.execute(
                    "SELECT lease_until FROM jobs WHERE id=? AND status='running' "
                    "AND lease_owner=? AND lease_epoch=? AND lease_until>?",
                    (jid, owner, epoch, now),
                ).fetchone()
                if not job:
                    self._db.rollback()
                    return None
                until = min(
                    now + duration,
                    float(job["lease_until"]),
                )
                rows = self._db.execute(
                    "SELECT * FROM steps WHERE job_id=? ORDER BY idx", (jid,)
                ).fetchall()
                done = {r["idx"] for r in rows if r["status"] == "done"}
                candidate: Optional[sqlite3.Row] = None
                for row in rows:
                    if row["status"] != "pending":
                        continue
                    deps = json.loads(row["deps"] or "[]")
                    if all(dep in done for dep in deps):
                        candidate = row
                        break
                if candidate is None:
                    self._db.rollback()
                    return None
                reservation_bytes = len(candidate["terminal_reservation"] or b"")
                if reservation_bytes != 0:
                    raise sqlite3.DatabaseError(
                        "TaskLedger deprecated step reservation is populated"
                    )
                token = uuid.uuid4().hex
                cur = self._db.execute(
                    "UPDATE steps SET status='running',attempts=attempts+1,lease_owner=?,lease_until=?,"
                    "claim_token=?,terminal_reservation=X'',updated=? "
                    "WHERE id=? AND status='pending'",
                    (
                        owner,
                        until,
                        token,
                        now,
                        candidate["id"],
                    ),
                )
                if cur.rowcount != 1:
                    self._db.rollback()
                    return None
                self._ensure_terminal_headroom_locked(
                    self._db, "step", str(candidate["id"])
                )
                claimed = self._db.execute(
                    "SELECT * FROM steps WHERE id=?", (candidate["id"],)
                ).fetchone()
                self._db.commit()
                if not claimed:
                    return None
                claimed_dict = dict(claimed)
                claimed_dict.pop("terminal_reservation", None)
                return claimed_dict
            except Exception:
                self._db.rollback()
                raise

    def renew_step(
        self,
        step_id: str,
        claim_token: str,
        *,
        owner: str,
        epoch: int,
        lease_seconds: float = 60.0,
    ) -> bool:
        """续租当前 step claim；token 变化说明本 worker 已被 fencing。"""
        claim_token = _validated_claim_token(claim_token)
        owner = _validated_lease_owner(owner)
        epoch = _validated_epoch(epoch)
        duration = _validated_lease_seconds(lease_seconds)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                claim = self._db.execute(
                    "SELECT jobs.lease_until AS job_lease_until FROM steps "
                    "JOIN jobs ON jobs.id=steps.job_id "
                    "WHERE steps.id=? AND steps.status='running' "
                    "AND steps.lease_owner=? AND steps.claim_token=? "
                    "AND steps.lease_until>? AND jobs.status='running' "
                    "AND jobs.lease_owner=? AND jobs.lease_epoch=? AND jobs.lease_until>?",
                    (step_id, owner, claim_token, now, owner, epoch, now),
                ).fetchone()
                if not claim:
                    self._db.rollback()
                    return False
                until = min(
                    now + duration,
                    float(claim["job_lease_until"]),
                )
                cur = self._db.execute(
                    "UPDATE steps SET lease_until=?,updated=? "
                    "WHERE id=? AND status='running' AND lease_owner=? "
                    "AND claim_token=? AND lease_until>?",
                    (until, now, step_id, owner, claim_token, now),
                )
                self._db.commit()
                return cur.rowcount == 1
            except Exception:
                self._db.rollback()
                raise

    def finish_claimed_step(
        self,
        step_id: str,
        claim_token: str,
        status: str,
        *,
        owner: str,
        epoch: int,
        output: str = "",
        error: str = "",
    ) -> bool:
        """以 claim token 提交结果；过期 worker 的迟到结果不会覆盖新执行。"""
        if status not in ("done", "pending", "failed"):
            raise ValueError(f"非法 step 终态: {status}")
        claim_token = _validated_claim_token(claim_token)
        owner = _validated_lease_owner(owner)
        epoch = _validated_epoch(epoch)
        output = _bounded_text(output, "step output", _MAX_STEP_OUTPUT_BYTES)
        error = _bounded_text(error, "step error", _MAX_STEP_ERROR_BYTES)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                claim = self._db.execute(
                    "SELECT steps.job_id FROM steps JOIN jobs ON jobs.id=steps.job_id "
                    "WHERE steps.id=? AND steps.status='running' "
                    "AND steps.lease_owner=? AND steps.claim_token=? "
                    "AND steps.lease_until>? AND jobs.status='running' "
                    "AND jobs.lease_owner=? AND jobs.lease_epoch=? AND jobs.lease_until>?",
                    (step_id, owner, claim_token, now, owner, epoch, now),
                ).fetchone()
                if not claim:
                    self._db.rollback()
                    return False
                baseline = self._terminal_page_budget_baseline(self._db)
                self._consume_terminal_headroom_locked(self._db, "step", step_id)
                if status == "failed":
                    self._consume_terminal_headroom_locked(
                        self._db, "job", str(claim["job_id"])
                    )
                cur = self._db.execute(
                    "UPDATE steps SET status=?,output=?,error=?,lease_owner='',"
                    "lease_until=0,claim_token='',"
                    "terminal_reservation=X'',updated=? "
                    "WHERE id=? AND status='running' AND lease_owner=? "
                    "AND claim_token=? AND lease_until>? "
                    "AND length(terminal_reservation)=0",
                    (
                        status,
                        output,
                        error,
                        now,
                        step_id,
                        owner,
                        claim_token,
                        now,
                    ),
                )
                if cur.rowcount != 1:
                    self._db.rollback()
                    return False
                if status == "failed":
                    job_cur = self._db.execute(
                        "UPDATE jobs SET status='failed',result_reservation=X'',updated=? "
                        "WHERE id=? AND status='running' AND lease_owner=? "
                        "AND lease_epoch=? AND lease_until>?",
                        (now, claim["job_id"], owner, epoch, now),
                    )
                    if job_cur.rowcount != 1:
                        self._db.rollback()
                        return False
                self._assert_terminal_page_budget_consumed(self._db, baseline)
                self._db.commit()
                return True
            except Exception:
                self._db.rollback()
                raise

    def set_claimed_job(
        self,
        jid: str,
        owner: str,
        epoch: int,
        status: str,
        *,
        result: Optional[str] = None,
    ) -> bool:
        """只有当前 job epoch 能写终态。"""
        if status not in ("done", "paused"):
            raise ValueError(f"非法 job 终态: {status}")
        owner = _validated_lease_owner(owner)
        epoch = _validated_epoch(epoch)
        if result is not None:
            result = _bounded_text(result, "job result", _MAX_JOB_RESULT_BYTES)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                complete_guard = (
                    " AND NOT EXISTS (SELECT 1 FROM steps "
                    "WHERE steps.job_id=jobs.id AND steps.status<>'done')"
                    if status == "done"
                    else ""
                )
                eligible = self._db.execute(
                    "SELECT 1 FROM jobs WHERE id=? AND status='running' "
                    "AND lease_owner=? AND lease_epoch=? AND lease_until>? "
                    + (
                        "AND NOT EXISTS (SELECT 1 FROM steps "
                        "WHERE steps.job_id=jobs.id AND steps.status<>'done')"
                        if status == "done"
                        else ""
                    ),
                    (jid, owner, epoch, now),
                ).fetchone()
                if not eligible:
                    self._db.rollback()
                    return False
                baseline = self._terminal_page_budget_baseline(self._db)
                self._consume_terminal_headroom_locked(self._db, "job", jid)
                if result is None:
                    cur = self._db.execute(
                        "UPDATE jobs SET status=?,result_reservation=X'',updated=? "
                        "WHERE id=? AND status='running' AND lease_owner=? "
                        "AND lease_epoch=? AND lease_until>? "
                        "AND length(result_reservation)=0" + complete_guard,
                        (
                            status,
                            now,
                            jid,
                            owner,
                            epoch,
                            now,
                        ),
                    )
                else:
                    cur = self._db.execute(
                        "UPDATE jobs SET status=?,result=?,result_reservation=X'',updated=? "
                        "WHERE id=? AND status='running' AND lease_owner=? "
                        "AND lease_epoch=? AND lease_until>? "
                        "AND length(result_reservation)=0" + complete_guard,
                        (
                            status,
                            result,
                            now,
                            jid,
                            owner,
                            epoch,
                            now,
                        ),
                    )
                if cur.rowcount != 1:
                    self._db.rollback()
                    return False
                self._assert_terminal_page_budget_consumed(self._db, baseline)
                self._db.commit()
                return True
            except Exception:
                self._db.rollback()
                raise

    # ---------- 改 ----------
    def mark(self, step_id: str, status: str, *, output: str = "", error: str = "", bump: bool = False) -> None:
        raise RuntimeError("未带租约的 step 写入口已禁用")

    def set_job(self, jid: str, status: str, *, result: Optional[str] = None) -> None:
        raise RuntimeError("未带租约的 job 写入口已禁用")

    def fail_unclaimed_job(self, jid: str, *, result: Optional[str] = None) -> bool:
        """记录 worker 启动前的失败，绝不覆盖已被认领的 job。"""
        if result is not None:
            result = _bounded_text(result, "job result", _MAX_JOB_RESULT_BYTES)
        with self._write_lock:
            try:
                self._begin_authoritative_write()
                now = time.time()
                eligible = self._db.execute(
                    "SELECT 1 FROM jobs WHERE id=? AND status IN ('planning','running') "
                    "AND lease_owner='' AND lease_epoch=0",
                    (jid,),
                ).fetchone()
                if not eligible:
                    self._db.rollback()
                    return False
                baseline = self._terminal_page_budget_baseline(self._db)
                self._consume_terminal_headroom_locked(self._db, "job", jid)
                if result is None:
                    cur = self._db.execute(
                        "UPDATE jobs SET status='failed',result_reservation=X'',updated=? "
                        "WHERE id=? AND status IN ('planning','running') "
                        "AND lease_owner='' AND lease_epoch=0",
                        (now, jid),
                    )
                else:
                    cur = self._db.execute(
                        "UPDATE jobs SET status='failed',result=?,result_reservation=X'',updated=? "
                        "WHERE id=? AND status IN ('planning','running') "
                        "AND lease_owner='' AND lease_epoch=0",
                        (result, now, jid),
                    )
                if cur.rowcount != 1:
                    self._db.rollback()
                    return False
                self._assert_terminal_page_budget_consumed(self._db, baseline)
                self._db.commit()
                return True
            except Exception:
                self._db.rollback()
                raise

    def recover(self, jid: str) -> None:
        raise RuntimeError("未带新 epoch 的恢复入口已禁用；请使用 claim_job")

    # ---------- 序列化 ----------
    def to_dict(self, jid: str) -> dict:
        with closing(self._reader()) as db:
            # Pin one WAL snapshot across the parent and child reads.  Without
            # an explicit read transaction a concurrent atomic failure commit
            # can produce an impossible running-job/failed-step mixture.
            j = db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
            if not j:
                return {}
            rows = db.execute(
                "SELECT * FROM steps WHERE job_id=? ORDER BY idx", (jid,)
            ).fetchall()
        steps = []
        for r in rows:
            d = dict(r)
            d["deps"] = json.loads(d["deps"] or "[]")
            for internal in (
                "lease_owner",
                "lease_until",
                "claim_token",
                "terminal_reservation",
            ):
                d.pop(internal, None)
            steps.append(d)
        done = sum(1 for s in steps if s["status"] == "done")
        return {
            "id": j["id"], "goal": j["goal"], "status": j["status"], "result": j["result"],
            "user_id": j["user_id"], "steps": steps, "progress": f"{done}/{len(steps)}",
        }

    def close(self) -> None:
        """Close the writer handle explicitly (required for Windows backup/delete)."""
        with self._write_lock:
            if self._closed:
                return
            with self._reader_condition:
                while self._active_readers:
                    self._reader_condition.wait()
            try:
                if self._db.in_transaction:
                    self._db.rollback()
                self._db.close()
            except sqlite3.ProgrammingError as exc:
                if "closed" not in str(exc).casefold():
                    raise
            self._closed = True


async def run_job(
    ledger: TaskLedger,
    jid: str,
    executor: StepExecutor,
    *,
    max_attempts: int = 2,
    on_step: Optional[Callable[[dict, str, Any], None]] = None,
    lease_seconds: float = 60.0,
) -> dict:
    """逐步执行任务。可重复调用→断点续跑（done 步骤自动跳过）。

    每步最多重试 max_attempts 次；某步耗尽重试→该步 failed、整单 failed 并返回。
    """
    lease_seconds = _validated_lease_seconds(lease_seconds)
    owner = uuid.uuid4().hex
    epoch = ledger.claim_job(jid, owner, lease_seconds=lease_seconds)
    if epoch is None:
        return ledger.to_dict(jid)
    lease_lost = asyncio.Event()

    async def heartbeat() -> None:
        interval = min(max(lease_seconds / 3, 0.02), 10.0)
        while True:
            await asyncio.sleep(interval)
            try:
                renewed = await asyncio.to_thread(
                    ledger.renew_job,
                    jid,
                    owner,
                    epoch,
                    lease_seconds=lease_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception:  # renewal failure means authority is no longer proven
                lease_lost.set()
                return
            if not renewed:
                lease_lost.set()
                return

    def notify(step_data: dict, status: str, value: Any) -> None:
        if on_step is None:
            return
        try:
            on_step(step_data, status, value)
        except Exception:
            # Observability callbacks never own the durable transition.
            pass

    heartbeat_task = asyncio.create_task(heartbeat())
    try:
        while True:
            if lease_lost.is_set():
                return ledger.to_dict(jid)
            step = ledger.claim_next_step(
                jid, owner, epoch, lease_seconds=lease_seconds
            )
            if step is None:
                break
            sd = dict(step)
            sd["deps"] = json.loads(step["deps"] or "[]")
            claim_token = str(step["claim_token"])
            for internal in ("lease_owner", "lease_until", "claim_token"):
                sd.pop(internal, None)

            async def step_heartbeat() -> None:
                interval = min(max(lease_seconds / 3, 0.02), 10.0)
                while True:
                    await asyncio.sleep(interval)
                    try:
                        renewed = await asyncio.to_thread(
                            ledger.renew_step,
                            step["id"],
                            claim_token,
                            owner=owner,
                            epoch=epoch,
                            lease_seconds=lease_seconds,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        lease_lost.set()
                        return
                    if not renewed:
                        lease_lost.set()
                        return

            step_heartbeat_task = asyncio.create_task(step_heartbeat())
            executor_task: asyncio.Task[Any] | None = None
            lease_wait_task: asyncio.Task[bool] | None = None
            try:
                executor_task = asyncio.create_task(executor(sd))
                lease_wait_task = asyncio.create_task(lease_lost.wait())
                completed, _pending = await asyncio.wait(
                    {executor_task, lease_wait_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if lease_wait_task in completed or lease_lost.is_set():
                    # A worker without a live root+child lease has no authority
                    # to continue side effects or submit a result.  Cooperative
                    # cancellation is awaited before this invocation returns.
                    executor_task.cancel()
                    await asyncio.gather(executor_task, return_exceptions=True)
                    return ledger.to_dict(jid)
                lease_wait_task.cancel()
                await asyncio.gather(lease_wait_task, return_exceptions=True)
                out = await executor_task
                if lease_lost.is_set():
                    return ledger.to_dict(jid)
                committed = ledger.finish_claimed_step(
                    step["id"],
                    claim_token,
                    "done",
                    owner=owner,
                    epoch=epoch,
                    output=_truncate_utf8(out, _MAX_STEP_OUTPUT_BYTES),
                )
                if not committed:
                    return ledger.to_dict(jid)
                notify(sd, "done", out)
            except Exception as e:  # noqa: BLE001
                if int(step["attempts"]) >= max_attempts:
                    committed = ledger.finish_claimed_step(
                        step["id"],
                        claim_token,
                        "failed",
                        owner=owner,
                        epoch=epoch,
                        error=_truncate_utf8(e, _MAX_STEP_ERROR_BYTES),
                    )
                    if not committed:
                        return ledger.to_dict(jid)
                    notify(sd, "failed", str(e))
                    return ledger.to_dict(jid)
                committed = ledger.finish_claimed_step(
                    step["id"],
                    claim_token,
                    "pending",
                    owner=owner,
                    epoch=epoch,
                    error=_truncate_utf8(e, _MAX_STEP_ERROR_BYTES),
                )
                if not committed:
                    return ledger.to_dict(jid)
                notify(sd, "retry", str(e))
            finally:
                for task in (executor_task, lease_wait_task):
                    if task is not None and not task.done():
                        task.cancel()
                await asyncio.gather(
                    *(task for task in (executor_task, lease_wait_task) if task is not None),
                    return_exceptions=True,
                )
                step_heartbeat_task.cancel()
                await asyncio.gather(step_heartbeat_task, return_exceptions=True)
        if ledger.all_done(jid):
            rows = ledger._steps(jid)
            result = "\n".join(f"[{r['idx'] + 1}] {r['title']}：{(r['output'] or '')[:200]}" for r in rows)
            ledger.set_claimed_job(
                jid,
                owner,
                epoch,
                "done",
                result=_truncate_utf8(result, _MAX_JOB_RESULT_BYTES),
            )
        return ledger.to_dict(jid)
    finally:
        heartbeat_task.cancel()
        await asyncio.gather(heartbeat_task, return_exceptions=True)
        # A failed/negative renewal means this worker can no longer prove that
        # it owns the epoch.  Do not perform a best-effort release with stale
        # authority (or block cancellation on the same unavailable store).
        if not lease_lost.is_set():
            ledger.release_job(jid, owner, epoch)


async def plan_job(router: Any, goal: str, *, model: Optional[str] = None) -> list[dict]:
    """让模型把目标拆成有序步骤。返回 [{title, detail, kind, deps}]；失败返回 []。"""
    from gateway.failover import chat_with_fallback
    from gateway.provider_call_ledger import bind_provider_call_scope
    from gateway.schemas import ChatCompletionRequest
    from orchestrator.modes import pick_model

    m = model or pick_model(router, "cheap")
    ask = (
        "把下面的目标拆解成可执行的有序步骤（3-8 步）。每步给 title(短)、detail(具体怎么做)、"
        "kind(action=要动手用工具/文件/命令，reason=只需思考分析)。"
        '严格只输出 JSON 数组，形如 [{"title":"...","detail":"...","kind":"action"}]，按执行顺序排列。\n'
        f"目标：{goal}"
    )
    req = ChatCompletionRequest(model=m, messages=[{"role": "user", "content": ask}])  # type: ignore[arg-type]
    with bind_provider_call_scope(role="task_ledger.plan_job"):
        res, _served, _route = await chat_with_fallback(router, req)
    txt = ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
    return parse_steps(txt)


def parse_steps(txt: str) -> list[dict]:
    """从模型输出里抠出步骤 JSON 数组并规整。"""
    m = re.search(r"\[.*\]", txt, re.S)
    raw = m.group(0) if m else txt
    try:
        arr = json.loads(raw)
    except Exception:  # noqa: BLE001
        return []
    out: list[dict] = []
    if not isinstance(arr, list):
        return out
    for i, s in enumerate(arr):
        if isinstance(s, dict) and (s.get("title") or s.get("detail")):
            out.append(
                {
                    "title": str(s.get("title") or f"步骤{i + 1}")[:160],
                    "detail": str(s.get("detail") or "")[:2000],
                    "kind": "reason" if s.get("kind") == "reason" else "action",
                    "deps": [i - 1] if i else [],
                }
            )
    return out
