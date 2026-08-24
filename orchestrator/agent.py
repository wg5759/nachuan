"""超级智能体核心：带记忆的多轮对话。

里程碑式扩展（飞书与桌面共用同一套）：
  · M1（本文件起步）：按会话(channel:chat_id)维护滚动对话历史 → 机器人会“接话”。
  · M2：长期用户记忆（抽取/存/取你的习惯偏好）。
  · M3：案例库 + 师生进化（强模型解法存库，免费模型检索复用）。
  · M4：反思与反馈（👍👎/纠正 → 教训）。

设计取向：本地优先、零重型依赖，借鉴 mem0 / Letta(MemGPT) / Voyager / Memento 的“打法”，
用项目自家的免费模型做抽取与检索。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import stat
import threading
import time
from collections import OrderedDict, deque
from contextlib import closing
from functools import lru_cache
from pathlib import Path
from typing import Any

from gateway.failover import chat_with_fallback
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.route_attestation import bind_agent_author_receipt
from gateway.schemas import ChatCompletionRequest
from orchestrator.cases import decide_route, format_case
from orchestrator.classify import classify
from orchestrator.intent import classify_intent
from orchestrator.media import (
    create_video_task,
    gen_image,
    gen_video,
    parse_duration,
    polish_prompt,
)
from orchestrator.memory import format_memories
from orchestrator.modes import pick_model, run_org
from orchestrator.translate import translate
from orchestrator.workflows.common import route_receipt

_LOG = logging.getLogger(__name__)

# 每会话保留的最近“轮”数（一轮=用户+助手两条），控制上下文长度、省 token。
_MAX_TURNS = 12
_CHANNEL_ATTEMPT_TIMEOUT = max(
    1.0, float(os.getenv("NACHUAN_CHANNEL_ATTEMPT_TIMEOUT", "25"))
)
_CHANNEL_TOTAL_TIMEOUT = max(
    _CHANNEL_ATTEMPT_TIMEOUT,
    float(os.getenv("NACHUAN_CHANNEL_TOTAL_TIMEOUT", "45")),
)


class ConversationReceiptUnavailable(RuntimeError):
    """The durable agent Turn receipt cannot be read or trusted."""


class _ConversationDatabaseFamilyChanged(sqlite3.DatabaseError):
    """A read-only SQLite-family snapshot changed before it could be trusted."""


_CONVERSATION_APPLICATION_ID = 0x4E434356  # "NCCV"
_CONVERSATION_SCHEMA_VERSION = 1
_CONV_LEGACY_SCHEMA_SQL = (
    "CREATE TABLE conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "key TEXT NOT NULL, role TEXT, content TEXT, ts REAL)"
)
_CONV_V2_SCHEMA_SQL = (
    "CREATE TABLE conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "key TEXT NOT NULL CHECK(length(CAST(key AS BLOB)) BETWEEN 1 AND 4096), "
    "role TEXT NOT NULL CHECK(role IN ('user','assistant')), "
    "content TEXT NOT NULL, ts REAL NOT NULL)"
)
_CONV_SCHEMA_SQL = (
    "CREATE TABLE conv (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "key TEXT NOT NULL CHECK(typeof(key)='text' AND "
    "length(CAST(key AS BLOB)) BETWEEN 1 AND 4096), "
    "role TEXT NOT NULL CHECK(typeof(role)='text' AND "
    "role IN ('user','assistant')), "
    "content TEXT NOT NULL CHECK(typeof(content)='text' AND "
    "length(CAST(content AS BLOB))<=8388608), "
    "ts REAL NOT NULL CHECK(typeof(ts) IN ('integer','real') AND "
    "abs(ts)<=1.7976931348623157e308))"
)
_CONV_INDEX_SQL = "CREATE INDEX idx_conv_key ON conv(key, id)"
_TURN_RECEIPT_V1_SCHEMA_SQL = (
    "CREATE TABLE agent_turn_receipt ("
    "turn_key TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, "
    "response_json TEXT NOT NULL, created_at REAL NOT NULL) WITHOUT ROWID"
)
_TURN_RECEIPT_SCHEMA_SQL = (
    "CREATE TABLE agent_turn_receipt ("
    "turn_key TEXT PRIMARY KEY CHECK(typeof(turn_key)='text' AND "
    "length(turn_key)=64 AND turn_key NOT GLOB '*[^0-9a-f]*'), "
    "request_sha256 TEXT NOT NULL CHECK(typeof(request_sha256)='text' AND "
    "length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "response_json TEXT NOT NULL CHECK(typeof(response_json)='text' AND "
    "length(CAST(response_json AS BLOB))<=1048576), "
    "created_at REAL NOT NULL CHECK(typeof(created_at) IN ('integer','real') AND "
    "abs(created_at)<=1.7976931348623157e308)) WITHOUT ROWID"
)
_TURN_RECEIPT_INDEX_SQL = (
    "CREATE INDEX idx_agent_turn_receipt_created_at "
    "ON agent_turn_receipt(created_at,turn_key)"
)
_TURN_RESERVATION_PAYLOAD_BYTES = 64 + 64 + 1024 * 1024
_TURN_RESERVATION_V1_SCHEMA_SQL = (
    "CREATE TABLE agent_turn_reservation ("
    "turn_key TEXT PRIMARY KEY CHECK(typeof(turn_key)='text' AND "
    "length(turn_key)=64 AND turn_key NOT GLOB '*[^0-9a-f]*'), "
    "request_sha256 TEXT NOT NULL CHECK(typeof(request_sha256)='text' AND "
    "length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "state TEXT NOT NULL CHECK(typeof(state)='text' AND "
    "state IN ('reserved','provider_started')), "
    "reserved_payload_bytes INTEGER NOT NULL CHECK("
    "typeof(reserved_payload_bytes)='integer' AND reserved_payload_bytes=1048704), "
    "created_at REAL NOT NULL CHECK(typeof(created_at) IN ('integer','real') AND "
    "abs(created_at)<=1.7976931348623157e308), "
    "provider_started_at REAL CHECK(provider_started_at IS NULL OR "
    "(typeof(provider_started_at) IN ('integer','real') AND "
    "abs(provider_started_at)<=1.7976931348623157e308)), "
    "CHECK((state='reserved' AND provider_started_at IS NULL) OR "
    "(state='provider_started' AND provider_started_at IS NOT NULL))"
    ") WITHOUT ROWID"
)
_TURN_RESERVATION_SCHEMA_SQL = (
    "CREATE TABLE agent_turn_reservation ("
    "turn_key TEXT PRIMARY KEY CHECK(typeof(turn_key)='text' AND "
    "length(turn_key)=64 AND turn_key NOT GLOB '*[^0-9a-f]*'), "
    "request_sha256 TEXT NOT NULL CHECK(typeof(request_sha256)='text' AND "
    "length(request_sha256)=64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'), "
    "state TEXT NOT NULL CHECK(typeof(state)='text' AND "
    "state IN ('reserved','provider_started','abandoned')), "
    "reserved_payload_bytes INTEGER NOT NULL CHECK("
    "typeof(reserved_payload_bytes)='integer' AND "
    "((state IN ('reserved','provider_started') AND "
    "reserved_payload_bytes=1048704) OR "
    "(state='abandoned' AND reserved_payload_bytes=0))), "
    "created_at REAL NOT NULL CHECK(typeof(created_at) IN ('integer','real') AND "
    "abs(created_at)<=1.7976931348623157e308), "
    "provider_started_at REAL CHECK(provider_started_at IS NULL OR "
    "(typeof(provider_started_at) IN ('integer','real') AND "
    "abs(provider_started_at)<=1.7976931348623157e308)), "
    "CHECK((state IN ('reserved','abandoned') AND provider_started_at IS NULL) OR "
    "(state='provider_started' AND provider_started_at IS NOT NULL))"
    ") WITHOUT ROWID"
)
_CAPACITY_META_V2_SCHEMA_SQL = (
    "CREATE TABLE conversation_capacity_meta ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "conv_rows INTEGER NOT NULL CHECK(typeof(conv_rows)='integer' AND conv_rows>=0), "
    "conv_payload_bytes INTEGER NOT NULL CHECK(typeof(conv_payload_bytes)='integer' AND conv_payload_bytes>=0), "
    "receipt_rows INTEGER NOT NULL CHECK(typeof(receipt_rows)='integer' AND receipt_rows>=0), "
    "receipt_payload_bytes INTEGER NOT NULL CHECK(typeof(receipt_payload_bytes)='integer' AND receipt_payload_bytes>=0)"
    ") WITHOUT ROWID"
)
_CAPACITY_META_V3_SCHEMA_SQL = (
    "CREATE TABLE conversation_capacity_meta ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "conv_rows INTEGER NOT NULL CHECK(typeof(conv_rows)='integer' AND conv_rows>=0), "
    "conv_payload_bytes INTEGER NOT NULL CHECK(typeof(conv_payload_bytes)='integer' AND conv_payload_bytes>=0), "
    "receipt_rows INTEGER NOT NULL CHECK(typeof(receipt_rows)='integer' AND receipt_rows>=0), "
    "receipt_payload_bytes INTEGER NOT NULL CHECK(typeof(receipt_payload_bytes)='integer' AND receipt_payload_bytes>=0), "
    "reservation_rows INTEGER NOT NULL CHECK(typeof(reservation_rows)='integer' AND reservation_rows>=0), "
    "reservation_payload_bytes INTEGER NOT NULL CHECK(typeof(reservation_payload_bytes)='integer' AND reservation_payload_bytes>=0)"
    ") WITHOUT ROWID"
)
_CAPACITY_META_SCHEMA_SQL = (
    "CREATE TABLE conversation_capacity_meta ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "conv_rows INTEGER NOT NULL CHECK(typeof(conv_rows)='integer' AND conv_rows>=0), "
    "conv_payload_bytes INTEGER NOT NULL CHECK(typeof(conv_payload_bytes)='integer' AND conv_payload_bytes>=0), "
    "receipt_rows INTEGER NOT NULL CHECK(typeof(receipt_rows)='integer' AND receipt_rows>=0), "
    "receipt_payload_bytes INTEGER NOT NULL CHECK(typeof(receipt_payload_bytes)='integer' AND receipt_payload_bytes>=0), "
    "reservation_rows INTEGER NOT NULL CHECK(typeof(reservation_rows)='integer' AND reservation_rows>=0), "
    "reservation_payload_bytes INTEGER NOT NULL CHECK(typeof(reservation_payload_bytes)='integer' AND reservation_payload_bytes>=0), "
    "receipt_contract_version INTEGER NOT NULL CHECK("
    "typeof(receipt_contract_version)='integer' AND receipt_contract_version=1), "
    "max_turn_receipts INTEGER NOT NULL CHECK(typeof(max_turn_receipts)='integer' AND "
    "max_turn_receipts BETWEEN 1 AND 1000000), "
    "max_turn_receipt_bytes INTEGER NOT NULL CHECK("
    "typeof(max_turn_receipt_bytes)='integer' AND "
    "max_turn_receipt_bytes BETWEEN 1 AND 1073741824)"
    ") WITHOUT ROWID"
)
_CAPACITY_META_V1_SCHEMA_SQL = (
    "CREATE TABLE conversation_capacity_meta ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "conv_rows INTEGER NOT NULL CHECK(conv_rows>=0), "
    "conv_payload_bytes INTEGER NOT NULL CHECK(conv_payload_bytes>=0), "
    "receipt_rows INTEGER NOT NULL CHECK(receipt_rows>=0), "
    "receipt_payload_bytes INTEGER NOT NULL CHECK(receipt_payload_bytes>=0)"
    ") WITHOUT ROWID"
)
_CAPACITY_TRIGGER_V2_SQL = {
    "conversation_capacity_conv_insert": (
        "CREATE TRIGGER conversation_capacity_conv_insert AFTER INSERT ON conv BEGIN "
        "UPDATE conversation_capacity_meta SET conv_rows=conv_rows+1,"
        "conv_payload_bytes=conv_payload_bytes+length(CAST(NEW.key AS BLOB))+"
        "length(CAST(NEW.role AS BLOB))+length(CAST(NEW.content AS BLOB)) "
        "WHERE singleton=1; END"
    ),
    "conversation_capacity_conv_delete": (
        "CREATE TRIGGER conversation_capacity_conv_delete AFTER DELETE ON conv BEGIN "
        "UPDATE conversation_capacity_meta SET conv_rows=conv_rows-1,"
        "conv_payload_bytes=conv_payload_bytes-length(CAST(OLD.key AS BLOB))-"
        "length(CAST(OLD.role AS BLOB))-length(CAST(OLD.content AS BLOB)) "
        "WHERE singleton=1; END"
    ),
    "conversation_capacity_conv_update": (
        "CREATE TRIGGER conversation_capacity_conv_update "
        "AFTER UPDATE OF key,role,content ON conv BEGIN "
        "UPDATE conversation_capacity_meta SET conv_payload_bytes=conv_payload_bytes-"
        "length(CAST(OLD.key AS BLOB))-length(CAST(OLD.role AS BLOB))-"
        "length(CAST(OLD.content AS BLOB))+length(CAST(NEW.key AS BLOB))+"
        "length(CAST(NEW.role AS BLOB))+length(CAST(NEW.content AS BLOB)) "
        "WHERE singleton=1; END"
    ),
    "conversation_capacity_receipt_insert": (
        "CREATE TRIGGER conversation_capacity_receipt_insert "
        "AFTER INSERT ON agent_turn_receipt BEGIN "
        "UPDATE conversation_capacity_meta SET receipt_rows=receipt_rows+1,"
        "receipt_payload_bytes=receipt_payload_bytes+"
        "length(CAST(NEW.turn_key AS BLOB))+"
        "length(CAST(NEW.request_sha256 AS BLOB))+"
        "length(CAST(NEW.response_json AS BLOB)) WHERE singleton=1; END"
    ),
    "conversation_capacity_receipt_delete": (
        "CREATE TRIGGER conversation_capacity_receipt_delete "
        "AFTER DELETE ON agent_turn_receipt BEGIN "
        "UPDATE conversation_capacity_meta SET receipt_rows=receipt_rows-1,"
        "receipt_payload_bytes=receipt_payload_bytes-"
        "length(CAST(OLD.turn_key AS BLOB))-"
        "length(CAST(OLD.request_sha256 AS BLOB))-"
        "length(CAST(OLD.response_json AS BLOB)) WHERE singleton=1; END"
    ),
    "conversation_capacity_receipt_update": (
        "CREATE TRIGGER conversation_capacity_receipt_update "
        "AFTER UPDATE OF turn_key,request_sha256,response_json "
        "ON agent_turn_receipt BEGIN "
        "UPDATE conversation_capacity_meta SET receipt_payload_bytes="
        "receipt_payload_bytes-length(CAST(OLD.turn_key AS BLOB))-"
        "length(CAST(OLD.request_sha256 AS BLOB))-"
        "length(CAST(OLD.response_json AS BLOB))+"
        "length(CAST(NEW.turn_key AS BLOB))+"
        "length(CAST(NEW.request_sha256 AS BLOB))+"
        "length(CAST(NEW.response_json AS BLOB)) WHERE singleton=1; END"
    ),
}
_CAPACITY_TRIGGER_V3_SQL = {
    **_CAPACITY_TRIGGER_V2_SQL,
    "conversation_capacity_reservation_insert": (
        "CREATE TRIGGER conversation_capacity_reservation_insert "
        "AFTER INSERT ON agent_turn_reservation BEGIN "
        "UPDATE conversation_capacity_meta SET reservation_rows=reservation_rows+1,"
        "reservation_payload_bytes=reservation_payload_bytes+NEW.reserved_payload_bytes "
        "WHERE singleton=1; END"
    ),
    "conversation_capacity_reservation_delete": (
        "CREATE TRIGGER conversation_capacity_reservation_delete "
        "AFTER DELETE ON agent_turn_reservation BEGIN "
        "UPDATE conversation_capacity_meta SET reservation_rows=reservation_rows-1,"
        "reservation_payload_bytes=reservation_payload_bytes-OLD.reserved_payload_bytes "
        "WHERE singleton=1; END"
    ),
}
_CAPACITY_TRIGGER_SQL = {
    **_CAPACITY_TRIGGER_V2_SQL,
    "conversation_capacity_reservation_insert": (
        "CREATE TRIGGER conversation_capacity_reservation_insert "
        "AFTER INSERT ON agent_turn_reservation BEGIN "
        "UPDATE conversation_capacity_meta SET reservation_rows=reservation_rows+"
        "CASE WHEN NEW.state='abandoned' THEN 0 ELSE 1 END,"
        "reservation_payload_bytes=reservation_payload_bytes+NEW.reserved_payload_bytes "
        "WHERE singleton=1; END"
    ),
    "conversation_capacity_reservation_delete": (
        "CREATE TRIGGER conversation_capacity_reservation_delete "
        "AFTER DELETE ON agent_turn_reservation BEGIN "
        "UPDATE conversation_capacity_meta SET reservation_rows=reservation_rows-"
        "CASE WHEN OLD.state='abandoned' THEN 0 ELSE 1 END,"
        "reservation_payload_bytes=reservation_payload_bytes-OLD.reserved_payload_bytes "
        "WHERE singleton=1; END"
    ),
    "conversation_capacity_reservation_update": (
        "CREATE TRIGGER conversation_capacity_reservation_update "
        "AFTER UPDATE OF state,reserved_payload_bytes ON agent_turn_reservation BEGIN "
        "UPDATE conversation_capacity_meta SET reservation_rows=reservation_rows-"
        "CASE WHEN OLD.state='abandoned' THEN 0 ELSE 1 END+"
        "CASE WHEN NEW.state='abandoned' THEN 0 ELSE 1 END,"
        "reservation_payload_bytes=reservation_payload_bytes-OLD.reserved_payload_bytes+"
        "NEW.reserved_payload_bytes WHERE singleton=1; END"
    ),
}


def _conversation_schema_declarations(
    conv_sql: str,
    receipt_sql: str | None,
    reservation_sql: str | None,
    meta_sql: str | None,
    triggers: dict[str, str],
    *,
    conv_index: bool = True,
    receipt_index: bool = True,
) -> tuple[tuple[str, str, str], ...]:
    items: list[tuple[str, str, str]] = [("table", "conv", conv_sql)]
    if conv_index:
        items.append(("index", "idx_conv_key", _CONV_INDEX_SQL))
    if receipt_sql is not None:
        items.append(("table", "agent_turn_receipt", receipt_sql))
        if receipt_index:
            items.append(
                (
                    "index",
                    "idx_agent_turn_receipt_created_at",
                    _TURN_RECEIPT_INDEX_SQL,
                )
            )
    if reservation_sql is not None:
        items.append(("table", "agent_turn_reservation", reservation_sql))
    if meta_sql is not None:
        items.append(("table", "conversation_capacity_meta", meta_sql))
    items.extend(("trigger", name, ddl) for name, ddl in triggers.items())
    return tuple(items)


def _conversation_schema_variants(
) -> tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...]:
    declarations = _conversation_schema_declarations
    return (
        (
            "legacy_conversation_no_index",
            declarations(
                _CONV_LEGACY_SCHEMA_SQL,
                None,
                None,
                None,
                {},
                conv_index=False,
            ),
        ),
        (
            "legacy_conversation",
            declarations(_CONV_LEGACY_SCHEMA_SQL, None, None, None, {}),
        ),
        # Committed by 1cbc955 / 72ea2a3 / 2821cc4: receipt v1 existed
        # before its created_at index and the capacity contract.
        (
            "committed_legacy_receipt_v1",
            declarations(
                _CONV_LEGACY_SCHEMA_SQL,
                _TURN_RECEIPT_V1_SCHEMA_SQL,
                None,
                None,
                {},
                receipt_index=False,
            ),
        ),
        (
            "previous_legacy_strict",
            declarations(
                _CONV_V2_SCHEMA_SQL,
                _TURN_RECEIPT_V1_SCHEMA_SQL,
                None,
                _CAPACITY_META_V1_SCHEMA_SQL,
                _CAPACITY_TRIGGER_V2_SQL,
            ),
        ),
        (
            "previous_strict",
            declarations(
                _CONV_SCHEMA_SQL,
                _TURN_RECEIPT_SCHEMA_SQL,
                None,
                _CAPACITY_META_V2_SCHEMA_SQL,
                _CAPACITY_TRIGGER_V2_SQL,
            ),
        ),
        (
            "previous_reservation",
            declarations(
                _CONV_SCHEMA_SQL,
                _TURN_RECEIPT_SCHEMA_SQL,
                _TURN_RESERVATION_V1_SCHEMA_SQL,
                _CAPACITY_META_V3_SCHEMA_SQL,
                _CAPACITY_TRIGGER_V3_SQL,
            ),
        ),
        (
            "previous_abandoned",
            declarations(
                _CONV_SCHEMA_SQL,
                _TURN_RECEIPT_SCHEMA_SQL,
                _TURN_RESERVATION_SCHEMA_SQL,
                _CAPACITY_META_V3_SCHEMA_SQL,
                _CAPACITY_TRIGGER_SQL,
            ),
        ),
        (
            "current",
            declarations(
                _CONV_SCHEMA_SQL,
                _TURN_RECEIPT_SCHEMA_SQL,
                _TURN_RESERVATION_SCHEMA_SQL,
                _CAPACITY_META_SCHEMA_SQL,
                _CAPACITY_TRIGGER_SQL,
            ),
        ),
    )


@lru_cache(maxsize=16)
def _materialized_conversation_schema_objects(
    declarations: tuple[tuple[str, str, str], ...],
) -> dict[tuple[str, str], tuple[str, str | None]]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        for _kind, _name, ddl in declarations:
            connection.execute(ddl)
        objects = {
            (str(kind), str(name)): (
                str(tbl_name),
                sql if isinstance(sql, str) else None,
            )
            for kind, name, tbl_name, sql in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
        }
    finally:
        connection.close()
    declared = {(kind, name) for kind, name, _ddl in declarations}
    if not declared.issubset(objects) or any(
        not objects[identity][1] for identity in declared
    ):
        raise sqlite3.DatabaseError(
            "conversation expected schema could not be materialized exactly"
        )
    return objects


def _actual_conversation_schema_objects(
    connection: sqlite3.Connection,
) -> dict[tuple[str, str], tuple[str, str | None]]:
    return {
        (str(kind), str(name)): (
            str(tbl_name),
            sql if isinstance(sql, str) else None,
        )
        for kind, name, tbl_name, sql in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
    }


def _conversation_schema_generation(connection: sqlite3.Connection) -> str:
    actual = _actual_conversation_schema_objects(connection)
    if not actual:
        return "empty"
    for name, declarations in _conversation_schema_variants():
        if actual == _materialized_conversation_schema_objects(declarations):
            return name
    raise sqlite3.DatabaseError(
        "conversation database is neither empty nor a complete recognized schema"
    )


def _conversation_database_generation(connection: sqlite3.Connection) -> str:
    """Classify exact schema and its SQLite application identity together."""

    application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    generation = _conversation_schema_generation(connection)
    if application_id == 0 and user_version == 0:
        return generation
    if (
        application_id == _CONVERSATION_APPLICATION_ID
        and user_version == _CONVERSATION_SCHEMA_VERSION
        and generation == "current"
    ):
        return generation
    raise sqlite3.DatabaseError(
        "conversation database application identity is not recognized"
    )


@lru_cache(maxsize=1)
def _expected_schema_sql_by_declaration() -> dict[str, str]:
    """Materialize every supported schema generation with the real SQLite DDL."""

    variants = tuple(
        declarations for _name, declarations in _conversation_schema_variants()
    )
    materialized: dict[str, str] = {}
    for variant in variants:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        try:
            for _kind, _name, ddl in variant:
                connection.execute(ddl)
            for kind, name, ddl in variant:
                row = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type=? AND name=?",
                    (kind, name),
                ).fetchone()
                if row is None or not isinstance(row[0], str) or not row[0]:
                    raise sqlite3.DatabaseError(
                        "conversation expected schema could not be materialized exactly"
                    )
                previous = materialized.setdefault(ddl, str(row[0]))
                if previous != str(row[0]):
                    raise sqlite3.DatabaseError(
                        "conversation expected schema materialization is inconsistent"
                    )
        finally:
            connection.close()
    return materialized


def _normalized_schema_sql(value: str) -> str:
    """Return exact stored SQL; built-in DDL is first materialized by SQLite."""

    if not isinstance(value, str) or not value:
        raise sqlite3.DatabaseError("conversation schema SQL is missing")
    return _expected_schema_sql_by_declaration().get(value, value)

# 翻译目标语种抽取（agent_chat 走 translate 意图时用；与前端 parseTranslate 同源思路）
_TR_TABLE = {
    "中": "zh", "英": "en", "日": "ja", "韩": "ko", "法": "fr", "德": "de", "西": "es", "俄": "ru",
    "chinese": "zh", "english": "en", "japanese": "ja", "korean": "ko",
    "french": "fr", "german": "de", "spanish": "es", "russian": "ru",
}


def _translate_target(s: str) -> str:
    m = re.search(
        r"(?:成|为|译成|译为|to)\s*([中英日韩法德西俄]|chinese|english|japanese|korean|french|german|spanish|russian)",
        s,
        re.I,
    )
    return _TR_TABLE.get(m.group(1).lower(), "en") if m else "en"


def _strip_translate_cmd(s: str) -> str:
    """去掉「翻译成X：」这类指令前缀，剩下的就是待译文本。"""
    return re.sub(
        r"^(请?帮?我?)?(把)?(这段|下面的?)?(翻译|翻成|译成|translate)\s*(成|为|to)?\s*"
        r"(英文|英语|english|中文|汉语|chinese|日文|日语|japanese|韩文|韩语|korean|"
        r"法文|法语|french|德文|德语|german|西班牙\w*|spanish|俄文|俄语|russian)?\s*[：:，,。\s]*",
        "",
        s,
        flags=re.I,
    ).strip()


class ConversationStore:
    """按 session_key 保存最近若干轮对话（短期记忆）。

    可选 SQLite 持久化（传 db_path）：**引擎重启也能续上上下文**——飞书常驻机器人尤其需要，
    否则一重启就"失忆"。SQLite 是真源；内存只保留有界 LRU，会话首次访问时按 key
    读取最近若干轮。每次启动用 COUNT/SUM 精确核对容量元数据；正常单写热路径不扫描
    历史全表，只有 PRAGMA data_version 证明另一连接提交后才重验 schema/计数并失效 LRU。
    不传 db_path 则退化为纯内存（测试用）。
    """

    def __init__(
        self,
        max_turns: int = _MAX_TURNS,
        db_path: str | None = None,
        *,
        max_cached_sessions: int = 1024,
        max_database_bytes: int = 1024 * 1024 * 1024,
        max_content_bytes: int = 2 * 1024 * 1024,
        max_conversation_rows: int = 200_000,
        max_conversation_bytes: int | None = None,
        max_turn_receipts: int = 50_000,
        max_turn_receipt_bytes: int | None = None,
    ) -> None:
        if not 1 <= int(max_turns) <= 10_000:
            raise ValueError("max_turns must be between 1 and 10000")
        if not 1 <= int(max_cached_sessions) <= 100_000:
            raise ValueError("max_cached_sessions must be between 1 and 100000")
        if not 64 * 1024 <= int(max_database_bytes) <= 1024**3:
            raise ValueError("max_database_bytes must be between 64 KiB and 1 GiB")
        if not 1 <= int(max_content_bytes) <= 8 * 1024 * 1024:
            raise ValueError("max_content_bytes must be between 1 byte and 8 MiB")
        if not 1 <= int(max_conversation_rows) <= 10_000_000:
            raise ValueError("max_conversation_rows must be between 1 and 10000000")
        if not 1 <= int(max_turn_receipts) <= 1_000_000:
            raise ValueError("max_turn_receipts must be between 1 and 1000000")
        database_bytes = int(max_database_bytes)
        conversation_bytes = (
            max(1, min(256 * 1024 * 1024, database_bytes // 4))
            if max_conversation_bytes is None
            else int(max_conversation_bytes)
        )
        receipt_bytes = (
            max(1, min(256 * 1024 * 1024, database_bytes // 4))
            if max_turn_receipt_bytes is None
            else int(max_turn_receipt_bytes)
        )
        if not 1 <= conversation_bytes <= database_bytes:
            raise ValueError("max_conversation_bytes must fit within database capacity")
        if not 1 <= receipt_bytes <= database_bytes:
            raise ValueError("max_turn_receipt_bytes must fit within database capacity")
        self._max = int(max_turns)
        self._max_cached_sessions = int(max_cached_sessions)
        self._max_database_bytes = database_bytes
        self._max_content_bytes = int(max_content_bytes)
        self._max_conversation_rows = int(max_conversation_rows)
        self._max_conversation_bytes = conversation_bytes
        self._max_turn_receipts = int(max_turn_receipts)
        self._max_turn_receipt_bytes = receipt_bytes
        self._h: OrderedDict[str, deque[dict[str, str]]] = OrderedDict()
        # 本轮 served model 记忆（供 👍/👎 反馈把评价记到具体模型头上）：只留内存最近一条，
        # 不落库——反馈钩子是「锦上添花」，重启后拿不到就跳过（不瞎猜模型）。
        self._last_model: OrderedDict[str, str] = OrderedDict()
        self._conn: sqlite3.Connection | None = None
        self._data_version: int | None = None
        self._lock = threading.Lock()
        self._turn_results: dict[str, tuple[str, dict[str, Any]]] = {}
        if db_path:
            connection: sqlite3.Connection | None = None
            try:
                p = Path(os.path.abspath(os.fspath(db_path)))
                self._assert_safe_database_path(p, require_database=False)
                p.parent.mkdir(parents=True, exist_ok=True)
                self._assert_safe_database_path(p, require_database=False)
                (
                    preflight_generation,
                    preflight_identity,
                    preflight_family,
                ) = self._stabilized_database_preflight(p)
                if self._database_family_presence(p) != preflight_family:
                    (
                        preflight_generation,
                        preflight_identity,
                        preflight_family,
                    ) = self._stabilized_database_preflight(p)
                connection = sqlite3.connect(
                    str(p), check_same_thread=False, timeout=5.0
                )
                self._conn = connection
                self._assert_safe_database_path(p, require_database=True)
                connection.execute("PRAGMA busy_timeout=5000")
                connection.execute("PRAGMA trusted_schema=OFF")
                self._begin_initialization_transaction(connection)
                schema_generation = _conversation_database_generation(connection)
                expected_generation = (
                    "empty" if preflight_generation == "missing" else preflight_generation
                )
                peer_converged = (
                    expected_generation != "current"
                    and schema_generation == "current"
                )
                if schema_generation != expected_generation and not peer_converged:
                    raise sqlite3.DatabaseError(
                        "conversation database changed during initialization"
                    )
                opened_identity = os.lstat(p)
                if preflight_identity is not None and not os.path.samestat(
                    preflight_identity, opened_identity
                ):
                    raise sqlite3.DatabaseError(
                        "conversation database identity changed before locked open"
                    )
                page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
                max_pages = self._max_database_bytes // page_size
                page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
                configured = int(
                    connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0]
                )
                if configured != max_pages or page_count > max_pages:
                    raise RuntimeError("existing conversation database exceeds capacity")
                existing_conv = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='conv'"
                ).fetchone()
                self._initialize_schema(
                    connection,
                    existing_conv,
                    schema_generation=schema_generation,
                )
                connection.execute(
                    f"PRAGMA application_id={_CONVERSATION_APPLICATION_ID}"
                )
                connection.execute(
                    f"PRAGMA user_version={_CONVERSATION_SCHEMA_VERSION}"
                )
                if _conversation_database_generation(connection) != "current":
                    raise RuntimeError("conversation migration did not produce current schema")
                self._validate_runtime_contract(connection)
                # Capture the external-change baseline while BEGIN IMMEDIATE still
                # excludes another writer.  Sampling after COMMIT can absorb a
                # concurrent commit into the baseline without validating it.
                self._data_version = int(
                    connection.execute("PRAGMA data_version").fetchone()[0]
                )
                connection.commit()

                # Only a locked, exact family match may reach persistent runtime
                # profile changes.  Unknown/lookalike databases returned above
                # without changing their main file or creating SQLite sidecars.
                self._ensure_initialization_wal_mode(connection)
                connection.execute("PRAGMA synchronous=FULL")
                self._assert_safe_database_path(p, require_database=True)
                if int(connection.execute("PRAGMA page_count").fetchone()[0]) > max_pages:
                    raise RuntimeError("conversation database exceeded capacity during setup")
            except Exception as exc:
                if connection is not None:
                    try:
                        connection.rollback()
                    finally:
                        connection.close()
                self._conn = None
                raise ConversationReceiptUnavailable(
                    "cannot initialize bounded conversation database"
                ) from exc

    @staticmethod
    def _is_reparse(info: os.stat_result) -> bool:
        return bool(
            int(getattr(info, "st_file_attributes", 0))
            & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        ) or stat.S_ISLNK(info.st_mode)

    @classmethod
    def _assert_safe_database_path(
        cls, path: Path, *, require_database: bool
    ) -> None:
        """Reject symlinks/junctions in the lexical DB chain and sidecars."""

        if not path.is_absolute():
            raise OSError("conversation database path must be absolute")
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                break
            if cls._is_reparse(info):
                raise OSError("conversation database path contains a reparse point")
            if current != path and not stat.S_ISDIR(info.st_mode):
                raise OSError("conversation database parent is not a directory")
            if current == path and not stat.S_ISREG(info.st_mode):
                raise OSError("conversation database is not a regular file")
        if require_database and not path.exists():
            raise OSError("conversation database was not created")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            try:
                info = sidecar.lstat()
            except FileNotFoundError:
                continue
            if cls._is_reparse(info) or not stat.S_ISREG(info.st_mode):
                raise OSError("conversation database sidecar is not a regular file")

    @classmethod
    def _database_family_presence(cls, path: Path) -> dict[str, bool]:
        cls._assert_safe_database_path(path, require_database=False)
        return {
            suffix: Path(f"{path}{suffix}").is_file()
            for suffix in ("", "-wal", "-shm", "-journal")
        }

    @staticmethod
    def _is_transient_sqlite_lock(exc: sqlite3.OperationalError) -> bool:
        code = getattr(exc, "sqlite_errorcode", None)
        if isinstance(code, int) and (code & 0xFF) in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }:
            return True
        rendered = str(exc).casefold()
        return "locked" in rendered or "busy" in rendered

    @classmethod
    def _begin_initialization_transaction(
        cls, connection: sqlite3.Connection
    ) -> None:
        for attempt in range(3):
            try:
                connection.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.OperationalError as exc:
                if attempt >= 2 or not cls._is_transient_sqlite_lock(exc):
                    raise
                time.sleep(0.025 * (2**attempt))

    @classmethod
    def _ensure_initialization_wal_mode(
        cls, connection: sqlite3.Connection
    ) -> None:
        for attempt in range(3):
            try:
                row = connection.execute("PRAGMA journal_mode=WAL").fetchone()
                if row and str(row[0]).casefold() == "wal":
                    return
            except sqlite3.OperationalError as exc:
                if attempt >= 2 or not cls._is_transient_sqlite_lock(exc):
                    raise
            if attempt < 2:
                time.sleep(0.025 * (2**attempt))
        raise RuntimeError("conversation database WAL mode unavailable")

    @classmethod
    def _preflight_database_generation(
        cls, path: Path
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        presence = cls._database_family_presence(path)
        if not presence[""]:
            if any(presence[suffix] for suffix in ("-wal", "-shm", "-journal")):
                raise _ConversationDatabaseFamilyChanged(
                    "conversation main database is missing beside unstable sidecars"
                )
            return "missing", None, presence
        if presence["-journal"]:
            raise _ConversationDatabaseFamilyChanged(
                "conversation rollback journal has not stabilized"
            )
        if presence["-wal"] != presence["-shm"]:
            raise _ConversationDatabaseFamilyChanged(
                "conversation WAL and SHM sidecars have not stabilized"
            )
        identity = os.lstat(path)
        readonly_uri = path.as_uri() + (
            "?mode=ro" if presence["-wal"] else "?mode=ro&immutable=1"
        )
        with closing(
            sqlite3.connect(
                readonly_uri,
                uri=True,
                timeout=5.0,
                isolation_level=None,
            )
        ) as candidate:
            candidate.execute("PRAGMA busy_timeout=5000")
            candidate.execute("PRAGMA query_only=ON")
            candidate.execute("PRAGMA trusted_schema=OFF")
            candidate.execute("BEGIN")
            try:
                generation = _conversation_database_generation(candidate)
            finally:
                candidate.rollback()
        if cls._database_family_presence(path) != presence:
            raise _ConversationDatabaseFamilyChanged(
                "conversation database family changed during read-only preflight"
            )
        try:
            current_identity = os.lstat(path)
        except FileNotFoundError as exc:
            raise _ConversationDatabaseFamilyChanged(
                "conversation database disappeared during read-only preflight"
            ) from exc
        if not os.path.samestat(identity, current_identity):
            raise _ConversationDatabaseFamilyChanged(
                "conversation database identity changed during read-only preflight"
            )
        return generation, identity, presence

    @classmethod
    def _stabilized_database_preflight(
        cls, path: Path
    ) -> tuple[str, os.stat_result | None, dict[str, bool]]:
        last_change: _ConversationDatabaseFamilyChanged | None = None
        # Exact first-open schema materialization can keep an honest rollback
        # journal visible for several seconds on a loaded Windows host.  The
        # wait remains bounded and read-only; a stable foreign journal fails.
        deadline = time.monotonic() + 10.0
        while True:
            try:
                return cls._preflight_database_generation(path)
            except _ConversationDatabaseFamilyChanged as exc:
                last_change = exc
                if time.monotonic() < deadline:
                    time.sleep(0.025)
                    continue
                break
        raise sqlite3.DatabaseError(
            "conversation database family did not stabilize during preflight"
        ) from last_change

    @staticmethod
    def _explicit_indexes(
        connection: sqlite3.Connection, table: str
    ) -> dict[str, str]:
        return {
            str(name): str(sql)
            for name, sql in connection.execute(
                "SELECT name,sql FROM sqlite_master "
                "WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
                (table,),
            ).fetchall()
        }

    @staticmethod
    def _validate_index_set(
        connection: sqlite3.Connection,
        table: str,
        expected: dict[str, str],
        *,
        allow_missing: bool = False,
    ) -> None:
        actual = ConversationStore._explicit_indexes(connection, table)
        if set(actual) - set(expected):
            raise RuntimeError(f"unrecognized {table} index schema")
        if not allow_missing and set(actual) != set(expected):
            raise RuntimeError(f"missing {table} index schema")
        for name, sql in actual.items():
            if _normalized_schema_sql(sql) != _normalized_schema_sql(expected[name]):
                raise RuntimeError(f"unrecognized {table} index schema")

    @staticmethod
    def _validate_table_xinfo(
        connection: sqlite3.Connection,
        table: str,
        expected: tuple[tuple[str, str, int, Any, int, int], ...],
    ) -> None:
        rows = connection.execute(f"PRAGMA table_xinfo('{table}')").fetchall()
        actual = tuple(
            (str(row[1]), str(row[2]).upper(), int(row[3]), row[4], int(row[5]), int(row[6]))
            for row in rows
        )
        if actual != expected:
            raise RuntimeError(f"unrecognized {table} column contract")

    @staticmethod
    def _validate_index_columns(
        connection: sqlite3.Connection,
        table: str,
        name: str,
        columns: tuple[str, ...],
    ) -> None:
        listed = {
            str(row[1]): (int(row[2]), str(row[3]), int(row[4]))
            for row in connection.execute(f"PRAGMA index_list('{table}')").fetchall()
        }
        if listed.get(name) != (0, "c", 0):
            raise RuntimeError(f"unrecognized {table} index contract")
        key_columns = tuple(
            str(row[2])
            for row in connection.execute(f"PRAGMA index_xinfo('{name}')").fetchall()
            if int(row[5]) == 1
        )
        if key_columns != columns:
            raise RuntimeError(f"unrecognized {table} index columns")

    @staticmethod
    def _capacity_trigger_rows(connection: sqlite3.Connection) -> dict[str, str]:
        return {
            str(name): str(sql)
            for name, sql in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name IN ('conv','agent_turn_receipt',"
                "'agent_turn_reservation','conversation_capacity_meta')"
            ).fetchall()
        }

    def _drop_capacity_contract_for_migration(
        self,
        connection: sqlite3.Connection,
        *,
        expected_meta_sql: str,
        expected_triggers: dict[str, str],
    ) -> None:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='conversation_capacity_meta'"
        ).fetchone()
        triggers = self._capacity_trigger_rows(connection)
        if row is None:
            if triggers:
                raise RuntimeError("capacity triggers exist without trusted metadata")
            return
        if _normalized_schema_sql(str(row[0])) != _normalized_schema_sql(
            expected_meta_sql
        ):
            raise RuntimeError("unrecognized conversation capacity metadata schema")
        if set(triggers) != set(expected_triggers):
            raise RuntimeError("conversation capacity trigger set is incomplete")
        for name, sql in triggers.items():
            if _normalized_schema_sql(sql) != _normalized_schema_sql(
                expected_triggers[name]
            ):
                raise RuntimeError("unrecognized conversation capacity trigger schema")
        for name in sorted(expected_triggers):
            connection.execute(f'DROP TRIGGER "{name}"')
        connection.execute("DROP TABLE conversation_capacity_meta")

    @staticmethod
    def _validate_schema_closed_set(connection: sqlite3.Connection) -> None:
        current_declarations = next(
            declarations
            for name, declarations in _conversation_schema_variants()
            if name == "current"
        )
        expected = _materialized_conversation_schema_objects(current_declarations)
        if _actual_conversation_schema_objects(connection) != expected:
            raise RuntimeError("conversation database schema is not exact current authority")

    @staticmethod
    def _actual_capacity_usage(
        connection: sqlite3.Connection,
    ) -> tuple[int, int, int, int, int, int]:
        row = connection.execute(
            "SELECT (SELECT COUNT(*) FROM conv),"
            "(SELECT COALESCE(SUM(length(CAST(key AS BLOB))+"
            "length(CAST(role AS BLOB))+length(CAST(content AS BLOB))),0) FROM conv),"
            "(SELECT COUNT(*) FROM agent_turn_receipt),"
            "(SELECT COALESCE(SUM(length(CAST(turn_key AS BLOB))+"
            "length(CAST(request_sha256 AS BLOB))+"
            "length(CAST(response_json AS BLOB))),0) FROM agent_turn_receipt),"
            "(SELECT COUNT(*) FROM agent_turn_reservation "
            "WHERE state!='abandoned'),"
            "(SELECT COALESCE(SUM(reserved_payload_bytes),0) "
            "FROM agent_turn_reservation WHERE state!='abandoned')"
        ).fetchone()
        if row is None or any(type(value) is not int or value < 0 for value in row):
            raise RuntimeError("conversation capacity baseline is corrupt")
        return tuple(row)  # type: ignore[return-value]

    def _verify_capacity_totals(self, connection: sqlite3.Connection) -> None:
        if self._capacity_usage(connection) != self._actual_capacity_usage(connection):
            raise RuntimeError("conversation capacity metadata does not match stored rows")
        overlap = connection.execute(
            "SELECT 1 FROM agent_turn_receipt r JOIN agent_turn_reservation p "
            "ON p.turn_key=r.turn_key LIMIT 1"
        ).fetchone()
        if overlap is not None:
            raise RuntimeError("committed receipt overlaps an active reservation")

    def _verify_receipt_capacity_contract(
        self, connection: sqlite3.Connection
    ) -> None:
        row = connection.execute(
            "SELECT receipt_contract_version,max_turn_receipts,"
            "max_turn_receipt_bytes,typeof(receipt_contract_version),"
            "typeof(max_turn_receipts),typeof(max_turn_receipt_bytes) "
            "FROM conversation_capacity_meta WHERE singleton=1"
        ).fetchone()
        expected = (
            1,
            self._max_turn_receipts,
            self._max_turn_receipt_bytes,
            "integer",
            "integer",
            "integer",
        )
        if row != expected:
            raise RuntimeError("durable Turn receipt capacity contract changed")
        (
            _conv_rows,
            _conv_bytes,
            receipt_rows,
            receipt_bytes,
            reservation_rows,
            reservation_bytes,
        ) = self._capacity_usage(connection)
        if (
            receipt_rows + reservation_rows > self._max_turn_receipts
            or receipt_bytes + reservation_bytes > self._max_turn_receipt_bytes
        ):
            raise RuntimeError("durable Turn receipt usage exceeds its capacity contract")

    def _validate_runtime_contract(self, connection: sqlite3.Connection) -> None:
        if _conversation_database_generation(connection) != "current":
            raise RuntimeError("conversation database identity changed")
        expected_tables = {
            "conv": _CONV_SCHEMA_SQL,
            "agent_turn_receipt": _TURN_RECEIPT_SCHEMA_SQL,
            "agent_turn_reservation": _TURN_RESERVATION_SCHEMA_SQL,
            "conversation_capacity_meta": _CAPACITY_META_SCHEMA_SQL,
        }
        rows = {
            str(name): str(sql)
            for name, sql in connection.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='table' "
                "AND name IN ('conv','agent_turn_receipt','agent_turn_reservation',"
                "'conversation_capacity_meta')"
            ).fetchall()
        }
        if set(rows) != set(expected_tables) or any(
            _normalized_schema_sql(rows[name])
            != _normalized_schema_sql(expected_tables[name])
            for name in expected_tables
        ):
            raise RuntimeError("conversation database table contract changed")
        self._validate_index_set(
            connection, "conv", {"idx_conv_key": _CONV_INDEX_SQL}
        )
        self._validate_index_set(
            connection,
            "agent_turn_receipt",
            {"idx_agent_turn_receipt_created_at": _TURN_RECEIPT_INDEX_SQL},
        )
        self._validate_index_set(connection, "agent_turn_reservation", {})
        triggers = self._capacity_trigger_rows(connection)
        if set(triggers) != set(_CAPACITY_TRIGGER_SQL) or any(
            _normalized_schema_sql(triggers[name])
            != _normalized_schema_sql(_CAPACITY_TRIGGER_SQL[name])
            for name in _CAPACITY_TRIGGER_SQL
        ):
            raise RuntimeError("conversation database trigger contract changed")
        self._validate_schema_closed_set(connection)
        self._verify_capacity_totals(connection)
        self._verify_receipt_capacity_contract(connection)

    def _revalidate_if_external_change(
        self, connection: sqlite3.Connection
    ) -> None:
        current = int(connection.execute("PRAGMA data_version").fetchone()[0])
        if self._data_version is None or current != self._data_version:
            self._validate_runtime_contract(connection)
            # Only discard process-local state after the external commit has
            # passed the full schema/counter contract.  Otherwise a corrupt
            # writer could both make the read fail and silently erase the
            # last known-good cache.  Served-model attribution is also cleared:
            # after another writer changes a session, retaining it could attach
            # feedback to the wrong Turn/model.
            self._h.clear()
            self._last_model.clear()
            self._data_version = current

    def _initialize_capacity_meta(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='conversation_capacity_meta'"
        ).fetchone()
        trigger_rows = self._capacity_trigger_rows(connection)
        unknown_triggers = set(trigger_rows) - set(_CAPACITY_TRIGGER_SQL)
        if unknown_triggers:
            raise RuntimeError("unrecognized conversation capacity trigger")

        if row is None:
            if trigger_rows:
                raise RuntimeError("capacity triggers exist without trusted metadata")
            connection.execute(_CAPACITY_META_SCHEMA_SQL)
            connection.execute(
                "INSERT INTO conversation_capacity_meta("
                "singleton,conv_rows,conv_payload_bytes,receipt_rows,receipt_payload_bytes,"
                "reservation_rows,reservation_payload_bytes,receipt_contract_version,"
                "max_turn_receipts,max_turn_receipt_bytes) "
                "SELECT 1,"
                "(SELECT COUNT(*) FROM conv),"
                "(SELECT COALESCE(SUM(length(CAST(key AS BLOB))+"
                "length(CAST(role AS BLOB))+length(CAST(content AS BLOB))),0) FROM conv),"
                "(SELECT COUNT(*) FROM agent_turn_receipt),"
                "(SELECT COALESCE(SUM(length(CAST(turn_key AS BLOB))+"
                "length(CAST(request_sha256 AS BLOB))+"
                "length(CAST(response_json AS BLOB))),0) FROM agent_turn_receipt),"
                "(SELECT COUNT(*) FROM agent_turn_reservation "
                "WHERE state!='abandoned'),"
                "(SELECT COALESCE(SUM(reserved_payload_bytes),0) "
                "FROM agent_turn_reservation WHERE state!='abandoned'),1,?,?",
                (self._max_turn_receipts, self._max_turn_receipt_bytes),
            )
            for sql in _CAPACITY_TRIGGER_SQL.values():
                connection.execute(sql)
        else:
            if _normalized_schema_sql(str(row[0])) != _normalized_schema_sql(
                _CAPACITY_META_SCHEMA_SQL
            ):
                raise RuntimeError("unrecognized conversation capacity metadata schema")
            if set(trigger_rows) != set(_CAPACITY_TRIGGER_SQL):
                raise RuntimeError("conversation capacity trigger set is incomplete")
            for name, sql in trigger_rows.items():
                if _normalized_schema_sql(sql) != _normalized_schema_sql(
                    _CAPACITY_TRIGGER_SQL[name]
                ):
                    raise RuntimeError("unrecognized conversation capacity trigger schema")

        self._validate_table_xinfo(
            connection,
            "conversation_capacity_meta",
            (
                ("singleton", "INTEGER", 1, None, 1, 0),
                ("conv_rows", "INTEGER", 1, None, 0, 0),
                ("conv_payload_bytes", "INTEGER", 1, None, 0, 0),
                ("receipt_rows", "INTEGER", 1, None, 0, 0),
                ("receipt_payload_bytes", "INTEGER", 1, None, 0, 0),
                ("reservation_rows", "INTEGER", 1, None, 0, 0),
                ("reservation_payload_bytes", "INTEGER", 1, None, 0, 0),
                ("receipt_contract_version", "INTEGER", 1, None, 0, 0),
                ("max_turn_receipts", "INTEGER", 1, None, 0, 0),
                ("max_turn_receipt_bytes", "INTEGER", 1, None, 0, 0),
            ),
        )
        meta_rows = connection.execute(
            "SELECT singleton,typeof(conv_rows),typeof(conv_payload_bytes),"
            "typeof(receipt_rows),typeof(receipt_payload_bytes),"
            "typeof(reservation_rows),typeof(reservation_payload_bytes),"
            "typeof(receipt_contract_version),typeof(max_turn_receipts),"
            "typeof(max_turn_receipt_bytes) "
            "FROM conversation_capacity_meta"
        ).fetchall()
        if meta_rows != [
            (
                1,
                "integer",
                "integer",
                "integer",
                "integer",
                "integer",
                "integer",
                "integer",
                "integer",
                "integer",
            )
        ]:
            raise RuntimeError("conversation capacity metadata row is corrupt")
        self._verify_receipt_capacity_contract(connection)
        self._validate_index_set(
            connection, "conversation_capacity_meta", {}
        )
        self._verify_capacity_totals(connection)

    def _initialize_schema(
        self,
        connection: sqlite3.Connection,
        existing_conv: tuple[Any, ...] | None,
        *,
        schema_generation: str,
    ) -> None:
        receipt = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='agent_turn_receipt'"
        ).fetchone()
        reservation = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='agent_turn_reservation'"
        ).fetchone()
        meta = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='conversation_capacity_meta'"
        ).fetchone()
        conv_normalized = (
            None
            if existing_conv is None
            else _normalized_schema_sql(str(existing_conv[0]))
        )
        receipt_normalized = (
            None if receipt is None else _normalized_schema_sql(str(receipt[0]))
        )
        reservation_normalized = (
            None
            if reservation is None
            else _normalized_schema_sql(str(reservation[0]))
        )
        meta_normalized = (
            None if meta is None else _normalized_schema_sql(str(meta[0]))
        )
        # The caller classified the complete materialized sqlite_master tuple
        # (type, name, tbl_name, sql) while holding BEGIN IMMEDIATE.  Reuse that
        # exact generation here instead of weakening migration routing back to
        # a names-only object set.
        schema_state = schema_generation
        migratable_conv = {
            _normalized_schema_sql(_CONV_LEGACY_SCHEMA_SQL),
            _normalized_schema_sql(_CONV_V2_SCHEMA_SQL),
        }
        if conv_normalized not in {
            None,
            _normalized_schema_sql(_CONV_SCHEMA_SQL),
            *migratable_conv,
        }:
            raise RuntimeError("unrecognized conversation table schema")
        if receipt_normalized not in {
            None,
            _normalized_schema_sql(_TURN_RECEIPT_SCHEMA_SQL),
            _normalized_schema_sql(_TURN_RECEIPT_V1_SCHEMA_SQL),
        }:
            raise RuntimeError("unrecognized durable Turn receipt table schema")
        if reservation_normalized not in {
            None,
            _normalized_schema_sql(_TURN_RESERVATION_SCHEMA_SQL),
            _normalized_schema_sql(_TURN_RESERVATION_V1_SCHEMA_SQL),
        }:
            raise RuntimeError("unrecognized durable Turn reservation table schema")
        if meta_normalized not in {
            None,
            _normalized_schema_sql(_CAPACITY_META_SCHEMA_SQL),
            _normalized_schema_sql(_CAPACITY_META_V3_SCHEMA_SQL),
            _normalized_schema_sql(_CAPACITY_META_V2_SCHEMA_SQL),
            _normalized_schema_sql(_CAPACITY_META_V1_SCHEMA_SQL),
        }:
            raise RuntimeError("unrecognized conversation capacity metadata schema")

        if schema_state == "previous_strict":
            self._drop_capacity_contract_for_migration(
                connection,
                expected_meta_sql=_CAPACITY_META_V2_SCHEMA_SQL,
                expected_triggers=_CAPACITY_TRIGGER_V2_SQL,
            )
        elif schema_state == "previous_legacy_strict":
            self._drop_capacity_contract_for_migration(
                connection,
                expected_meta_sql=_CAPACITY_META_V1_SCHEMA_SQL,
                expected_triggers=_CAPACITY_TRIGGER_V2_SQL,
            )
        elif schema_state == "previous_reservation":
            self._drop_capacity_contract_for_migration(
                connection,
                expected_meta_sql=_CAPACITY_META_V3_SCHEMA_SQL,
                expected_triggers=_CAPACITY_TRIGGER_V3_SQL,
            )
        elif schema_state == "previous_abandoned":
            self._drop_capacity_contract_for_migration(
                connection,
                expected_meta_sql=_CAPACITY_META_V3_SCHEMA_SQL,
                expected_triggers=_CAPACITY_TRIGGER_SQL,
            )

        if existing_conv is None:
            connection.execute(_CONV_SCHEMA_SQL)
            connection.execute(_CONV_INDEX_SQL)
        else:
            if conv_normalized in migratable_conv:
                self._validate_index_set(
                    connection,
                    "conv",
                    {"idx_conv_key": _CONV_INDEX_SQL},
                    allow_missing=True,
                )
                corrupt = connection.execute(
                    "SELECT 1 FROM conv WHERE "
                    "typeof(key)!='text' OR typeof(role)!='text' "
                    "OR length(CAST(key AS BLOB)) NOT BETWEEN 1 AND 4096 "
                    "OR role NOT IN ('user','assistant') "
                    "OR typeof(content)!='text' "
                    "OR length(CAST(content AS BLOB))>? "
                    "OR typeof(ts) NOT IN ('integer','real') "
                    "LIMIT 1",
                    (self._max_content_bytes,),
                ).fetchone()
                if corrupt is not None:
                    raise RuntimeError("legacy conversation rows are corrupt")
                collision = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='conv_legacy_v1'"
                ).fetchone()
                if collision is not None:
                    raise RuntimeError("legacy conversation migration name collision")
                connection.execute("DROP INDEX IF EXISTS idx_conv_key")
                connection.execute("ALTER TABLE conv RENAME TO conv_legacy_v1")
                connection.execute(_CONV_SCHEMA_SQL)
                connection.execute(
                    "INSERT INTO conv(id,key,role,content,ts) "
                    "SELECT id,key,role,content,ts FROM conv_legacy_v1 ORDER BY id"
                )
                connection.execute("DROP TABLE conv_legacy_v1")
                connection.execute(_CONV_INDEX_SQL)
            elif conv_normalized == _normalized_schema_sql(_CONV_SCHEMA_SQL):
                self._validate_index_set(
                    connection,
                    "conv",
                    {"idx_conv_key": _CONV_INDEX_SQL},
                )
            else:
                raise RuntimeError("unrecognized conversation table schema")

        if receipt is None:
            connection.execute(_TURN_RECEIPT_SCHEMA_SQL)
            connection.execute(_TURN_RECEIPT_INDEX_SQL)
        elif receipt_normalized == _normalized_schema_sql(
            _TURN_RECEIPT_V1_SCHEMA_SQL
        ):
            self._validate_index_set(
                connection,
                "agent_turn_receipt",
                {"idx_agent_turn_receipt_created_at": _TURN_RECEIPT_INDEX_SQL},
                allow_missing=True,
            )
            for turn_key, request_sha256, response_json, created_at in connection.execute(
                "SELECT turn_key,request_sha256,response_json,created_at "
                "FROM agent_turn_receipt"
            ).fetchall():
                self._validated_turn_digest(turn_key, "turn_key")
                self._validated_turn_digest(request_sha256, "request_sha256")
                if not isinstance(response_json, str):
                    raise RuntimeError("legacy durable Turn receipt is corrupt")
                decoded = json.loads(response_json)
                if (
                    not isinstance(decoded, dict)
                    or len(response_json.encode("utf-8")) > 1024 * 1024
                    or not isinstance(created_at, (int, float))
                    or isinstance(created_at, bool)
                    or not math.isfinite(float(created_at))
                ):
                    raise RuntimeError("legacy durable Turn receipt is corrupt")
            collision = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='agent_turn_receipt_legacy_v1'"
            ).fetchone()
            if collision is not None:
                raise RuntimeError("legacy durable Turn receipt migration collision")
            connection.execute("DROP INDEX IF EXISTS idx_agent_turn_receipt_created_at")
            connection.execute(
                "ALTER TABLE agent_turn_receipt RENAME TO agent_turn_receipt_legacy_v1"
            )
            connection.execute(_TURN_RECEIPT_SCHEMA_SQL)
            connection.execute(
                "INSERT INTO agent_turn_receipt(turn_key,request_sha256,response_json,created_at) "
                "SELECT turn_key,request_sha256,response_json,created_at "
                "FROM agent_turn_receipt_legacy_v1"
            )
            connection.execute("DROP TABLE agent_turn_receipt_legacy_v1")
            connection.execute(_TURN_RECEIPT_INDEX_SQL)
        elif receipt_normalized == _normalized_schema_sql(_TURN_RECEIPT_SCHEMA_SQL):
            self._validate_index_set(
                connection,
                "agent_turn_receipt",
                {
                    "idx_agent_turn_receipt_created_at": _TURN_RECEIPT_INDEX_SQL,
                },
            )
        else:
            raise RuntimeError("unrecognized durable Turn receipt table schema")

        if reservation is None:
            connection.execute(_TURN_RESERVATION_SCHEMA_SQL)
        elif reservation_normalized == _normalized_schema_sql(
            _TURN_RESERVATION_V1_SCHEMA_SQL
        ):
            collision = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE name='agent_turn_reservation_legacy_v1'"
            ).fetchone()
            if collision is not None:
                raise RuntimeError("durable Turn reservation migration collision")
            connection.execute(
                "ALTER TABLE agent_turn_reservation "
                "RENAME TO agent_turn_reservation_legacy_v1"
            )
            connection.execute(_TURN_RESERVATION_SCHEMA_SQL)
            connection.execute(
                "INSERT INTO agent_turn_reservation("
                "turn_key,request_sha256,state,reserved_payload_bytes,created_at,"
                "provider_started_at) "
                "SELECT turn_key,request_sha256,state,reserved_payload_bytes,created_at,"
                "provider_started_at FROM agent_turn_reservation_legacy_v1"
            )
            connection.execute("DROP TABLE agent_turn_reservation_legacy_v1")
        elif reservation_normalized != _normalized_schema_sql(
            _TURN_RESERVATION_SCHEMA_SQL
        ):
            raise RuntimeError("unrecognized durable Turn reservation table schema")

        self._validate_index_set(
            connection,
            "conv",
            {"idx_conv_key": _CONV_INDEX_SQL},
        )
        self._validate_index_set(
            connection,
            "agent_turn_receipt",
            {"idx_agent_turn_receipt_created_at": _TURN_RECEIPT_INDEX_SQL},
        )
        self._validate_index_set(connection, "agent_turn_reservation", {})
        self._validate_table_xinfo(
            connection,
            "conv",
            (
                ("id", "INTEGER", 0, None, 1, 0),
                ("key", "TEXT", 1, None, 0, 0),
                ("role", "TEXT", 1, None, 0, 0),
                ("content", "TEXT", 1, None, 0, 0),
                ("ts", "REAL", 1, None, 0, 0),
            ),
        )
        self._validate_table_xinfo(
            connection,
            "agent_turn_receipt",
            (
                ("turn_key", "TEXT", 1, None, 1, 0),
                ("request_sha256", "TEXT", 1, None, 0, 0),
                ("response_json", "TEXT", 1, None, 0, 0),
                ("created_at", "REAL", 1, None, 0, 0),
            ),
        )
        self._validate_table_xinfo(
            connection,
            "agent_turn_reservation",
            (
                ("turn_key", "TEXT", 1, None, 1, 0),
                ("request_sha256", "TEXT", 1, None, 0, 0),
                ("state", "TEXT", 1, None, 0, 0),
                ("reserved_payload_bytes", "INTEGER", 1, None, 0, 0),
                ("created_at", "REAL", 1, None, 0, 0),
                ("provider_started_at", "REAL", 0, None, 0, 0),
            ),
        )
        self._validate_index_columns(
            connection, "conv", "idx_conv_key", ("key", "id")
        )
        self._validate_index_columns(
            connection,
            "agent_turn_receipt",
            "idx_agent_turn_receipt_created_at",
            ("created_at", "turn_key"),
        )
        self._initialize_capacity_meta(connection)
        self._validate_schema_closed_set(connection)

    def _slot(self, key: str) -> deque[dict[str, str]]:
        d = self._h.get(key)
        if d is None:
            d = deque(maxlen=self._max * 2)
            if self._conn is not None:
                try:
                    rows = self._conn.execute(
                        "SELECT role,content FROM conv WHERE key=? "
                        "ORDER BY id DESC LIMIT ?",
                        (key, self._max * 2),
                    ).fetchall()
                    d.extend(
                        {
                            "role": self._validated_role(role),
                            "content": self._validated_content(content),
                        }
                        for role, content in reversed(rows)
                    )
                except (sqlite3.Error, TypeError, ValueError) as exc:
                    raise ConversationReceiptUnavailable(
                        "cannot load trusted conversation history"
                    ) from exc
            self._h[key] = d
            while len(self._h) > self._max_cached_sessions:
                evicted_key, _ = self._h.popitem(last=False)
                self._last_model.pop(evicted_key, None)
        else:
            self._h.move_to_end(key)
        return d

    def get(self, key: str) -> list[dict[str, str]]:
        key = self._validated_key(key)
        with self._lock:
            if self._conn is not None:
                try:
                    self._revalidate_if_external_change(self._conn)
                except Exception as exc:  # noqa: BLE001
                    raise ConversationReceiptUnavailable(
                        "cannot load trusted conversation history"
                    ) from exc
            return [dict(item) for item in self._slot(key)]

    def _validated_content(self, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("content must be UTF-8 text")
        content = value
        try:
            size = len(content.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("content is not valid UTF-8") from exc
        if size > self._max_content_bytes:
            raise ValueError(
                f"content exceeds {self._max_content_bytes} UTF-8 bytes"
            )
        return content

    @staticmethod
    def _validated_role(value: Any) -> str:
        if not isinstance(value, str) or value not in ("user", "assistant"):
            raise ValueError("conversation role must be user or assistant")
        return value

    @staticmethod
    def _validated_key(value: Any) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("conversation key must be non-empty UTF-8 text")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("conversation key must be non-empty UTF-8 text") from exc
        if len(encoded) > 4096:
            raise ValueError("conversation key exceeds 4096 UTF-8 bytes")
        return value

    @staticmethod
    def _validated_model(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("served model must be UTF-8 text")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("served model must be UTF-8 text") from exc
        if len(encoded) > 4096:
            raise ValueError("served model exceeds 4096 UTF-8 bytes")
        return value

    @staticmethod
    def _conversation_payload_bytes(key: str, role: str, content: str) -> int:
        return len(key.encode("utf-8")) + len(role.encode("utf-8")) + len(
            content.encode("utf-8")
        )

    @staticmethod
    def _capacity_usage(
        connection: sqlite3.Connection,
    ) -> tuple[int, int, int, int, int, int]:
        row = connection.execute(
            "SELECT conv_rows,conv_payload_bytes,receipt_rows,receipt_payload_bytes,"
            "reservation_rows,reservation_payload_bytes,"
            "typeof(conv_rows),typeof(conv_payload_bytes),typeof(receipt_rows),"
            "typeof(receipt_payload_bytes),typeof(reservation_rows),"
            "typeof(reservation_payload_bytes) FROM conversation_capacity_meta "
            "WHERE singleton=1"
        ).fetchone()
        if (
            row is None
            or tuple(row[6:])
            != ("integer", "integer", "integer", "integer", "integer", "integer")
            or any(int(value) < 0 for value in row[:6])
        ):
            raise sqlite3.DatabaseError("conversation capacity metadata is corrupt")
        return tuple(int(value) for value in row[:6])  # type: ignore[return-value]

    def _prepare_conversation_entries(
        self,
        connection: sqlite3.Connection,
        entries: list[tuple[str, str, str]],
    ) -> set[str]:
        """Reserve exact row/UTF-8 budgets and return whole sessions reclaimed."""

        if not entries:
            return set()
        protected = tuple(dict.fromkeys(key for key, _role, _content in entries))
        incoming_by_key: dict[str, int] = {}
        for key, _role, _content in entries:
            incoming_by_key[key] = incoming_by_key.get(key, 0) + 1
        for key, incoming_count in incoming_by_key.items():
            keep = max(0, self._max * 2 - incoming_count)
            if keep == 0:
                connection.execute("DELETE FROM conv WHERE key=?", (key,))
            else:
                connection.execute(
                    "DELETE FROM conv WHERE key=? AND id NOT IN ("
                    "SELECT id FROM conv WHERE key=? ORDER BY id DESC LIMIT ?)",
                    (key, key, keep),
                )

        incoming_rows = len(entries)
        incoming_bytes = sum(
            self._conversation_payload_bytes(key, role, content)
            for key, role, content in entries
        )
        if (
            incoming_rows > self._max_conversation_rows
            or incoming_bytes > self._max_conversation_bytes
        ):
            raise ConversationReceiptUnavailable(
                "conversation write exceeds the configured global budget"
            )

        reclaimed: set[str] = set()
        while True:
            conv_rows, conv_bytes, *_ = self._capacity_usage(connection)
            if (
                conv_rows + incoming_rows <= self._max_conversation_rows
                and conv_bytes + incoming_bytes <= self._max_conversation_bytes
            ):
                return reclaimed
            placeholders = ",".join("?" for _ in protected)
            victim = connection.execute(
                "SELECT key FROM conv WHERE key NOT IN ("
                + placeholders
                + ") ORDER BY id LIMIT 1",
                protected,
            ).fetchone()
            if victim is None or not isinstance(victim[0], str):
                raise ConversationReceiptUnavailable(
                    "conversation capacity is exhausted by protected active sessions"
                )
            victim_key = victim[0]
            connection.execute("DELETE FROM conv WHERE key=?", (victim_key,))
            reclaimed.add(victim_key)

    @staticmethod
    def _receipt_payload_bytes(
        turn_key: str, request_sha256: str, encoded: str
    ) -> int:
        return (
            len(turn_key.encode("utf-8"))
            + len(request_sha256.encode("utf-8"))
            + len(encoded.encode("utf-8"))
        )

    def _prepare_turn_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        turn_key: str,
        request_sha256: str,
        encoded: str,
        current: float,
    ) -> None:
        # A receipt is replay authority for the full protected window.  Only
        # genuinely expired rows are reclaimable; fresh receipts are never
        # evicted merely to admit a newer request.
        connection.execute(
            "DELETE FROM agent_turn_receipt WHERE created_at < ?",
            (current - 30 * 24 * 60 * 60,),
        )
        (
            _conv_rows,
            _conv_bytes,
            receipt_rows,
            receipt_bytes,
            reservation_rows,
            reservation_bytes,
        ) = self._capacity_usage(connection)
        incoming = self._receipt_payload_bytes(turn_key, request_sha256, encoded)
        if (
            receipt_rows + reservation_rows + 1 > self._max_turn_receipts
            or receipt_bytes + reservation_bytes + incoming
            > self._max_turn_receipt_bytes
        ):
            raise ConversationReceiptUnavailable(
                "protected durable Turn receipt window is full"
            )

    def append(self, key: str, role: str, content: str) -> None:
        key = self._validated_key(key)
        role = self._validated_role(role)
        content = self._validated_content(content)
        with self._lock:
            if self._conn is None:
                self._slot(key).append({"role": role, "content": content})
                if role == "assistant":
                    self._last_model.pop(key, None)
                return
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(self._conn)
                reclaimed = self._prepare_conversation_entries(
                    self._conn, [(key, role, content)]
                )
                self._conn.execute(
                    "INSERT INTO conv (key, role, content, ts) VALUES (?,?,?,?)",
                    (key, role, content, time.time()),
                )
                # 每会话只留最近 max*2 条，老的删掉，库不无限涨
                self._conn.execute(
                    "DELETE FROM conv WHERE key=? AND id NOT IN "
                    "(SELECT id FROM conv WHERE key=? ORDER BY id DESC LIMIT ?)",
                    (key, key, self._max * 2),
                )
                self._conn.commit()
            except Exception as exc:  # noqa: BLE001
                try:
                    self._conn.rollback()
                except Exception:  # noqa: BLE001
                    pass
                raise ConversationReceiptUnavailable(
                    "cannot persist conversation history"
                ) from exc
            for reclaimed_key in reclaimed:
                self._h.pop(reclaimed_key, None)
                self._last_model.pop(reclaimed_key, None)
            cached = self._h.get(key)
            if cached is not None:
                cached.append({"role": role, "content": content})
                self._h.move_to_end(key)
            if role == "assistant":
                # Appending a new assistant row invalidates the previous
                # Turn's author by default. A verified provider path sets the
                # new author only after its exact reply has been bound.
                self._last_model.pop(key, None)

    def clear(self, key: str) -> None:
        key = self._validated_key(key)
        with self._lock:
            if self._conn is None:
                self._h.pop(key, None)
                self._last_model.pop(key, None)
                return
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(self._conn)
                self._conn.execute("DELETE FROM conv WHERE key=?", (key,))
                self._conn.commit()
            except Exception as exc:  # noqa: BLE001
                try:
                    self._conn.rollback()
                except Exception:  # noqa: BLE001
                    pass
                raise ConversationReceiptUnavailable(
                    "cannot persist conversation history"
                ) from exc
            self._h.pop(key, None)
            self._last_model.pop(key, None)

    def _remember_last_model(self, key: str, model: str) -> None:
        self._last_model[key] = model
        self._last_model.move_to_end(key)
        while len(self._last_model) > self._max_cached_sessions:
            self._last_model.popitem(last=False)

    def set_last_model(self, key: str, model: str) -> None:
        """记下该会话本轮实际服务的模型（供反馈钩子把 👍/👎 记到具体模型头上）。空模型忽略。"""
        key = self._validated_key(key)
        model = self._validated_model(model)
        if model:
            with self._lock:
                self._remember_last_model(key, model)

    def clear_last_model(self, key: str) -> None:
        """Mark the latest assistant Turn as locally authored and unscoreable."""

        key = self._validated_key(key)
        with self._lock:
            if self._conn is not None:
                try:
                    self._revalidate_if_external_change(self._conn)
                except Exception as exc:  # noqa: BLE001
                    raise ConversationReceiptUnavailable(
                        "cannot clear trusted served-model attribution"
                    ) from exc
            self._last_model.pop(key, None)

    def last_model(self, key: str) -> str | None:
        """该会话最近一轮的 served model；没有则 None（反馈钩子据此决定记不记、绝不瞎猜）。"""
        key = self._validated_key(key)
        with self._lock:
            if self._conn is not None:
                try:
                    self._revalidate_if_external_change(self._conn)
                except Exception as exc:  # noqa: BLE001
                    raise ConversationReceiptUnavailable(
                        "cannot read trusted served-model attribution"
                    ) from exc
            model = self._last_model.get(key)
            if model is not None:
                self._last_model.move_to_end(key)
            return model

    def last_pair(self, key: str) -> tuple[str, str] | None:
        """返回该会话最近一组 (用户问, 助手答)，没有则 None。"""
        key = self._validated_key(key)
        h = self.get(key)
        ai = max((i for i, m in enumerate(h) if m["role"] == "assistant"), default=-1)
        if ai < 0:
            return None
        ui = max((i for i in range(ai) if h[i]["role"] == "user"), default=-1)
        if ui < 0:
            return None
        return h[ui]["content"], h[ai]["content"]

    def close(self) -> None:
        if self._conn is not None:
            with self._lock:
                self._conn.close()

    @staticmethod
    def _validated_turn_digest(value: str, label: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"{label} must be a lowercase SHA-256 digest")
        return value

    @staticmethod
    def _validated_turn_time(value: float | None, label: str) -> float:
        current = time.time() if value is None else float(value)
        if isinstance(value, bool) or not math.isfinite(current):
            raise ValueError(f"{label} must be finite")
        return current

    @staticmethod
    def _validated_reservation_row(row: tuple[Any, ...]) -> tuple[str, str]:
        if len(row) != 6:
            raise RuntimeError("durable Turn reservation is corrupt")
        state, request_sha256, reserved_bytes, created_at, provider_at, response = row
        request = ConversationStore._validated_turn_digest(
            request_sha256, "stored request_sha256"
        )
        if (
            state not in ("reserved", "provider_started", "abandoned")
            or type(reserved_bytes) is not int
            or (
                state in ("reserved", "provider_started")
                and reserved_bytes != _TURN_RESERVATION_PAYLOAD_BYTES
            )
            or (state == "abandoned" and reserved_bytes != 0)
            or not isinstance(created_at, (int, float))
            or isinstance(created_at, bool)
            or not math.isfinite(float(created_at))
            or response is not None
        ):
            raise RuntimeError("durable Turn reservation is corrupt")
        if state in ("reserved", "abandoned"):
            if provider_at is not None:
                raise RuntimeError("durable Turn reservation is corrupt")
        elif (
            not isinstance(provider_at, (int, float))
            or isinstance(provider_at, bool)
            or not math.isfinite(float(provider_at))
        ):
            raise RuntimeError("durable Turn reservation is corrupt")
        return state, request

    def reserve_turn_receipt(
        self,
        *,
        turn_key: str,
        request_sha256: str,
        now: float | None = None,
    ) -> str:
        """Persist one worst-case receipt slot before any provider invocation."""

        turn_key = self._validated_turn_digest(turn_key, "turn_key")
        request_sha256 = self._validated_turn_digest(request_sha256, "request_sha256")
        current = self._validated_turn_time(now, "turn reservation timestamp")
        if self._conn is None:
            raise ConversationReceiptUnavailable(
                "durable Turn reservation requires a persistent conversation store"
            )
        with self._lock:
            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(connection)
                rows = connection.execute(
                    "SELECT 'committed',request_sha256,NULL,NULL,NULL,response_json "
                    "FROM agent_turn_receipt WHERE turn_key=? UNION ALL "
                    "SELECT state,request_sha256,reserved_payload_bytes,created_at,"
                    "provider_started_at,NULL FROM agent_turn_reservation WHERE turn_key=?",
                    (turn_key, turn_key),
                ).fetchall()
                if len(rows) > 1:
                    raise ConversationReceiptUnavailable(
                        "durable Turn authority overlaps committed and reserved state"
                    )
                revive_abandoned = False
                if rows:
                    row = tuple(rows[0])
                    if row[0] == "committed":
                        stored_request = self._validated_turn_digest(
                            row[1], "stored request_sha256"
                        )
                        self._decode_turn_response(row[5])
                        state = "committed"
                    else:
                        state, stored_request = self._validated_reservation_row(row)
                    if stored_request != request_sha256:
                        raise ValueError("turn idempotency semantic conflict")
                    if state != "abandoned":
                        connection.commit()
                        return state
                    revive_abandoned = True

                connection.execute(
                    "DELETE FROM agent_turn_receipt WHERE created_at < ?",
                    (current - 30 * 24 * 60 * 60,),
                )
                (
                    _conv_rows,
                    _conv_bytes,
                    receipt_rows,
                    receipt_bytes,
                    reservation_rows,
                    reservation_bytes,
                ) = self._capacity_usage(connection)
                if (
                    receipt_rows + reservation_rows + 1 > self._max_turn_receipts
                    or receipt_bytes
                    + reservation_bytes
                    + _TURN_RESERVATION_PAYLOAD_BYTES
                    > self._max_turn_receipt_bytes
                ):
                    raise ConversationReceiptUnavailable(
                        "protected durable Turn receipt capacity is fully reserved"
                    )
                if revive_abandoned:
                    updated = connection.execute(
                        "UPDATE agent_turn_reservation SET state='reserved',"
                        "reserved_payload_bytes=?,created_at=?,provider_started_at=NULL "
                        "WHERE turn_key=? AND request_sha256=? AND state='abandoned'",
                        (
                            _TURN_RESERVATION_PAYLOAD_BYTES,
                            current,
                            turn_key,
                            request_sha256,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise ConversationReceiptUnavailable(
                            "abandoned durable Turn changed before reservation"
                        )
                else:
                    connection.execute(
                        "INSERT INTO agent_turn_reservation("
                        "turn_key,request_sha256,state,reserved_payload_bytes,created_at,"
                        "provider_started_at) VALUES(?,?,'reserved',?,?,NULL)",
                        (
                            turn_key,
                            request_sha256,
                            _TURN_RESERVATION_PAYLOAD_BYTES,
                            current,
                        ),
                    )
                connection.commit()
                return "reserved"
            except ConversationReceiptUnavailable:
                connection.rollback()
                raise
            except ValueError:
                connection.rollback()
                raise
            except (OSError, sqlite3.Error, TypeError, RuntimeError) as exc:
                connection.rollback()
                raise ConversationReceiptUnavailable(
                    "cannot reserve durable Turn receipt capacity"
                ) from exc

    def claim_idempotent_effect(
        self,
        *,
        turn_key: str,
        request_sha256: str,
        now: float | None = None,
    ) -> tuple[str, dict[str, Any] | None]:
        """Claim one durable non-repeatable effect.

        The existing Turn reservation is the fail-closed execution marker:
        exactly one caller can create/transition it to ``provider_started``.
        A crash before the terminal receipt leaves the marker in progress so a
        retry cannot silently repeat an externally visible side effect.
        """

        turn_key = self._validated_turn_digest(turn_key, "turn_key")
        request_sha256 = self._validated_turn_digest(request_sha256, "request_sha256")
        current = self._validated_turn_time(now, "effect claim timestamp")
        if self._conn is None:
            raise ConversationReceiptUnavailable(
                "idempotent effects require a persistent conversation store"
            )
        with self._lock:
            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(connection)
                rows = connection.execute(
                    "SELECT 'committed',request_sha256,NULL,NULL,NULL,response_json "
                    "FROM agent_turn_receipt WHERE turn_key=? UNION ALL "
                    "SELECT state,request_sha256,reserved_payload_bytes,created_at,"
                    "provider_started_at,NULL FROM agent_turn_reservation WHERE turn_key=?",
                    (turn_key, turn_key),
                ).fetchall()
                if len(rows) > 1:
                    raise ConversationReceiptUnavailable(
                        "durable effect authority overlaps committed and executing state"
                    )
                if rows:
                    row = tuple(rows[0])
                    if row[0] == "committed":
                        stored_request = self._validated_turn_digest(
                            row[1], "stored request_sha256"
                        )
                        cached = self._decode_turn_response(row[5])
                        if stored_request != request_sha256:
                            raise ValueError("effect idempotency semantic conflict")
                        connection.commit()
                        return "committed", cached
                    state, stored_request = self._validated_reservation_row(row)
                    if stored_request != request_sha256:
                        raise ValueError("effect idempotency semantic conflict")
                    if state == "provider_started":
                        connection.commit()
                        return "in_progress", None
                    if state == "abandoned":
                        raise ConversationReceiptUnavailable(
                            "abandoned durable effect cannot be executed"
                        )
                    updated = connection.execute(
                        "UPDATE agent_turn_reservation SET state='provider_started',"
                        "provider_started_at=? WHERE turn_key=? AND request_sha256=? "
                        "AND state='reserved'",
                        (current, turn_key, request_sha256),
                    )
                    if updated.rowcount != 1:
                        raise ConversationReceiptUnavailable(
                            "durable effect changed before execution claim"
                        )
                else:
                    connection.execute(
                        "DELETE FROM agent_turn_receipt WHERE created_at < ?",
                        (current - 30 * 24 * 60 * 60,),
                    )
                    (
                        _conv_rows,
                        _conv_bytes,
                        receipt_rows,
                        receipt_bytes,
                        reservation_rows,
                        reservation_bytes,
                    ) = self._capacity_usage(connection)
                    if (
                        receipt_rows + reservation_rows + 1 > self._max_turn_receipts
                        or receipt_bytes
                        + reservation_bytes
                        + _TURN_RESERVATION_PAYLOAD_BYTES
                        > self._max_turn_receipt_bytes
                    ):
                        raise ConversationReceiptUnavailable(
                            "protected durable effect receipt capacity is fully reserved"
                        )
                    connection.execute(
                        "INSERT INTO agent_turn_reservation("
                        "turn_key,request_sha256,state,reserved_payload_bytes,created_at,"
                        "provider_started_at) VALUES(?,?,'provider_started',?,?,?)",
                        (
                            turn_key,
                            request_sha256,
                            _TURN_RESERVATION_PAYLOAD_BYTES,
                            current,
                            current,
                        ),
                    )
                connection.commit()
                return "claimed", None
            except ConversationReceiptUnavailable:
                connection.rollback()
                raise
            except ValueError:
                connection.rollback()
                raise
            except (OSError, sqlite3.Error, TypeError, RuntimeError) as exc:
                connection.rollback()
                raise ConversationReceiptUnavailable(
                    "cannot claim durable idempotent effect"
                ) from exc

    def enter_turn_provider_phase(
        self,
        *,
        turn_key: str,
        request_sha256: str,
        now: float | None = None,
    ) -> str:
        """Durably fence a reservation before the first provider invocation."""

        turn_key = self._validated_turn_digest(turn_key, "turn_key")
        request_sha256 = self._validated_turn_digest(request_sha256, "request_sha256")
        current = self._validated_turn_time(now, "provider phase timestamp")
        if self._conn is None:
            raise ConversationReceiptUnavailable(
                "provider phase requires a durable Turn reservation"
            )
        with self._lock:
            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(connection)
                rows = connection.execute(
                    "SELECT 'committed',request_sha256,NULL,NULL,NULL,response_json "
                    "FROM agent_turn_receipt WHERE turn_key=? UNION ALL "
                    "SELECT state,request_sha256,reserved_payload_bytes,created_at,"
                    "provider_started_at,NULL FROM agent_turn_reservation WHERE turn_key=?",
                    (turn_key, turn_key),
                ).fetchall()
                if len(rows) > 1:
                    raise ConversationReceiptUnavailable(
                        "durable Turn authority overlaps committed and reserved state"
                    )
                if not rows:
                    raise ConversationReceiptUnavailable(
                        "durable Turn reservation is missing"
                    )
                row = tuple(rows[0])
                if row[0] == "committed":
                    stored_request = self._validated_turn_digest(
                        row[1], "stored request_sha256"
                    )
                    self._decode_turn_response(row[5])
                    state = "committed"
                else:
                    state, stored_request = self._validated_reservation_row(row)
                if stored_request != request_sha256:
                    raise ValueError("turn idempotency semantic conflict")
                if state == "abandoned":
                    raise ConversationReceiptUnavailable(
                        "abandoned durable Turn must be reserved again"
                    )
                if state == "reserved":
                    updated = connection.execute(
                        "UPDATE agent_turn_reservation SET state='provider_started',"
                        "provider_started_at=? WHERE turn_key=? AND request_sha256=? "
                        "AND state='reserved'",
                        (current, turn_key, request_sha256),
                    )
                    if updated.rowcount != 1:
                        raise ConversationReceiptUnavailable(
                            "durable Turn reservation changed before provider phase"
                        )
                    state = "provider_started"
                connection.commit()
                return state
            except ConversationReceiptUnavailable:
                connection.rollback()
                raise
            except ValueError:
                connection.rollback()
                raise
            except (OSError, sqlite3.Error, TypeError, RuntimeError) as exc:
                connection.rollback()
                raise ConversationReceiptUnavailable(
                    "cannot enter durable Turn provider phase"
                ) from exc

    def abandon_turn_before_provider(
        self,
        *,
        turn_key: str,
        request_sha256: str,
    ) -> bool:
        """Release only an exact reservation that has not entered provider phase."""

        turn_key = self._validated_turn_digest(turn_key, "turn_key")
        request_sha256 = self._validated_turn_digest(request_sha256, "request_sha256")
        if self._conn is None:
            raise ConversationReceiptUnavailable(
                "abandoning a Turn requires a durable reservation"
            )
        with self._lock:
            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(connection)
                rows = connection.execute(
                    "SELECT 'committed',request_sha256,NULL,NULL,NULL,response_json "
                    "FROM agent_turn_receipt WHERE turn_key=? UNION ALL "
                    "SELECT state,request_sha256,reserved_payload_bytes,created_at,"
                    "provider_started_at,NULL FROM agent_turn_reservation WHERE turn_key=?",
                    (turn_key, turn_key),
                ).fetchall()
                if len(rows) > 1:
                    raise ConversationReceiptUnavailable(
                        "durable Turn authority overlaps committed and reserved state"
                    )
                if not rows:
                    connection.commit()
                    return False
                row = tuple(rows[0])
                if row[0] == "committed":
                    stored_request = self._validated_turn_digest(
                        row[1], "stored request_sha256"
                    )
                    self._decode_turn_response(row[5])
                    state = "committed"
                else:
                    state, stored_request = self._validated_reservation_row(row)
                if stored_request != request_sha256:
                    raise ValueError("turn idempotency semantic conflict")
                if state != "reserved":
                    connection.commit()
                    return False
                abandoned = connection.execute(
                    "UPDATE agent_turn_reservation SET state='abandoned',"
                    "reserved_payload_bytes=0,provider_started_at=NULL "
                    "WHERE turn_key=? AND request_sha256=? AND state='reserved'",
                    (turn_key, request_sha256),
                )
                if abandoned.rowcount != 1:
                    raise ConversationReceiptUnavailable(
                        "durable Turn reservation changed before release"
                    )
                connection.commit()
                return True
            except ConversationReceiptUnavailable:
                connection.rollback()
                raise
            except ValueError:
                connection.rollback()
                raise
            except (OSError, sqlite3.Error, TypeError, RuntimeError) as exc:
                connection.rollback()
                raise ConversationReceiptUnavailable(
                    "cannot abandon durable Turn reservation"
                ) from exc

    @staticmethod
    def _turn_response_json(result: dict[str, Any]) -> str:
        if not isinstance(result, dict):
            raise ValueError("turn result must be an object")
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(encoded.encode("utf-8")) > 1024 * 1024:
            raise ValueError("turn result exceeds receipt limit")
        return encoded

    @staticmethod
    def _decode_turn_response(value: Any) -> dict[str, Any]:
        if not isinstance(value, str):
            raise RuntimeError("durable Turn receipt response is not text")
        if len(value.encode("utf-8")) > 1024 * 1024:
            raise RuntimeError("durable Turn receipt response exceeds limit")
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise RuntimeError("durable Turn receipt response is corrupt")
        return decoded

    def turn_receipt_snapshot(self, turn_key: str) -> dict[str, Any]:
        """Return replay availability without exposing request/response data."""

        normalized = self._validated_turn_digest(turn_key, "turn_key")
        try:
            if self._conn is None:
                with self._lock:
                    row = self._turn_results.get(normalized)
                if row is None:
                    return {"found": False}
                request_sha256, response = row
                created_at = None
            else:
                with self._lock:
                    self._revalidate_if_external_change(self._conn)
                    row = self._conn.execute(
                        "SELECT request_sha256,response_json,created_at "
                        "FROM agent_turn_receipt WHERE turn_key=?",
                        (normalized,),
                    ).fetchone()
                if row is None:
                    return {"found": False}
                request_sha256, response_json, created_at = row
                response = self._decode_turn_response(response_json)

            request_hash_present = bool(
                isinstance(request_sha256, str)
                and re.fullmatch(r"[0-9a-f]{64}", request_sha256)
            )
            if not request_hash_present or not isinstance(response, dict):
                raise RuntimeError("durable Turn receipt is corrupt")
            normalized_created_at = (
                None if created_at is None else float(created_at)
            )
            if normalized_created_at is not None and not math.isfinite(
                normalized_created_at
            ):
                raise RuntimeError("durable Turn receipt timestamp is corrupt")
            return {
                "found": True,
                "request_hash_present": True,
                "response_present": True,
                "replay_available": True,
                "created_at": normalized_created_at,
            }
        except ConversationReceiptUnavailable:
            raise
        except (
            OSError,
            sqlite3.Error,
            TypeError,
            ValueError,
            RuntimeError,
        ) as exc:
            raise ConversationReceiptUnavailable(
                "cannot read durable Turn receipt status"
            ) from exc

    def idempotent_result(
        self, turn_key: str, request_sha256: str
    ) -> dict[str, Any] | None:
        """Return an atomically committed Turn result after crash/restart."""

        turn_key = self._validated_turn_digest(turn_key, "turn_key")
        request_sha256 = self._validated_turn_digest(request_sha256, "request_sha256")
        try:
            if self._conn is None:
                with self._lock:
                    stored = self._turn_results.get(turn_key)
                row = (
                    None
                    if stored is None
                    else ("committed", stored[0], None, None, None, stored[1])
                )
            else:
                with self._lock:
                    self._revalidate_if_external_change(self._conn)
                    rows = self._conn.execute(
                        "SELECT 'committed',request_sha256,NULL,created_at,NULL,"
                        "response_json FROM agent_turn_receipt WHERE turn_key=? UNION ALL "
                        "SELECT state,request_sha256,reserved_payload_bytes,created_at,"
                        "provider_started_at,NULL FROM agent_turn_reservation WHERE turn_key=?",
                        (turn_key, turn_key),
                    ).fetchall()
                    if len(rows) > 1:
                        raise RuntimeError(
                            "durable Turn authority overlaps committed and reserved state"
                        )
                    row = None if not rows else tuple(rows[0])
        except (OSError, sqlite3.Error, TypeError, RuntimeError) as exc:
            raise ConversationReceiptUnavailable(
                "cannot read durable Turn receipt"
            ) from exc
        if row is None:
            return None
        if row[0] != "committed":
            try:
                _state, stored_request = self._validated_reservation_row(tuple(row))
            except (TypeError, ValueError, RuntimeError) as exc:
                raise ConversationReceiptUnavailable(
                    "cannot read durable Turn receipt"
                ) from exc
            if stored_request != request_sha256:
                raise ValueError("turn idempotency semantic conflict")
            return None
        try:
            stored_request = self._validated_turn_digest(
                row[1], "stored request_sha256"
            )
        except ValueError as exc:
            raise ConversationReceiptUnavailable(
                "cannot read durable Turn receipt"
            ) from exc
        if stored_request != request_sha256:
            raise ValueError("turn idempotency semantic conflict")
        if self._conn is None:
            if not isinstance(row[5], dict):
                raise ConversationReceiptUnavailable(
                    "cannot read durable Turn receipt"
                )
            return json.loads(json.dumps(row[5], ensure_ascii=False, allow_nan=False))
        try:
            return self._decode_turn_response(row[5])
        except (TypeError, ValueError, RuntimeError) as exc:
            raise ConversationReceiptUnavailable(
                "cannot read durable Turn receipt"
            ) from exc

    def commit_idempotent_turn(
        self,
        *,
        turn_key: str,
        request_sha256: str,
        entries: list[tuple[str, str, str]],
        result: dict[str, Any],
        last_models: dict[str, str] | None = None,
        now: float | None = None,
        require_provider_started: bool = False,
    ) -> dict[str, Any]:
        """Atomically commit conversation rows and their replayable Turn result.

        A process crash can occur before or after this SQLite transaction, never
        between the conversation pair and the unique Turn receipt.
        """

        turn_key = self._validated_turn_digest(turn_key, "turn_key")
        request_sha256 = self._validated_turn_digest(request_sha256, "request_sha256")
        if type(require_provider_started) is not bool:
            raise ValueError("require_provider_started must be a boolean")
        encoded = self._turn_response_json(result)
        current = time.time() if now is None else float(now)
        if not math.isfinite(current):
            raise ValueError("turn receipt timestamp must be finite")
        clean_entries: list[tuple[str, str, str]] = []
        for key, role, content in entries:
            clean_entries.append(
                (
                    self._validated_key(key),
                    self._validated_role(role),
                    self._validated_content(content),
                )
            )
        clean_last_models: dict[str, str] = {
            key: "" for key, role, _content in clean_entries if role == "assistant"
        }
        for key, model in (last_models or {}).items():
            clean_key = self._validated_key(key)
            clean_model = self._validated_model(model)
            # Empty is an explicit local-author sentinel.  It must survive the
            # buffered durable Turn and clear stale provider attribution only
            # after the conversation pair and receipt commit together.
            clean_last_models[clean_key] = clean_model

        with self._lock:
            if self._conn is None:
                if require_provider_started:
                    raise ConversationReceiptUnavailable(
                        "strict provider commit requires a durable provider_started reservation"
                    )
                existing = self._turn_results.get(turn_key)
                if existing is not None:
                    if existing[0] != request_sha256:
                        raise ValueError("turn idempotency semantic conflict")
                    return json.loads(
                        json.dumps(existing[1], ensure_ascii=False, allow_nan=False)
                    )
                for key, role, content in clean_entries:
                    self._slot(key).append({"role": role, "content": content})
                for key, model in clean_last_models.items():
                    if model:
                        self._remember_last_model(key, model)
                    else:
                        self._last_model.pop(key, None)
                stored = json.loads(encoded)
                self._turn_results[turn_key] = (request_sha256, stored)
                return json.loads(encoded)

            connection = self._conn
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._revalidate_if_external_change(connection)
                existing = connection.execute(
                    "SELECT request_sha256,response_json FROM agent_turn_receipt "
                    "WHERE turn_key=?",
                    (turn_key,),
                ).fetchone()
                reservation = connection.execute(
                    "SELECT state,request_sha256,reserved_payload_bytes,created_at,"
                    "provider_started_at,NULL FROM agent_turn_reservation WHERE turn_key=?",
                    (turn_key,),
                ).fetchone()
                if existing is not None:
                    if reservation is not None:
                        raise ConversationReceiptUnavailable(
                            "durable Turn authority overlaps committed and reserved state"
                        )
                    try:
                        stored_request = self._validated_turn_digest(
                            existing[0], "stored request_sha256"
                        )
                        cached = self._decode_turn_response(existing[1])
                    except (TypeError, ValueError, RuntimeError) as exc:
                        raise ConversationReceiptUnavailable(
                            "cannot read durable Turn receipt"
                        ) from exc
                    if stored_request != request_sha256:
                        raise ValueError("turn idempotency semantic conflict")
                    connection.commit()
                    return cached
                if reservation is None:
                    if require_provider_started:
                        raise ConversationReceiptUnavailable(
                            "strict provider commit requires a provider_started reservation"
                        )
                    self._prepare_turn_receipt(
                        connection,
                        turn_key=turn_key,
                        request_sha256=request_sha256,
                        encoded=encoded,
                        current=current,
                    )
                else:
                    reservation_state, reserved_request = self._validated_reservation_row(
                        tuple(reservation)
                    )
                    if reserved_request != request_sha256:
                        raise ValueError("turn idempotency semantic conflict")
                    if reservation_state == "abandoned":
                        raise ConversationReceiptUnavailable(
                            "abandoned durable Turn cannot be committed"
                        )
                    if require_provider_started and reservation_state != "provider_started":
                        raise ConversationReceiptUnavailable(
                            "strict provider commit requires a provider_started reservation"
                        )
                    incoming = self._receipt_payload_bytes(
                        turn_key, request_sha256, encoded
                    )
                    if incoming > int(reservation[2]):
                        raise ConversationReceiptUnavailable(
                            "reserved durable Turn receipt capacity is insufficient"
                        )
                reclaimed = self._prepare_conversation_entries(
                    connection, clean_entries
                )
                for key, role, content in clean_entries:
                    connection.execute(
                        "INSERT INTO conv (key,role,content,ts) VALUES (?,?,?,?)",
                        (key, role, content, current),
                    )
                for key in dict.fromkeys(key for key, _role, _content in clean_entries):
                    connection.execute(
                        "DELETE FROM conv WHERE key=? AND id NOT IN "
                        "(SELECT id FROM conv WHERE key=? ORDER BY id DESC LIMIT ?)",
                        (key, key, self._max * 2),
                    )
                if reservation is not None:
                    deleted = connection.execute(
                        "DELETE FROM agent_turn_reservation "
                        "WHERE turn_key=? AND request_sha256=?",
                        (turn_key, request_sha256),
                    )
                    if deleted.rowcount != 1:
                        raise ConversationReceiptUnavailable(
                            "durable Turn reservation disappeared before commit"
                        )
                connection.execute(
                    "INSERT INTO agent_turn_receipt"
                    "(turn_key,request_sha256,response_json,created_at) VALUES(?,?,?,?)",
                    (turn_key, request_sha256, encoded, current),
                )
                connection.commit()
            except ConversationReceiptUnavailable:
                connection.rollback()
                raise
            except (OSError, sqlite3.Error) as exc:
                connection.rollback()
                raise ConversationReceiptUnavailable(
                    "cannot atomically persist durable Turn result"
                ) from exc
            except BaseException:
                connection.rollback()
                raise
            for reclaimed_key in reclaimed:
                self._h.pop(reclaimed_key, None)
                self._last_model.pop(reclaimed_key, None)
            for key, role, content in clean_entries:
                cached = self._h.get(key)
                if cached is not None:
                    cached.append({"role": role, "content": content})
                    self._h.move_to_end(key)
            for key, model in clean_last_models.items():
                if model:
                    self._remember_last_model(key, model)
                else:
                    self._last_model.pop(key, None)
            return json.loads(encoded)


class BufferedConversationStore:
    """Delay one Turn's history writes until its result can commit atomically."""

    def __init__(self, base: ConversationStore) -> None:
        self.base = base
        self.entries: list[tuple[str, str, str]] = []
        self.last_models: dict[str, str] = {}

    def get(self, key: str) -> list[dict[str, str]]:
        key = self.base._validated_key(key)
        current = self.base.get(key)
        current.extend(
            {"role": role, "content": content}
            for entry_key, role, content in self.entries
            if entry_key == key
        )
        return current

    def append(self, key: str, role: str, content: str) -> None:
        clean_key = self.base._validated_key(key)
        clean_role = self.base._validated_role(role)
        self.entries.append(
            (
                clean_key,
                clean_role,
                self.base._validated_content(content),
            )
        )
        if clean_role == "assistant":
            self.last_models[clean_key] = ""

    def set_last_model(self, key: str, model: str) -> None:
        clean_key = self.base._validated_key(key)
        clean_model = self.base._validated_model(model)
        if clean_model:
            self.last_models[clean_key] = clean_model

    def clear_last_model(self, key: str) -> None:
        clean_key = self.base._validated_key(key)
        self.last_models[clean_key] = ""

    def commit(
        self,
        *,
        turn_key: str,
        request_sha256: str,
        result: dict[str, Any],
        require_provider_started: bool = False,
    ) -> dict[str, Any]:
        return self.base.commit_idempotent_turn(
            turn_key=turn_key,
            request_sha256=request_sha256,
            entries=self.entries,
            result=result,
            last_models=self.last_models,
            require_provider_started=require_provider_started,
        )


def _text(resp: dict[str, Any]) -> str:
    return (resp.get("choices") or [{}])[0].get("message", {}).get("content") or ""


def session_key(channel: str, chat_id: str) -> str:
    return f"{channel}:{chat_id}"


def memory_system_note(memory: Any | None, user_id: str, query: str) -> tuple[str, list[dict[str, Any]]]:
    """检索该用户长期记忆，返回 (要并入 system 的提示文本, 命中的记忆)。

    把"记得你"做成底层通用能力：任何对话路径（直连/执行/路由）都能调它注入记忆，
    不必各自重写——这是"超级助手不该是一个模式、应写进底层、每个 agent 通用"的落点。
    """
    if memory is None or not user_id:
        return "", []
    try:
        mems = memory.search(user_id, query)
    except Exception:  # noqa: BLE001
        return "", []
    return format_memories(mems), mems


async def _conversation_history(
    store: ConversationStore | BufferedConversationStore,
    key: str,
) -> list[dict[str, str]]:
    """Read lock/SQLite-backed history without freezing deadline scheduling."""

    return await asyncio.to_thread(store.get, key)


async def _conversation_turns(
    store: ConversationStore | BufferedConversationStore,
    key: str,
) -> int:
    return len(await _conversation_history(store, key)) // 2


async def run_advisory_chat(
    router: Any,
    messages: list[dict[str, Any]],
    *,
    total_timeout: float = _CHANNEL_TOTAL_TIMEOUT,
) -> dict[str, Any]:
    """复杂纯文本的无副作用多模型 seam：规划、作答、跨来源评审，全程不提供执行工具。"""
    deadline = time.monotonic() + max(1.0, float(total_timeout))
    try:
        result = await run_org(router, messages, wall_deadline=deadline)
    except asyncio.TimeoutError:
        # Channel requests need a bounded, honest terminal response.  No requested model
        # is reported as served when the shared advisory budget expires mid-flight.
        return {
            "reply": "本轮多模型协作超过响应时限，已有过程未形成合格终审，请重试。",
            "model": "nachuan-engine",
            "usage": {},
            "orchestration_mode": "org",
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
            "outcome": "partial",
            "route": {
                "mode": "org",
                "timed_out": True,
                "reviewed": False,
                "verified": False,
                "machine_verified": False,
                "outcome": "partial",
            },
        }
    route = result.get("_route") or {}
    # 不从“是否升级”推测验收状态；只信 run_org 在最后一份产出上
    # 记录的独立复审结果。旧路由缺少显式字段时也必须 fail-closed。
    reviewed = route.get("reviewed") is True
    machine_verified = route.get("machine_verified") is True
    verified = machine_verified
    # Provider response ``model`` is commonly the upstream identifier, while
    # the public Agent contract names the actual virtual route.  Only the
    # signed invocation snapshot can decide that attribution after fallback.
    served = str(
        route.get("actual_model")
        or route.get("final_model")
        or route.get("summary_model")
        or ""
    )
    return {
        "reply": _text(result),
        "model": served,
        "usage": result.get("usage") or {},
        "orchestration_mode": str(route.get("mode") or "org"),
        "reviewed": reviewed,
        "verified": verified,
        "machine_verified": machine_verified,
        "outcome": "completed" if verified else ("completed_unverified" if reviewed else "partial"),
        "route": route,
    }


_AGENT_TERMINAL_OUTCOMES = frozenset(
    {
        "completed",
        "completed_unverified",
        "partial",
        "failed",
        "blocked",
        "accepted_async",
        "rejected_capacity",
    }
)


def _agent_outcome_fields(outcome: str, *, blocked: bool) -> dict[str, Any]:
    """Return the closed, honest status projection shared by early Agent paths."""

    if outcome not in _AGENT_TERMINAL_OUTCOMES:
        raise ValueError("unknown Agent outcome")
    return {
        "outcome": outcome,
        "blocked": bool(blocked),
        "reviewed": False,
        "verified": False,
        "machine_verified": False,
    }


async def agent_chat(
    router: Any,
    store: ConversationStore,
    *,
    message: str,
    chat_id: str,
    channel: str = "api",
    user_id: str = "",
    model: str = "glm",
    model_locked: bool = False,
    system: str | None = None,
    memory: Any | None = None,
    cases: Any | None = None,
    approvals: Any | None = None,
    guard: Any | None = None,
    persona: str | None = None,
    video_async: bool = False,
    video_async_capacity_available: bool = True,
    kb: Any | None = None,
) -> dict[str, Any]:
    """带记忆的一次对话。

    流程：检索长期记忆(若有) + 取本会话历史 → 拼 [system?]+历史+本轮 →
    经失败转移调用模型 → 落历史。返回 {reply, model, session, turns, usage, memories_used}。

    `memory` 为可选的长期记忆存储（鸭子类型，需有 .search(user_id, query)）。
    """
    key = session_key(channel, chat_id)
    # 前钩子（C1）：内容拦截 + 每日额度。命中即拒，不调用模型、不烧额度。
    if guard is not None:
        ok, reason = await asyncio.to_thread(guard.check, user_id, message)
        if not ok:
            store.append(key, "user", message)
            store.append(key, "assistant", reason)
            store.clear_last_model(key)
            return {
                "reply": reason,
                "model": "(blocked)",
                "session": key,
                "user_id": user_id,
                "turns": await _conversation_turns(store, key),
                "usage": {},
                "memories_used": [],
                "agent_route": {"label": "blocked"},
                **_agent_outcome_fields("blocked", blocked=True),
            }
    # 多模态意图（#3 #15 #17）：模型判意图（与前端共享同一套）。prefilter=True：纯聊天走关键词快筛、
    # 不花模型调用也不污染调用链；只有疑似特殊意图才用模型确认。失败回退规则，绝不阻断。
    intent = await classify_intent(router, message, prefilter=True)
    if intent == "image" and router.resolve("agnes-image"):
        polished = await polish_prompt(router, message, "image")
        imgs = await gen_image(router, polished)
        reply = f"🎨 已生成：{polished}\n{imgs[0]}" if imgs else "🎨 生成失败了，换个描述再试试？"
        store.append(key, "user", message)
        store.append(key, "assistant", reply)
        store.clear_last_model(key)
        if guard is not None:
            guard.record(user_id)
        return {
            "reply": reply, "model": "agnes-image", "session": key, "user_id": user_id,
            "turns": await _conversation_turns(store, key), "usage": {}, "memories_used": [],
            "agent_route": {"label": "image"}, "images": imgs,
            **_agent_outcome_fields(
                "completed_unverified" if imgs else "partial", blocked=False
            ),
        }
    if intent == "video" and video_async and not video_async_capacity_available:
        reply = (
            "🎬 当前异步视频队列已满，本次没有创建视频任务；"
            "请稍后重新发送视频请求，普通聊天仍可继续。"
        )
        store.append(key, "user", message)
        store.append(key, "assistant", reply)
        store.clear_last_model(key)
        return {
            "reply": reply,
            "model": "(video-capacity)",
            "session": key,
            "user_id": user_id,
            "turns": await _conversation_turns(store, key),
            "usage": {},
            "memories_used": [],
            "agent_route": {"label": "video_capacity"},
            "video_rejected": "capacity",
            **_agent_outcome_fields("rejected_capacity", blocked=True),
        }
    if intent == "video" and router.resolve("agnes-video"):
        if video_async:
            # 异步生视频（飞书桥）：润色限时，慢了/失败就用原话——先把任务发起来、快速回执要紧（视频模型也吃原始描述）。
            _dur = parse_duration(message)  # "生成10秒"→10，随 payload 传上游
            try:
                polished = await asyncio.wait_for(polish_prompt(router, message, "video"), timeout=25)
            except Exception:  # noqa: BLE001
                polished = message
            task_id, early = await create_video_task(router, polished, duration=_dur)
            reply = "🎬 收到，视频在生成了，约几分钟，好了我直接发你～（这期间可以继续聊别的）"
            store.append(key, "user", message)
            store.append(key, "assistant", reply)
            store.clear_last_model(key)
            if guard is not None:
                guard.record(user_id)
            return {
                "reply": reply, "model": "agnes-video", "session": key, "user_id": user_id,
                "turns": await _conversation_turns(store, key), "usage": {}, "memories_used": [],
                "agent_route": {"label": "video"}, "video": early or "",
                "video_task": task_id, "video_prompt": polished,
                **_agent_outcome_fields("accepted_async", blocked=False),
            }
        polished = await polish_prompt(router, message, "video")
        url = await gen_video(router, polished, duration=parse_duration(message))
        reply = f"🎬 已生成：{polished}\n{url}" if url else "🎬 视频还在生成或超时了，过会儿再问我要～"
        store.append(key, "user", message)
        store.append(key, "assistant", reply)
        store.clear_last_model(key)
        if guard is not None:
            guard.record(user_id)
        return {
            "reply": reply, "model": "agnes-video", "session": key, "user_id": user_id,
            "turns": await _conversation_turns(store, key), "usage": {}, "memories_used": [],
            "agent_route": {"label": "video"}, "video": url,
            **_agent_outcome_fields(
                "completed_unverified" if url else "partial", blocked=False
            ),
        }
    if intent == "translate":
        # 翻译意图（#15 飞书/API 也能用）：抽目标语种 + 待译文本，免费模型直翻。
        cheap = "agnes-flash" if router.resolve("agnes-flash") else (pick_model(router, "cheap") or model)
        body = _strip_translate_cmd(message) or message
        try:
            out = await translate(
                router,
                text=body,
                target=_translate_target(message),
                model=cheap,
                include_author_evidence=True,
            )
            translated = str(out.get("translated") or "").strip()
            reply = translated or "（没译出来，换个说法再试）"
            served = str(out.get("model") or "")
            translated_ok = bool(translated)
            final_route_receipt: dict[str, Any] | None = None
            if translated_ok:
                response = out.get("_response")
                invocation_route = out.get("_route")
                if isinstance(response, dict):
                    try:
                        final_route_receipt = bind_agent_author_receipt(
                            route_receipt(
                                requested_model=str(out.get("_requested_model") or cheap),
                                actual_model=served,
                                route=invocation_route,
                                response=response,
                            ),
                            reply=reply,
                        )
                    except ValueError:
                        final_route_receipt = None
            if final_route_receipt is None:
                served = "nachuan-engine"
        except Exception as exc:  # noqa: BLE001 - provider detail stays out of replies/logs
            _LOG.warning("agent translate failed: %s", type(exc).__name__)
            reply, served = "翻译暂时失败，本轮没有产出译文，请稍后重试。", "nachuan-engine"
            translated_ok = False
            final_route_receipt = None
        if guard is not None:  # 计入每日配额，和 image/video/chat 一致（Codex 审 #4）
            guard.record(user_id)
        store.append(key, "user", message)
        store.append(key, "assistant", reply)
        if final_route_receipt is not None:
            store.set_last_model(key, served)
        else:
            store.clear_last_model(key)
        result = {
            "reply": reply, "model": served, "session": key, "user_id": user_id,
            "turns": await _conversation_turns(store, key), "usage": {}, "memories_used": [],
            "agent_route": {"label": "translate"},
            **_agent_outcome_fields(
                "completed_unverified" if translated_ok else "partial", blocked=False
            ),
        }
        if final_route_receipt is not None:
            result["final_route_receipt"] = final_route_receipt
        return result
    if intent == "kb" and kb is not None:
        # 知识库问答（#15 飞书/API 也能据用户文档回答）：检索分块 → 模型带引用作答。
        hits = await asyncio.to_thread(kb.search, user_id or "owner", message, k=5)
        if not hits:
            reply = "知识库里没找到相关内容。"
            kb_outcome = "completed_unverified"
            served = "nachuan-engine"
            final_route_receipt = None
        else:
            from orchestrator.knowledge import build_context as _kbctx

            cheap = "agnes-flash" if router.resolve("agnes-flash") else (pick_model(router, "cheap") or model)
            req = ChatCompletionRequest(
                model=cheap,
                messages=[
                    {
                        "role": "system",
                        "content": _kbctx(hits)
                        + "\n\n只依据以上资料回答用户问题，引用处标[编号]；资料里没有就说「知识库里没有」、别编。",
                    },
                    {"role": "user", "content": message},
                ],
            )
            try:
                with bind_provider_call_scope(role="agent.knowledge_base.answer"):
                    res, served, invocation_route = await chat_with_fallback(router, req)
                answer = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
                reply = answer or "（没回答出来）"
                kb_outcome = (
                    "completed_unverified"
                    if answer
                    else "partial"
                )
                final_route_receipt = None
                if answer:
                    try:
                        final_route_receipt = bind_agent_author_receipt(
                            route_receipt(
                                requested_model=cheap,
                                actual_model=served,
                                route=invocation_route,
                                response=res,
                            ),
                            reply=reply,
                        )
                    except ValueError:
                        final_route_receipt = None
                if final_route_receipt is None:
                    served = "nachuan-engine"
            except Exception as exc:  # noqa: BLE001 - provider detail stays out of replies/logs
                _LOG.warning("agent knowledge answer failed: %s", type(exc).__name__)
                reply = "知识库回答暂时失败，本轮没有形成答案，请稍后重试。"
                kb_outcome = "partial"
                served = "nachuan-engine"
                final_route_receipt = None
        if guard is not None:  # 计入每日配额（Codex 审 #4）
            guard.record(user_id)
        store.append(key, "user", message)
        store.append(key, "assistant", reply)
        if final_route_receipt is not None:
            store.set_last_model(key, served)
        else:
            store.clear_last_model(key)
        result = {
            "reply": reply, "model": served, "session": key, "user_id": user_id,
            "turns": await _conversation_turns(store, key), "usage": {}, "memories_used": [],
            "agent_route": {"label": "kb"},
            **_agent_outcome_fields(kb_outcome, blocked=False),
        }
        if final_route_receipt is not None:
            result["final_route_receipt"] = final_route_receipt
        return result

    sys_parts: list[str] = []
    if persona:  # C2：稳定人设前缀（同一前缀利于将来接入缓存型 provider；也是 Output-Style 入口）
        sys_parts.append(persona)
    if system:
        sys_parts.append(system)
    note, mems = await asyncio.to_thread(memory_system_note, memory, user_id, message)
    if note:
        sys_parts.append(note)

    # 案例库路由（M3）：相似老题→免费模型带“老师解法”答；难题→强模型解并存案例。
    # 连接中心/模型选择器传入的显式模型已经由 Gateway 对实时路由表验证；这种选择是
    # 本轮的用户合同，案例路由可以补上下文，但不得暗中换成便宜模型或舰队。
    chosen_model = model
    route_info: dict[str, Any] | None = None
    if cases is not None and user_id:
        d = await asyncio.to_thread(decide_route, router, user_id, message, cases)
        chosen_model = model if model_locked else (d["model"] or model)
        route_info = {"label": d["label"], "store": bool(d["store"])}
        if model_locked:
            route_info["model_locked"] = True
        if d["case"]:
            sys_parts.append(format_case(d["case"]))
            route_info["reused_case_id"] = d["case"]["id"]

    msgs: list[dict[str, str]] = []
    if sys_parts:
        msgs.append({"role": "system", "content": "\n\n".join(sys_parts)})
    msgs.extend(await _conversation_history(store, key))
    msgs.append({"role": "user", "content": message})

    # 消息渠道的复杂纯文本走纯 chat 多模型 advisory；命中过往案例则保留快速复用路径。
    # advisory 只调用 provider.chat，不进入 run_tool_agent，因而没有文件/命令/浏览器写能力。
    use_advisory = (
        not model_locked
        and classify(message).get("difficulty") == "hard"
        and (route_info or {}).get("label") != "case_reuse"
    )
    if use_advisory:
        advisory = await run_advisory_chat(router, msgs)
        reply = advisory["reply"]
        served = advisory["model"]
        response_usage = advisory["usage"]
        orchestration_mode = advisory["orchestration_mode"]
        reviewed = advisory["reviewed"]
        verified = advisory["verified"]
        machine_verified = advisory["machine_verified"]
        outcome = advisory["outcome"]
        if route_info is None:
            route_info = {"label": "orchestrated"}
        route_info["orchestration"] = advisory["route"]
        final_route_receipt: dict[str, Any] | None = None
        advisory_receipt = advisory.get("route")
        if isinstance(advisory_receipt, dict):
            try:
                final_route_receipt = bind_agent_author_receipt(
                    advisory_receipt,
                    reply=reply,
                )
            except ValueError:
                final_route_receipt = None
    else:
        req = ChatCompletionRequest(model=chosen_model, messages=msgs)  # type: ignore[arg-type]
        with bind_provider_call_scope(role="agent.single_answer"):
            res, served, invocation_route = await chat_with_fallback(
                router,
                req,
                attempt_timeout=_CHANNEL_ATTEMPT_TIMEOUT,
                total_timeout=_CHANNEL_TOTAL_TIMEOUT,
            )
        reply = _text(res)
        response_usage = res.get("usage") or {}
        orchestration_mode = "single"
        reviewed = None
        verified = None
        machine_verified = None
        # 快路径没有独立审查，必须如实标成“已返回但未验证”，不能冒充已验收完成。
        outcome = "completed_unverified"
        final_route_receipt = None
        if reply.strip():
            try:
                final_route_receipt = bind_agent_author_receipt(
                    route_receipt(
                        requested_model=chosen_model,
                        actual_model=served,
                        route=invocation_route,
                        response=res,
                    ),
                    reply=reply,
                )
            except ValueError:
                final_route_receipt = None
        else:
            reply = "模型未返回可显示内容，本轮未完成；请重试或更换模型。"
            served = "nachuan-engine"
            outcome = "partial"

    if route_info is not None:
        if route_info.get("store"):
            # P6 学习沉淀：强模型解过的难题先挂"待审技能卡"，机主审核通过才进案例库；
            # 没接审核库时也不得把模型互审冒充机器验证后直接入库。
            if approvals is not None and user_id:
                route_info["pending_card_id"] = approvals.create(
                    user_id, "skill_card", (message or "").strip()[:80],
                    {"problem": message, "solution": reply, "model": served},
                )
            elif cases is not None and machine_verified is True:
                route_info["stored_case_id"] = cases.add(user_id, message, reply, served)
            else:
                # Model review is advisory evidence, not an executable or
                # machine-verifiable proof.  Persisting review-only output as
                # teacher data would turn a consensus mistake (or injected
                # prompt) into durable training material.  Human approval is
                # handled by the approval/feedback paths; otherwise fail closed.
                route_info["store_blocked_reason"] = "machine_verification_required"
        route_info["model"] = served

    store.append(key, "user", message)
    store.append(key, "assistant", reply)
    if final_route_receipt is not None and served != "nachuan-engine":
        store.set_last_model(key, served)
    else:
        # A local/fail-closed answer must never inherit the previous provider
        # and poison its scoreboard entry when the user rates this Turn.
        store.clear_last_model(key)
    if guard is not None:  # 后钩子：计入该用户当日成功调用（机主豁免）
        guard.record(user_id)
    result = {
        "reply": reply,
        "model": served,
        "session": key,
        "user_id": user_id,
        "turns": await _conversation_turns(store, key),
        "usage": response_usage,
        "memories_used": [m["text"] for m in mems],
        "agent_route": route_info,
        "orchestration_mode": orchestration_mode,
        "reviewed": reviewed,
        "verified": verified,
        "machine_verified": machine_verified,
        "outcome": outcome,
        "blocked": False,
    }
    if final_route_receipt is not None:
        result["final_route_receipt"] = final_route_receipt
    return result


def record_feedback(
    *,
    memory: Any,
    cases: Any,
    conv: ConversationStore,
    user_id: str,
    rating: str,
    channel: str = "api",
    chat_id: str = "",
    note: str | None = None,
) -> dict[str, Any]:
    """采集反馈（Reflexion）：

    · 👎(down)[+纠正 note] → 存“教训”(kind=lesson)，下次按记忆注入、自动改进；
    · 👍(up) → 把该会话上一轮(问→答)提升为“已验证案例”，今后可被免费模型复用。
    """
    applied: list[str] = []
    if user_id and rating == "down":
        lesson = (note or "").strip() or "上一次回答未达预期，请提高准确性与表达"
        if memory is not None and memory.add(user_id, f"【教训】{lesson}", kind="lesson"):
            applied.append("lesson_added")
    elif user_id and rating == "up" and chat_id and cases is not None:
        pair = conv.last_pair(session_key(channel, chat_id))
        if pair:
            cid = cases.add(user_id, pair[0], pair[1], "user_approved")
            if cid:
                applied.append(f"case_promoted:{cid}")

    # F6 反馈记账钩子（批6③，最小侵入·全吞异常，风格照 orchestrated_agent 的 F6 钩子）：
    # 若能把这条被评价的回复定位到具体模型（conv 里存了本轮 served model），就按用户原话的
    # task_kind 给该模型记一场 win(👍)/loss(👎)——让 👍/👎 真正教会点将官该题给谁。
    # 拿不到模型名（没 chat_id / 重启后无 last_model / 该轮走的图/视频等非文本路径）→ 跳过，
    # **绝不瞎猜模型**。记分牌坏了绝不能影响反馈主流程。
    try:
        if chat_id and rating in ("up", "down"):
            key = session_key(channel, chat_id)
            model = conv.last_model(key)
            if model:
                from orchestrator import scoreboard
                from orchestrator.classify import classify

                pair = conv.last_pair(key)
                user_msg = pair[0] if pair else ""
                kind = classify(user_msg).get("kind") or "general"
                scoreboard.record(model, kind, rating == "up")
                applied.append("scoreboard_recorded")
    except Exception:  # noqa: BLE001 反馈记账坏了绝不能挡反馈主流程
        pass

    return {"applied": applied}


def record_feedback_once(
    *,
    memory: Any,
    cases: Any,
    conv: ConversationStore,
    user_id: str,
    rating: str,
    idempotency_key: str,
    channel: str = "api",
    chat_id: str = "",
    note: str | None = None,
    wait_seconds: float = 5.0,
) -> dict[str, Any]:
    """Apply feedback once and durably replay its exact terminal result.

    The reservation is committed before side effects begin.  If execution dies
    before the terminal receipt is committed, later calls fail closed in the
    in-progress state instead of guessing and duplicating a lesson/case/score.
    """

    if not isinstance(idempotency_key, str) or not (
        1 <= len(idempotency_key.encode("utf-8")) <= 512
    ):
        raise ValueError("feedback idempotency_key must be 1..512 UTF-8 bytes")
    if not all(isinstance(value, str) for value in (user_id, rating, channel, chat_id)):
        raise ValueError("feedback identity fields must be strings")
    if note is not None and not isinstance(note, str):
        raise ValueError("feedback note must be text or null")
    if isinstance(wait_seconds, bool) or not math.isfinite(float(wait_seconds)):
        raise ValueError("feedback wait_seconds must be finite")
    bounded_wait = max(0.0, min(float(wait_seconds), 30.0))
    semantic = json.dumps(
        {
            "channel": channel,
            "chat_id": chat_id,
            "note": note,
            "rating": rating,
            "user_id": user_id,
            "version": 1,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    principal_namespace = json.dumps(
        {
            "channel": channel,
            "chat_id": chat_id,
            "idempotency_key": idempotency_key,
            "user_id": user_id,
            "version": 2,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    namespace = b"nachuan.feedback.turn.v2\0" + principal_namespace
    turn_key = hashlib.sha256(namespace).hexdigest()
    request_sha256 = hashlib.sha256(semantic).hexdigest()
    state, cached = conv.claim_idempotent_effect(
        turn_key=turn_key,
        request_sha256=request_sha256,
    )
    if state == "committed":
        if cached is None:
            raise ConversationReceiptUnavailable(
                "durable feedback receipt is missing its result"
            )
        return cached
    if state == "in_progress":
        deadline = time.monotonic() + bounded_wait
        while True:
            replay = conv.idempotent_result(turn_key, request_sha256)
            if replay is not None:
                return replay
            if time.monotonic() >= deadline:
                raise ConversationReceiptUnavailable(
                    "durable feedback outcome is still in progress"
                )
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))
    if state != "claimed":
        raise ConversationReceiptUnavailable("invalid durable feedback claim state")

    result = record_feedback(
        memory=memory,
        cases=cases,
        conv=conv,
        user_id=user_id,
        rating=rating,
        channel=channel,
        chat_id=chat_id,
        note=note,
    )
    return conv.commit_idempotent_turn(
        turn_key=turn_key,
        request_sha256=request_sha256,
        entries=[],
        result=result,
        require_provider_started=True,
    )
