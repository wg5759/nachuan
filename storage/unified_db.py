"""SQLite 3 核心物理库路由与旧单库幂等自动迁移器（P1-2）。

物理库收敛规划（32 库 -> 3 核心物理库）：
- ``nachuan_core.db``：对话、摘要、长期记忆、案例库、知识库、审批、任务台账、撤销凭证、
  记分牌、工作流事件日志、语义缓存、隔离表、轻量媒体幂等键。
- ``nachuan_channels.db``：微信/飞书桥接、通道防重放、通道媒体请求与发件箱。
- ``nachuan_audit.db``：用量看板、供应商计费调用台账、限流准入计数、隐私权利台账、
  隐私擦除墓碑、用户会话操作台账。

兼容原则：
1. 若调用方传入显式自定义路径（例如测试中的 ``tmp_path / "xxx.db"`` 或 ``":memory:"``），
   ``resolve_db_path`` 原样返回，绝不劫持，保证既有数百个单元测试零破坏。
2. 默认 ``db_mode="unified"``；设置 ``NACHUAN_DB_MODE=legacy`` 可一键回退旧单库布局。
3. 迁移器采用 ``ATTACH DATABASE`` + ``INSERT OR IGNORE``，先建表、再迁数据、最后补索引与
   触发器（确保容量计数表与触发器零双倍累加），成功后将旧库连同侧车文件安全移至
   ``data_dir/legacy_db_backup/``，绝不丢失一字节历史数据。
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any

_LOG = logging.getLogger("nachuan.storage.unified_db")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CORE_DB = "nachuan_core.db"
CHANNELS_DB = "nachuan_channels.db"
AUDIT_DB = "nachuan_audit.db"

UNIFIED_DB_FILENAMES: frozenset[str] = frozenset({CORE_DB, CHANNELS_DB, AUDIT_DB})

# 逻辑库名 -> (统一物理库文件名, 旧单库文件名)
LOGICAL_DB_MAP: dict[str, tuple[str, str]] = {
    # 1) 核心业务库 nachuan_core.db
    "conversations": (CORE_DB, "conversations.db"),
    "conv_summary": (CORE_DB, "conv_summary.db"),
    "memory": (CORE_DB, "memory.db"),
    "cases": (CORE_DB, "cases.db"),
    "knowledge": (CORE_DB, "knowledge.db"),
    "approvals": (CORE_DB, "approvals.db"),
    "ledger": (CORE_DB, "ledger.db"),
    "undo_receipts": (CORE_DB, "undo_receipts.db"),
    "scoreboard": (CORE_DB, "scoreboard.db"),
    "workflow-events": (CORE_DB, "workflow-events.db"),
    "cache": (CORE_DB, "cache.db"),
    "quarantine": (CORE_DB, "quarantine.db"),
    "light_media_idempotency": (CORE_DB, "light_media_idempotency.db"),
    # 2) 渠道桥接库 nachuan_channels.db
    "weixin_outbox": (CHANNELS_DB, "weixin_outbox.db"),
    "weixin_agent_idempotency": (CHANNELS_DB, "weixin_agent_idempotency.db"),
    "feishu_bridge": (CHANNELS_DB, "feishu_bridge.db"),
    "feishu_pending_videos": (CHANNELS_DB, "feishu_pending_videos.db"),
    "bridge_protocol_replay": (CHANNELS_DB, "bridge_protocol_replay.db"),
    "channel_media_requests": (CHANNELS_DB, "channel_media_requests.db"),
    # 3) 审计合规库 nachuan_audit.db
    "usage": (AUDIT_DB, "usage.db"),
    "provider-calls": (AUDIT_DB, "provider-calls.db"),
    "admission": (AUDIT_DB, "admission.db"),
    "privacy_rights": (AUDIT_DB, "privacy_rights.db"),
    "privacy_tombstones": (AUDIT_DB, "privacy_tombstones.db"),
    "user-session-operations": (AUDIT_DB, "user-session-operations.db"),
}

# 旧文件名反查逻辑名（允许调用方直接传 "memory.db" 或 "memory"）
_LEGACY_FILENAME_TO_LOGICAL: dict[str, str] = {
    legacy.lower(): logical for logical, (_unified, legacy) in LOGICAL_DB_MAP.items()
}

_FTS5_SHADOW_SUFFIXES = (
    "_data",
    "_idx",
    "_content",
    "_docsize",
    "_config",
    "_segments",
    "_segdir",
    "_stat",
)


def _normalize_logical_name(logical_name: str) -> str:
    key = str(logical_name or "").strip()
    if key in LOGICAL_DB_MAP:
        return key
    lower = key.lower()
    if lower in _LEGACY_FILENAME_TO_LOGICAL:
        return _LEGACY_FILENAME_TO_LOGICAL[lower]
    if lower.endswith(".db") and lower[:-3] in LOGICAL_DB_MAP:
        return lower[:-3]
    raise KeyError(f"unknown logical database name: {logical_name!r}")


def get_db_mode(db_mode: str | None = None) -> str:
    """解析当前数据库布局模式：'unified'（默认）或 'legacy'。"""

    raw = db_mode if db_mode is not None else os.getenv("NACHUAN_DB_MODE", "unified")
    normalized = str(raw or "unified").strip().lower()
    if normalized in {"unified", "legacy"}:
        return normalized
    return "unified"


def is_unified_db_path(path: Path | str | None) -> bool:
    """判断路径是否指向 3 个统一物理库之一（用于多模块共存 Schema 子集校验）。"""

    if path is None:
        return False
    raw = str(path).strip()
    if not raw or raw == ":memory:":
        return False
    return Path(raw).name.lower() in UNIFIED_DB_FILENAMES


def _default_data_dir() -> Path:
    env_data = str(os.getenv("DATA_DIR") or "").strip()
    if env_data:
        return Path(env_data).expanduser().resolve(strict=False)
    env_usage = str(os.getenv("USAGE_DB_PATH") or "").strip()
    if env_usage:
        candidate = Path(env_usage).expanduser()
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate.resolve(strict=False).parent
    return (PROJECT_ROOT / "data").resolve(strict=False)


def resolve_db_path(
    logical_name: str,
    data_dir: Path | str | None = None,
    explicit_path: Path | str | None = None,
    db_mode: str | None = None,
) -> Path:
    """将逻辑库名解析为物理 SQLite 路径。

    - 若传入 ``explicit_path``（含 ``":memory:"`` 或任意测试临时路径），原样返回不劫持。
    - ``db_mode == "unified"``（默认）：映射到 3 个统一核心库之一。
    - ``db_mode == "legacy"``：映射到旧单库文件名。
    """

    if explicit_path is not None:
        raw_explicit = str(explicit_path).strip()
        if raw_explicit:
            return Path(raw_explicit)

    canonical = _normalize_logical_name(logical_name)
    unified_name, legacy_name = LOGICAL_DB_MAP[canonical]
    base_dir = Path(data_dir) if data_dir is not None else _default_data_dir()
    mode = get_db_mode(db_mode)
    target_name = unified_name if mode == "unified" else legacy_name
    return base_dir / target_name


def ensure_unified_wal(connection: sqlite3.Connection, *, busy_timeout_ms: int = 5000) -> None:
    """为统一库连接应用并发安全参数（WAL + busy_timeout）。"""

    connection.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    try:
        connection.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass


def _make_ddl_if_not_exists(sql: str, obj_type: str) -> str:
    text = sql.strip()
    if obj_type == "table":
        if re.match(r"^CREATE\s+VIRTUAL\s+TABLE\s+", text, re.IGNORECASE):
            return re.sub(
                r"^CREATE\s+VIRTUAL\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?",
                "CREATE VIRTUAL TABLE IF NOT EXISTS ",
                text,
                count=1,
                flags=re.IGNORECASE,
            )
        return re.sub(
            r"^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?",
            "CREATE TABLE IF NOT EXISTS ",
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    if obj_type == "index":
        return re.sub(
            r"^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?",
            lambda m: f"CREATE {m.group(1) or ''}INDEX IF NOT EXISTS ",
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    if obj_type == "trigger":
        return re.sub(
            r"^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?",
            "CREATE TRIGGER IF NOT EXISTS ",
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    if obj_type == "view":
        return re.sub(
            r"^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?",
            "CREATE VIEW IF NOT EXISTS ",
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    return text


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _table_columns(conn: sqlite3.Connection, schema: str, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA {schema}.table_info({_quote_ident(table)})").fetchall()
    return [str(r[1]) for r in rows]


def _move_to_backup(legacy_path: Path, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    dest = backup_dir / legacy_path.name
    if dest.exists():
        stamp = time.strftime("%Y%m%d_%H%M%S")
        dest = backup_dir / f"{legacy_path.stem}.{stamp}{legacy_path.suffix}"
    shutil.move(str(legacy_path), str(dest))
    # 同步搬移 WAL/SHM/Journal 侧车文件（若存在），避免残留孤儿侧车文件
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{legacy_path}{suffix}")
        if sidecar.exists():
            sidecar_dest = Path(f"{dest}{suffix}")
            try:
                shutil.move(str(sidecar), str(sidecar_dest))
            except OSError:
                pass
    return dest


def _migrate_single_legacy_db(
    legacy_path: Path,
    target_path: Path,
    backup_dir: Path,
) -> dict[str, Any]:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # 0 字节占位文件直接安全移入备份目录
    if legacy_path.stat().st_size == 0:
        backup_path = _move_to_backup(legacy_path, backup_dir)
        return {
            "source": legacy_path.name,
            "target": target_path.name,
            "tables": [],
            "rows_copied": 0,
            "backup": str(backup_path),
            "empty_file": True,
        }

    conn = sqlite3.connect(str(target_path), timeout=10.0, isolation_level=None)
    attached = False
    tables_migrated: list[str] = []
    total_rows_copied = 0
    try:
        ensure_unified_wal(conn, busy_timeout_ms=10_000)
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("ATTACH DATABASE ? AS legacy_src", (str(legacy_path),))
        attached = True

        src_objects = conn.execute(
            "SELECT type, name, tbl_name, sql FROM legacy_src.sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
            "ORDER BY CASE type "
            "WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 WHEN 'trigger' THEN 3 ELSE 4 END, name"
        ).fetchall()

        existing_main_objects = {
            (str(r[0]), str(r[1]))
            for r in conn.execute(
                "SELECT type, name FROM main.sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }

        virtual_table_names: set[str] = set()
        regular_tables: list[tuple[str, str]] = []
        virtual_tables: list[tuple[str, str]] = []
        indexes: list[tuple[str, str]] = []
        views: list[tuple[str, str]] = []
        triggers: list[tuple[str, str]] = []

        for obj_type, name, _tbl_name, sql in src_objects:
            o_type = str(obj_type)
            o_name = str(name)
            o_sql = str(sql)
            if o_type == "table":
                if re.match(r"^\s*CREATE\s+VIRTUAL\s+TABLE\b", o_sql, re.IGNORECASE):
                    virtual_table_names.add(o_name)
                    virtual_tables.append((o_name, o_sql))
                else:
                    regular_tables.append((o_name, o_sql))
            elif o_type == "index":
                indexes.append((o_name, o_sql))
            elif o_type == "view":
                views.append((o_name, o_sql))
            elif o_type == "trigger":
                triggers.append((o_name, o_sql))

        # 过滤掉 FTS5 等虚拟表自动生成的影子表（建虚拟表时 SQLite 会自动创建它们）
        shadow_tables: set[str] = set()
        for vt in virtual_table_names:
            for suffix in _FTS5_SHADOW_SUFFIXES:
                shadow_tables.add(f"{vt}{suffix}")

        conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. 先建缺失的普通表（不建 trigger，防止计数触发器在迁移期间重复累加）
            for tbl_name, ddl in regular_tables:
                if tbl_name in shadow_tables:
                    continue
                if ("table", tbl_name) not in existing_main_objects:
                    conn.execute(_make_ddl_if_not_exists(ddl, "table"))
                    existing_main_objects.add(("table", tbl_name))

            # 2. 按共有列 INSERT OR IGNORE 迁移数据
            for tbl_name, _ddl in regular_tables:
                if tbl_name in shadow_tables:
                    continue
                src_cols = _table_columns(conn, "legacy_src", tbl_name)
                dst_cols = _table_columns(conn, "main", tbl_name)
                dst_set = set(dst_cols)
                common = [c for c in src_cols if c in dst_set]
                if not common:
                    continue
                col_expr = ", ".join(_quote_ident(c) for c in common)
                q_tbl = _quote_ident(tbl_name)
                before_changes = conn.total_changes
                conn.execute(
                    f"INSERT OR IGNORE INTO main.{q_tbl} ({col_expr}) "
                    f"SELECT {col_expr} FROM legacy_src.{q_tbl}"
                )
                copied = conn.total_changes - before_changes
                total_rows_copied += max(0, copied)
                tables_migrated.append(tbl_name)

            # 3. 建缺失的虚拟表（如 FTS5），若目标虚拟表刚建立则拷贝可写入数据
            for vt_name, ddl in virtual_tables:
                if ("table", vt_name) not in existing_main_objects:
                    try:
                        conn.execute(_make_ddl_if_not_exists(ddl, "table"))
                        existing_main_objects.add(("table", vt_name))
                        src_cols = _table_columns(conn, "legacy_src", vt_name)
                        dst_cols = _table_columns(conn, "main", vt_name)
                        common = [c for c in src_cols if c in set(dst_cols)]
                        if common:
                            col_expr = ", ".join(_quote_ident(c) for c in common)
                            q_vt = _quote_ident(vt_name)
                            conn.execute(
                                f"INSERT OR IGNORE INTO main.{q_vt} ({col_expr}) "
                                f"SELECT {col_expr} FROM legacy_src.{q_vt}"
                            )
                    except sqlite3.Error:
                        # 如环境缺失特定虚拟表扩展则安全跳过（检索会自动降级）
                        pass

            # 4. 补建缺失索引、视图、触发器（在全部数据迁入之后）
            for idx_name, ddl in indexes:
                if ("index", idx_name) not in existing_main_objects:
                    try:
                        conn.execute(_make_ddl_if_not_exists(ddl, "index"))
                        existing_main_objects.add(("index", idx_name))
                    except sqlite3.Error:
                        pass

            for view_name, ddl in views:
                if ("view", view_name) not in existing_main_objects:
                    try:
                        conn.execute(_make_ddl_if_not_exists(ddl, "view"))
                        existing_main_objects.add(("view", view_name))
                    except sqlite3.Error:
                        pass

            for trg_name, ddl in triggers:
                if ("trigger", trg_name) not in existing_main_objects:
                    try:
                        conn.execute(_make_ddl_if_not_exists(ddl, "trigger"))
                        existing_main_objects.add(("trigger", trg_name))
                    except sqlite3.Error:
                        pass

            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        if attached:
            try:
                conn.execute("DETACH DATABASE legacy_src")
            except sqlite3.Error:
                pass
        conn.close()

    backup_path = _move_to_backup(legacy_path, backup_dir)
    return {
        "source": legacy_path.name,
        "target": target_path.name,
        "tables": tables_migrated,
        "rows_copied": total_rows_copied,
        "backup": str(backup_path),
    }


def migrate_legacy_dbs_if_needed(
    data_dir: Path | str,
    *,
    db_mode: str | None = None,
) -> dict[str, Any]:
    """当处于 ``unified`` 模式且检测到旧单库文件时，幂等迁移数据并备份旧库。

    - 逐个迁移至对应的 ``nachuan_core.db`` / ``nachuan_channels.db`` / ``nachuan_audit.db``。
    - 迁移成功后将旧单库及侧车文件移入 ``data_dir / "legacy_db_backup"``。
    - 幂等安全：已迁完或不存在旧单库时零副作用快速返回。
    """

    mode = get_db_mode(db_mode)
    base_dir = Path(data_dir)
    if mode != "unified":
        return {
            "mode": mode,
            "migrated": [],
            "skipped": True,
            "reason": "legacy_mode",
            "errors": [],
        }
    if not base_dir.exists() or not base_dir.is_dir():
        return {
            "mode": mode,
            "migrated": [],
            "skipped": True,
            "reason": "data_dir_missing",
            "errors": [],
        }

    backup_dir = base_dir / "legacy_db_backup"
    migrated: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    seen_legacy: set[str] = set()

    for _logical, (unified_name, legacy_name) in LOGICAL_DB_MAP.items():
        if legacy_name in seen_legacy:
            continue
        seen_legacy.add(legacy_name)
        legacy_path = base_dir / legacy_name
        if not legacy_path.is_file():
            continue
        target_path = base_dir / unified_name
        try:
            detail = _migrate_single_legacy_db(legacy_path, target_path, backup_dir)
            migrated.append(detail)
        except Exception as exc:  # noqa: BLE001 -- 单库失败不阻断其它库迁移与启动
            _LOG.warning(
                "legacy sqlite migration skipped for %s -> %s: %s",
                legacy_name,
                unified_name,
                type(exc).__name__,
            )
            errors.append(
                {
                    "source": legacy_name,
                    "target": unified_name,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    return {
        "mode": mode,
        "migrated": migrated,
        "skipped": not migrated and not errors,
        "errors": errors,
    }
