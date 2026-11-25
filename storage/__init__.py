"""纳川统一存储层（P1-2：SQLite 多库收敛至 3 个核心物理库）。"""

from __future__ import annotations

from storage.unified_db import (
    AUDIT_DB,
    CHANNELS_DB,
    CORE_DB,
    LOGICAL_DB_MAP,
    UNIFIED_DB_FILENAMES,
    ensure_unified_wal,
    get_db_mode,
    is_unified_db_path,
    migrate_legacy_dbs_if_needed,
    resolve_db_path,
)

__all__ = [
    "AUDIT_DB",
    "CHANNELS_DB",
    "CORE_DB",
    "LOGICAL_DB_MAP",
    "UNIFIED_DB_FILENAMES",
    "ensure_unified_wal",
    "get_db_mode",
    "is_unified_db_path",
    "migrate_legacy_dbs_if_needed",
    "resolve_db_path",
]
