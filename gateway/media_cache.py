"""贵工具（生图/生视频）结果去重缓存。

同样的输入（模型+提示+参数）绝不重复生成——不白烧 Agnes 套餐额度 / 不重复付费。
本地 json 文件持久化（data/media_cache.json），跨重启有效。全程安全降级：
任何读写异常都当作"没缓存"，照常走真实生成，绝不因缓存出错而影响出图/出视频。
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
import threading
import time
from typing import Any, Optional

_LOCK = threading.Lock()
# TTL：Agnes 任务号/成片 URL 都有时效，失败/过期任务若永久缓存，同样输入将**永远**拿到坏结果、
# 再也不能重新生成（gpt5.6 审 P2-3）。过期即当 miss 并驱逐；2 小时内的正常去重照旧省额度。
_TTL_SECONDS = 2 * 3600.0
_MAX_FINGERPRINT_BYTES = 24 * 1024 * 1024
_MAX_ENTRY_BYTES = 24 * 1024 * 1024
_MAX_CACHE_BYTES = 64 * 1024 * 1024
_MAX_ENTRIES = 256


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _path() -> str:
    from gateway.config import get_settings

    return os.path.join(os.path.dirname(get_settings().usage_db_path), "media_cache.json")


def _load() -> dict[str, Any]:
    try:
        path = _path()
        if os.path.getsize(path) > _MAX_CACHE_BYTES:
            return {}
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f) or {}
        return loaded if isinstance(loaded, dict) else {}
    except Exception:  # noqa: BLE001  # 文件不存在/损坏 → 当空缓存
        return {}


def _save(d: dict[str, Any]) -> None:
    tmp = ""
    try:
        p = _path()
        raw = _encoded(d)
        if len(raw) > _MAX_CACHE_BYTES:
            return
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=".media_cache-", suffix=".tmp", dir=os.path.dirname(p) or "."
        )
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)  # 原子替换，避免半截文件
    except Exception:  # noqa: BLE001
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _prune(d: dict[str, Any]) -> dict[str, Any]:
    """Keep newest valid entries while respecting count and byte ceilings."""

    now = time.time()
    candidates: list[tuple[str, dict[str, Any]]] = []
    for key, entry in d.items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[0-9a-f]{32}", key) is None
            or not isinstance(entry, dict)
        ):
            continue
        try:
            cached_at = float(entry.get("_cached_at") or 0)
            entry_size = len(_encoded(entry))
        except (TypeError, ValueError, RecursionError):
            continue
        age = now - cached_at
        if not math.isfinite(cached_at) or not 0 <= age <= _TTL_SECONDS:
            continue
        if entry_size > _MAX_ENTRY_BYTES:
            continue
        candidates.append((key, entry))

    candidates.sort(
        key=lambda item: float(item[1].get("_cached_at") or 0), reverse=True
    )
    kept: dict[str, Any] = {}
    encoded_size = 2  # opening and closing braces
    for key, entry in candidates[:_MAX_ENTRIES]:
        try:
            item_size = len(_encoded(key)) + 1 + len(_encoded(entry))
            projected = encoded_size + item_size + (1 if kept else 0)
            if projected > _MAX_CACHE_BYTES:
                continue
        except (TypeError, ValueError, RecursionError):
            continue
        kept[key] = entry
        encoded_size = projected
    return kept


def fingerprint(kind: str, payload: dict[str, Any]) -> str:
    """按 kind(image/video) + 规整后的输入算指纹。"""
    if not isinstance(kind, str) or not kind or len(kind) > 32:
        raise ValueError("invalid media kind")
    if not isinstance(payload, dict):
        raise ValueError("media payload must be an object")
    try:
        encoded = _encoded(payload)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("media payload is not canonical JSON") from exc
    if len(encoded) > _MAX_FINGERPRINT_BYTES:
        raise ValueError("media payload exceeds fingerprint byte limit")
    return hashlib.sha256(kind.encode("utf-8") + b":" + encoded).hexdigest()[:32]


def get(fp: str) -> Optional[Any]:
    if not isinstance(fp, str) or re.fullmatch(r"[0-9a-f]{32}", fp) is None:
        return None
    with _LOCK:
        d = _load()
        e = d.get(fp)
        if e is None:
            return None
        # 新格式 {_cached_at, data}：过期驱逐；旧格式（无时间戳、判不了龄）一律当过期驱逐（一次性迁移）
        if isinstance(e, dict) and "_cached_at" in e:
            try:
                age = time.time() - float(e.get("_cached_at") or 0)
                entry_size = len(_encoded(e))
            except (TypeError, ValueError, RecursionError):
                age, entry_size = _TTL_SECONDS + 1, _MAX_ENTRY_BYTES + 1
            if (
                math.isfinite(age)
                and 0 <= age <= _TTL_SECONDS
                and entry_size <= _MAX_ENTRY_BYTES
            ):
                return e.get("data")
        d.pop(fp, None)
        _save(_prune(d))
        return None


def put(fp: str, result: Any) -> None:
    if (
        result is None
        or not isinstance(fp, str)
        or re.fullmatch(r"[0-9a-f]{32}", fp) is None
    ):
        return
    entry = {"_cached_at": time.time(), "data": result}
    try:
        if len(_encoded(entry)) > _MAX_ENTRY_BYTES:
            return
    except (TypeError, ValueError, RecursionError):
        return
    with _LOCK:
        d = _load()
        d[fp] = entry
        _save(_prune(d))
