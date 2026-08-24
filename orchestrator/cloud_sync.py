"""跨设备云同步（Supabase）：把 长期记忆 / 案例库 / 知识库 同步到 Supabase（每用户 RLS 隔离）。

与 `orchestrator/sync.py` 互补、各管各的：
  · 本模块(cloud_sync) = **Supabase 云**，覆盖 记忆+案例+知识库，按 Supabase 账户隔离。
  · sync.py = 自建服务器/网盘快照容灾，仅案例（dormant，sync_server_url 空时不启用）。

机主拍板（2026-06-27）：只同步这三类；**对话历史与 BYOK 密钥绝不上云**。
**只有同一 Supabase 账户的设备之间**才互相同步（云端 RLS 按 auth.uid 行级隔离）。
自用与商用同一套：每个用户用自己的账户登录、各自一份。

去重/幂等：云端唯一键 (user_id, content_hash)，content_hash=sha256(归一化内容)，
天然去重、无需跨设备 id 映射、无回环。冲突 last-write-wins(updated_at)。删除走 deleted 墓碑。

优雅降级：未配置 / 未登录 / 缺依赖 / 任何异常 → 静默跳过，绝不影响主流程。
配置与登录态存 `data/sync.json` 的 Windows 当前用户 DPAPI 密文信封；旧明文首次读取即原位迁移。
密文损坏或不属于当前用户时失败关闭，密钥不回显、不进 git。
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from gateway.secure_store import read_protected_json, write_protected_json
from gateway.url_safety import is_public_http_url

_REPO = Path(__file__).resolve().parent.parent
_DATA = Path(os.getenv("DATA_DIR") or (_REPO / "data"))
_CFG_PATH = _DATA / "sync.json"
_lock = threading.RLock()
_sync_lock = threading.Lock()
_CFG_PURPOSE = "cloud-sync-credentials/v1"
_ALLOWLIST_ENV = "NACHUAN_SUPABASE_HOST_ALLOWLIST"
_BLOCKED_NAMES = {
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
}
_BLOCKED_SUFFIXES = (".local", ".internal", ".lan", ".home")


def bind_data_dir(path: str | os.PathLike[str]) -> None:
    """Bind cloud state to the gateway's already-selected runtime data root.

    Import-time environment snapshots are unsafe for packaged/test launches:
    ``USAGE_DB_PATH`` may select an isolated runtime directory after this module
    was imported.  The gateway calls this once during lifespan startup, before
    any sync worker exists, so plaintext migration and every later database read
    operate on the same data root.
    """

    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("云同步数据目录必须是绝对路径")
    candidate = Path(os.path.abspath(candidate))
    if candidate.exists() and not candidate.is_dir():
        raise ValueError("云同步数据目录不是目录")
    global _DATA, _CFG_PATH
    with _lock:
        _DATA = candidate
        _CFG_PATH = candidate / "sync.json"


def _norm(s: Optional[str]) -> str:
    """归一化：连续空白折叠成单空格 + 去首尾（前后端/各设备必须一致）。"""
    return " ".join((s or "").split())


def _hash(s: str) -> str:
    return hashlib.sha256(_norm(s).encode("utf-8")).hexdigest()


# ── 配置（data/sync.json）────────────────────────────────────────────────────
_DEFAULT_CFG: dict[str, Any] = {
    "url": "",
    "anon_key": "",
    "access_token": "",
    "refresh_token": "",
    "user_id": "",  # 云端 auth uid
    "email": "",
    "local_user": "owner",  # 本地 SQLite 里机主的 user_id（与桌面/飞书机主一致）
    "device_id": "",
    "enabled": False,
    "target_epoch": 0,
    "last_sync": {},  # {table: max_updated_at_seen}
}


def _canonical_host(raw: str) -> str:
    value = (raw or "").rstrip(".").lower()
    if not value:
        raise ValueError("Supabase URL 缺少主机名")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        try:
            encoded = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Supabase 主机名非法") from exc
        if (
            len(encoded) > 253
            or not re.fullmatch(r"[a-z0-9.-]+", encoded)
            or ".." in encoded
        ):
            raise ValueError("Supabase 主机名非法")
        return encoded


def _reject_private_or_metadata_host(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
            raise ValueError("Supabase URL 不允许内网或 metadata 主机")
    else:
        if not address.is_global:
            raise ValueError("Supabase URL 不允许内网、回环或 metadata 地址")


def _parse_target_allowlist() -> set[tuple[str, int]]:
    """Parse exact custom Supabase HTTPS hosts/origins from operator policy."""
    allowed: set[tuple[str, int]] = set()
    for token in re.split(r"[,;\s]+", os.getenv(_ALLOWLIST_ENV, "").strip()):
        if not token:
            continue
        candidate = token if "://" in token else f"//{token}"
        try:
            parsed = urlsplit(candidate)
            if parsed.scheme and parsed.scheme.lower() != "https":
                continue
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
            ):
                continue
            allowed.add((_canonical_host(parsed.hostname), parsed.port or 443))
        except (UnicodeError, ValueError):
            continue
    return allowed


def _authority(host: str, port: int) -> str:
    shown = f"[{host}]" if ":" in host else host
    return shown if port == 443 else f"{shown}:{port}"


def normalize_target_url(url: str, *, verify_public: bool = True) -> str:
    """Return the canonical Supabase project root after strict target checks.

    Production defaults to ``https://<project>.supabase.co`` on port 443.
    Self-hosted/test targets require an exact
    ``NACHUAN_SUPABASE_HOST_ALLOWLIST`` entry and must still resolve entirely
    to public addresses.
    """
    raw = (url or "").strip()
    if not raw or any(ch.isspace() or ord(ch) < 0x20 for ch in raw) or "\\" in raw:
        raise ValueError("Supabase URL 为空或包含非法字符")
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("Supabase URL 必须使用 HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Supabase URL 不允许嵌入用户名或密码")
        if parsed.query or parsed.fragment:
            raise ValueError("Supabase URL 不允许 query 或 fragment")
        host = _canonical_host(parsed.hostname)
        port = parsed.port or 443
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("Supabase"):
            raise
        raise ValueError("Supabase URL 格式非法") from exc

    _reject_private_or_metadata_host(host)
    path = parsed.path.rstrip("/")
    if path not in {"", "/rest/v1", "/auth/v1"}:
        raise ValueError("Supabase URL 必须是项目根、/rest/v1 或 /auth/v1")

    official = host.endswith(".supabase.co") and host != "supabase.co" and port == 443
    explicitly_allowed = (host, port) in _parse_target_allowlist()
    if not official and not explicitly_allowed:
        raise ValueError(
            "Supabase 默认仅允许 HTTPS *.supabase.co；自托管需精确主机 allowlist"
        )

    root = urlunsplit(("https", _authority(host, port), "", "", ""))
    if explicitly_allowed and not official and verify_public:
        if not is_public_http_url(root):
            raise ValueError("allowlist Supabase 目标必须解析为全公网地址")
    return root


def _target_fingerprint(normalized_url: str, anon_key: str) -> str:
    digest = hashlib.sha256(
        b"nachuan/cloud-sync-target/v1\0"
        + normalized_url.encode("utf-8")
        + b"\0"
        + anon_key.encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def validate_target(url: str, anon_key: str) -> dict[str, str]:
    """Validate endpoint input and return values suitable for capability binding."""
    normalized_url = normalize_target_url(url)
    normalized_key = (anon_key or "").strip()
    if not normalized_key:
        raise ValueError("Supabase anon key 不能为空")
    return {
        "url": normalized_url,
        "target_fingerprint": _target_fingerprint(normalized_url, normalized_key),
    }


def target_fingerprint(url: str, anon_key: str) -> str:
    """Stable, non-secret fingerprint of canonical URL + anon key."""
    return validate_target(url, anon_key)["target_fingerprint"]


def _validated_cfg(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("云同步配置必须是 JSON 对象")
    cfg = {**_DEFAULT_CFG, "last_sync": {}}
    cfg.update(raw)
    string_fields = (
        "url",
        "anon_key",
        "access_token",
        "refresh_token",
        "user_id",
        "email",
        "local_user",
        "device_id",
    )
    if any(not isinstance(cfg.get(field), str) for field in string_fields):
        raise ValueError("云同步配置字符串字段格式非法")
    if not isinstance(cfg.get("enabled"), bool):
        raise ValueError("云同步 enabled 必须是布尔值")
    if (
        isinstance(cfg.get("target_epoch"), bool)
        or not isinstance(cfg.get("target_epoch"), int)
        or cfg["target_epoch"] < 0
    ):
        raise ValueError("云同步 target_epoch 必须是非负整数")
    if not isinstance(cfg.get("last_sync"), dict) or any(
        not isinstance(key, str)
        or isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        for key, value in cfg["last_sync"].items()
    ):
        raise ValueError("云同步 last_sync 格式非法")

    cfg["anon_key"] = cfg["anon_key"].strip()
    if cfg["url"]:
        cfg["url"] = normalize_target_url(cfg["url"], verify_public=False)
    if bool(cfg["url"]) != bool(cfg["anon_key"]):
        raise ValueError("Supabase URL 与 anon key 必须同时配置")
    if not cfg["local_user"].strip():
        raise ValueError("云同步 local_user 不能为空")
    cfg["last_sync"] = dict(cfg["last_sync"])
    return cfg


def _write_cfg_unlocked(cfg: dict[str, Any]) -> None:
    write_protected_json(_CFG_PATH, cfg, purpose=_CFG_PURPOSE)


def _revoke_legacy_plaintext_cfg(_raw: dict[str, Any]) -> dict[str, Any]:
    """Discard credentials that were ever stored with a permissive plaintext ACL.

    Re-encrypting an exposed refresh/access token does not revoke it.  Startup
    intentionally requires the owner to configure and log in again; issuer-side
    token revocation remains an operational follow-up.
    """

    return {}


def _load_cfg_unlocked() -> dict[str, Any]:
    raw: dict[str, Any] = {}
    if _CFG_PATH.exists():
        raw = read_protected_json(
            _CFG_PATH,
            purpose=_CFG_PURPOSE,
            migrate_plaintext=True,
            plaintext_migrator=_revoke_legacy_plaintext_cfg,
        )
    cfg = _validated_cfg(raw)
    if not cfg["device_id"]:
        candidate = {**cfg, "device_id": uuid.uuid4().hex[:16]}
        _write_cfg_unlocked(candidate)
        cfg = candidate
    return cfg


def load_cfg() -> dict[str, Any]:
    with _lock:
        return _load_cfg_unlocked()


def save_cfg(cfg: dict[str, Any]) -> None:
    candidate = _validated_cfg(dict(cfg))
    with _lock:
        _write_cfg_unlocked(candidate)


def configure(url: str, anon_key: str) -> None:
    """录入 Supabase 项目 URL + anon key（不回显、存本地）。

    URL 容错：填成 `.../rest/v1/` 或 `.../auth/v1/` 也行，统一规整成项目根域名
    （本模块自己拼 /rest/v1 与 /auth/v1）。
    """
    target = validate_target(url, anon_key)
    normalized_url = target["url"]
    normalized_key = (anon_key or "").strip()
    with _lock:
        current = _load_cfg_unlocked()
        old_fingerprint = (
            _target_fingerprint(current["url"], current["anon_key"])
            if current["url"] and current["anon_key"]
            else ""
        )
        changed = old_fingerprint != target["target_fingerprint"]
        candidate = {**current, "url": normalized_url, "anon_key": normalized_key}
        if changed:
            candidate.update(
                {
                    "access_token": "",
                    "refresh_token": "",
                    "user_id": "",
                    "email": "",
                    "last_sync": {},
                    "enabled": False,
                    "target_epoch": current["target_epoch"] + 1,
                }
            )
        _write_cfg_unlocked(_validated_cfg(candidate))


def available() -> bool:
    """配置齐 + 已登录 + 开关开 才可用（决定是否真同步）。"""
    cfg = load_cfg()
    return bool(
        cfg.get("enabled")
        and cfg.get("url")
        and cfg.get("anon_key")
        and cfg.get("access_token")
        and cfg.get("user_id")
    )


def status() -> dict[str, Any]:
    """给端点/UI：是否配置/登录、邮箱、上次同步时间（不回显任何密钥/token）。"""
    cfg = load_cfg()
    configured = bool(cfg.get("url") and cfg.get("anon_key"))
    return {
        "configured": configured,
        "logged_in": bool(cfg.get("access_token") and cfg.get("user_id")),
        "enabled": bool(cfg.get("enabled")),
        "email": cfg.get("email", ""),
        "url": cfg.get("url", ""),
        "device_id": cfg.get("device_id", ""),
        "scope": "personal_account",
        "cloud_user_id": cfg.get("user_id", ""),
        "local_user": cfg.get("local_user", "owner"),
        "sync_tables": list(_ORDER),
        "last_sync": cfg.get("last_sync", {}),
        "target_safe": configured,
        "target_fingerprint": (
            _target_fingerprint(cfg["url"], cfg["anon_key"]) if configured else ""
        ),
        "target_policy": "https_supabase_or_exact_public_allowlist",
        "target_epoch": cfg["target_epoch"],
    }


def set_enabled(on: bool) -> None:
    with _lock:
        cfg = _load_cfg_unlocked()
        candidate = {**cfg, "enabled": bool(on)}
        _write_cfg_unlocked(_validated_cfg(candidate))


# ── Supabase HTTP（auth + PostgREST）─────────────────────────────────────────

def _client():  # -> httpx.Client
    import httpx

    return httpx.Client(timeout=30.0)


def _cfg_fingerprint(cfg: dict[str, Any]) -> str:
    if not cfg.get("url") or not cfg.get("anon_key"):
        return ""
    return _target_fingerprint(cfg["url"], cfg["anon_key"])


def _cfg_identity(cfg: dict[str, Any]) -> tuple[str, int, str, str, bool]:
    """Identity of the target, authenticated tenant and local merge scope."""
    return (
        _cfg_fingerprint(cfg),
        int(cfg["target_epoch"]),
        str(cfg.get("user_id") or ""),
        str(cfg.get("local_user") or ""),
        bool(cfg.get("enabled")),
    )


def _commit_if_target_unchanged(
    expected_identity: tuple[str, int, str, str, bool], updates: dict[str, Any]
) -> dict[str, Any] | None:
    """Compare-and-swap auth/cursor fields without reviving a retired target."""
    with _lock:
        current = _load_cfg_unlocked()
        if _cfg_identity(current) != expected_identity:
            return None
        candidate = _validated_cfg({**current, **updates})
        _write_cfg_unlocked(candidate)
        return candidate


class _TargetChanged(RuntimeError):
    pass


def _ensure_target_unchanged(cfg: dict[str, Any]) -> None:
    expected = _cfg_identity(cfg)
    with _lock:
        current = _load_cfg_unlocked()
        if _cfg_identity(current) != expected:
            raise _TargetChanged("Supabase 目标在同步期间已变更")


def login(email: str, password: str) -> dict[str, Any]:
    """Supabase Auth 邮箱密码登录 → 存 access/refresh token + 云端 user_id。"""
    cfg = load_cfg()
    if not cfg.get("url") or not cfg.get("anon_key"):
        return {"ok": False, "error": "未配置 Supabase URL / anon key"}
    expected_identity = _cfg_identity(cfg)
    try:
        with _client() as c:
            r = c.post(
                f"{cfg['url']}/auth/v1/token?grant_type=password",
                headers={"apikey": cfg["anon_key"], "Content-Type": "application/json"},
                json={"email": email, "password": password},
            )
        if r.status_code != 200:
            return {"ok": False, "error": f"{r.status_code} {r.text[:200]}"}
        data = r.json()
        user_id = (data.get("user") or {}).get("id", "")
        committed = _commit_if_target_unchanged(
            expected_identity,
            {
                "access_token": data.get("access_token", ""),
                "refresh_token": data.get("refresh_token", ""),
                "user_id": user_id,
                "email": email,
            },
        )
        if committed is None:
            return {"ok": False, "error": "Supabase 目标已变更，本次登录结果已丢弃"}
        return {"ok": True, "user_id": user_id, "email": email}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def signup(email: str, password: str) -> dict[str, Any]:
    """Supabase 注册（商用：终端用户自助开账户）。

    项目关了邮箱确认 → 直接返回登录态并存；开了确认 → need_confirm=True，提示去邮箱点链接。
    """
    cfg = load_cfg()
    if not cfg.get("url") or not cfg.get("anon_key"):
        return {"ok": False, "error": "未配置 Supabase URL / anon key"}
    expected_identity = _cfg_identity(cfg)
    try:
        with _client() as c:
            r = c.post(
                f"{cfg['url']}/auth/v1/signup",
                headers={"apikey": cfg["anon_key"], "Content-Type": "application/json"},
                json={"email": email, "password": password},
            )
        if r.status_code not in (200, 201):
            return {"ok": False, "error": f"{r.status_code} {r.text[:200]}"}
        data = r.json()
        if data.get("access_token"):  # 项目免确认 → 顺手登录
            committed = _commit_if_target_unchanged(
                expected_identity,
                {
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token", ""),
                    "user_id": (data.get("user") or {}).get("id", ""),
                    "email": email,
                },
            )
            if committed is None:
                return {"ok": False, "error": "Supabase 目标已变更，本次注册会话已丢弃"}
            return {"ok": True, "logged_in": True, "email": email}
        return {"ok": True, "logged_in": False, "need_confirm": True, "email": email}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _refresh(cfg: dict[str, Any]) -> bool:
    if not cfg.get("refresh_token"):
        return False
    expected_identity = _cfg_identity(cfg)
    try:
        with _client() as c:
            r = c.post(
                f"{cfg['url']}/auth/v1/token?grant_type=refresh_token",
                headers={"apikey": cfg["anon_key"], "Content-Type": "application/json"},
                json={"refresh_token": cfg["refresh_token"]},
            )
        if r.status_code != 200:
            return False
        data = r.json()
        access_token = data.get("access_token", cfg["access_token"])
        refresh_token = data.get("refresh_token", cfg["refresh_token"])
        committed = _commit_if_target_unchanged(
            expected_identity,
            {"access_token": access_token, "refresh_token": refresh_token},
        )
        if committed is None:
            return False
        cfg["access_token"] = access_token
        cfg["refresh_token"] = refresh_token
        return True
    except Exception:  # noqa: BLE001
        return False


def _rest(cfg: dict[str, Any], method: str, path: str, **kw) -> Any:
    """调 PostgREST，401 自动 refresh 重试一次。返回 httpx.Response。"""
    headers_extra = kw.pop("headers", {})

    def _do():
        headers = {
            "apikey": cfg["anon_key"],
            "Authorization": f"Bearer {cfg['access_token']}",
            "Content-Type": "application/json",
        }
        headers.update(headers_extra)
        with _client() as c:
            return c.request(method, f"{cfg['url']}/rest/v1/{path}", headers=headers, **kw)

    r = _do()
    if r.status_code == 401 and _refresh(cfg):
        r = _do()
    return r


# ── 表配置：本地直连 SQLite，内容指纹去重 ────────────────────────────────────

def _conn(db: str) -> sqlite3.Connection:
    return sqlite3.connect(str(_DATA / db), check_same_thread=False)


def _now() -> float:
    return time.time()


def _local_rows_memory(uid: str) -> list[dict[str, Any]]:
    con = _conn("memory.db")
    try:
        rows = con.execute(
            "SELECT text,kind,created_at,updated_at FROM user_memory WHERE user_id=?", (uid,)
        ).fetchall()
    finally:
        con.close()
    return [{
        "content_hash": _hash(text), "text": text, "kind": kind or "fact",
        "created_at": created, "updated_at": updated or created or _now(),
    } for text, kind, created, updated in rows]


def _insert_memory(uid: str, row: dict[str, Any]) -> None:
    con = _conn("memory.db")
    try:
        con.execute(
            "INSERT INTO user_memory(user_id,text,kind,created_at,updated_at) VALUES(?,?,?,?,?)",
            (uid, row["text"], row.get("kind", "fact"), row.get("created_at"), row.get("updated_at")),
        )
        con.commit()
    finally:
        con.close()


def _local_rows_cases(uid: str) -> list[dict[str, Any]]:
    con = _conn("cases.db")
    try:
        rows = con.execute(
            "SELECT problem,solution,model,created_at FROM cases WHERE user_id=?", (uid,)
        ).fetchall()
    finally:
        con.close()
    return [{
        "content_hash": _hash(p), "problem": p, "solution": s, "model": m or "",
        "created_at": c, "updated_at": c or _now(),
    } for p, s, m, c in rows]


def _insert_cases(uid: str, row: dict[str, Any]) -> None:
    con = _conn("cases.db")
    try:
        con.execute(
            "INSERT INTO cases(user_id,problem,solution,model,created_at) VALUES(?,?,?,?,?)",
            (uid, row["problem"], row["solution"], row.get("model", ""), row.get("created_at")),
        )
        con.commit()
    finally:
        con.close()


def _local_rows_kb_docs(uid: str) -> list[dict[str, Any]]:
    con = _conn("knowledge.db")
    try:
        # 老库无 status 列（未用新版引擎打开过）→ 视为 active，不炸；
        # 对齐 knowledge.py 的 PRAGMA table_info 探测惯例。
        has_status = "status" in {
            r[1] for r in con.execute("PRAGMA table_info(kb_docs)")
        }
        sel = "title,source,created_at,status" if has_status else "title,source,created_at"
        rows = con.execute(f"SELECT {sel} FROM kb_docs WHERE user_id=?", (uid,)).fetchall()
    finally:
        con.close()
    return [{
        "content_hash": _hash(f"{r[0]}\n{r[1] or ''}"), "title": r[0], "source": r[1] or "",
        "created_at": r[2], "updated_at": r[2] or _now(),
        "status": (r[3] if has_status else "active") or "active",
    } for r in rows]


_KB_DOC_STATUSES = ("active", "superseded", "archived")  # 对齐 knowledge._STATUSES


def _insert_kb_docs(uid: str, row: dict[str, Any]) -> None:
    con = _conn("knowledge.db")
    try:
        # 对端老库无 status 列 → 按 knowledge.py 的 PRAGMA + ALTER 迁移惯例就地补列。
        if "status" not in {r[1] for r in con.execute("PRAGMA table_info(kb_docs)")}:
            con.execute("ALTER TABLE kb_docs ADD COLUMN status TEXT DEFAULT 'active'")
        status = row.get("status")
        if status not in _KB_DOC_STATUSES:  # 远端脏值不落地，缺省 active
            status = "active"
        con.execute(
            "INSERT INTO kb_docs(user_id,title,source,chunks,created_at,status) "
            "VALUES(?,?,?,0,?,?)",
            (uid, row["title"], row.get("source", ""), row.get("created_at"), status),
        )
        con.commit()
    finally:
        con.close()


def _local_rows_kb_chunks(uid: str) -> list[dict[str, Any]]:
    con = _conn("knowledge.db")
    try:
        rows = con.execute(
            "SELECT c.text,c.title,d.title,d.source FROM kb_chunks c "
            "JOIN kb_docs d ON c.doc_id=d.id WHERE c.user_id=?", (uid,)
        ).fetchall()
    finally:
        con.close()
    return [{
        "content_hash": _hash(text), "doc_hash": _hash(f"{dt}\n{ds or ''}"),
        "title": title, "text": text, "updated_at": _now(),
    } for text, title, dt, ds in rows]


def _insert_kb_chunks(uid: str, row: dict[str, Any]) -> None:
    """按 doc_hash 找回本地文档 id 再插入分块；文档还没同步到则跳过（下次补）。"""
    con = _conn("knowledge.db")
    try:
        doc_id = None
        for did, t, s in con.execute(
            "SELECT id,title,source FROM kb_docs WHERE user_id=?", (uid,)
        ).fetchall():
            if _hash(f"{t}\n{s or ''}") == row.get("doc_hash"):
                doc_id = did
                break
        if doc_id is None:
            return
        con.execute(
            "INSERT INTO kb_chunks(user_id,doc_id,title,text) VALUES(?,?,?,?)",
            (uid, doc_id, row.get("title"), row["text"]),
        )
        con.commit()
    finally:
        con.close()


TABLES: dict[str, dict[str, Any]] = {
    "memory": {"read": _local_rows_memory, "insert": _insert_memory,
               "cols": ["content_hash", "text", "kind", "created_at", "updated_at"]},
    "cases": {"read": _local_rows_cases, "insert": _insert_cases,
              "cols": ["content_hash", "problem", "solution", "model", "created_at", "updated_at"]},
    "kb_docs": {"read": _local_rows_kb_docs, "insert": _insert_kb_docs,
                "cols": ["content_hash", "title", "source", "status", "created_at", "updated_at"]},
    "kb_chunks": {"read": _local_rows_kb_chunks, "insert": _insert_kb_chunks,
                  "cols": ["content_hash", "doc_hash", "title", "text", "updated_at"]},
}
# 同步顺序：先文档后分块，让分块能按 doc_hash 找到本地文档。
_ORDER = ["memory", "cases", "kb_docs", "kb_chunks"]


def _push(cfg: dict[str, Any], table: str) -> int:
    spec = TABLES[table]
    local = spec["read"](cfg["local_user"])
    if not local:
        return 0
    uid = cfg["user_id"]
    rows = [{"user_id": uid, **{k: r.get(k) for k in spec["cols"]}} for r in local]
    pushed = 0
    for i in range(0, len(rows), 200):  # 分批，避免单请求过大
        _ensure_target_unchanged(cfg)
        batch = rows[i : i + 200]
        r = _rest(
            cfg, "POST", f"{table}?on_conflict=user_id,content_hash",
            headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
            json=batch,
        )
        if r.status_code in (200, 201, 204):
            pushed += len(batch)
    return pushed


def _pull(cfg: dict[str, Any], table: str) -> int:
    spec = TABLES[table]
    since = float(cfg.get("last_sync", {}).get(table, 0) or 0)
    r = _rest(
        cfg,
        "GET",
        f"{table}?select=*&updated_at=gt.{since}&order=updated_at.asc&limit=1000",
    )
    if r.status_code != 200:
        return 0
    remote = r.json() or []
    if not remote:
        return 0
    if not isinstance(remote, list) or len(remote) > 1000:
        raise ValueError("Supabase pull 返回格式或行数超限")

    expected_identity = _cfg_identity(cfg)
    # Snapshot only the security identity/cursor under the config lock.  The
    # potentially large local full-table read deliberately runs outside it, so
    # status/configuration endpoints remain responsive.
    with _lock:
        current = _load_cfg_unlocked()
        if _cfg_identity(current) != expected_identity:
            raise _TargetChanged("Supabase 目标在同步期间已变更")
        uid = current["local_user"]

    local_hashes = {
        row["content_hash"] for row in spec["read"](uid)
    }
    merged = 0
    max_ts = since
    for row in remote:
        if not isinstance(row, dict):
            continue
        max_ts = max(max_ts, float(row.get("updated_at") or 0))
        h = row.get("content_hash")
        if row.get("deleted"):
            continue  # 删除传播：MVP 保守不在本地删（避免误删），仅推进时间戳
        if h and h not in local_hashes:
            try:
                # Hold the config fence for one bounded insert, rather than an
                # entire table scan/batch.  A target/account change can run
                # between rows but can never race one old-tenant write.
                with _lock:
                    current = _load_cfg_unlocked()
                    if _cfg_identity(current) != expected_identity:
                        raise _TargetChanged("Supabase 目标在同步期间已变更")
                    spec["insert"](current["local_user"], row)
                local_hashes.add(h)
                merged += 1
            except _TargetChanged:
                raise
            except Exception:  # noqa: BLE001
                pass

    # Cursor CAS is short and merges into the latest cursor map.  Partial rows
    # remain harmless if the target changed: hashes make the next pull idempotent.
    with _lock:
        current = _load_cfg_unlocked()
        if _cfg_identity(current) != expected_identity:
            raise _TargetChanged("Supabase 目标在同步期间已变更")
        next_cursor = dict(current.get("last_sync") or {})
        next_cursor[table] = max_ts
        candidate = _validated_cfg({**current, "last_sync": next_cursor})
        _write_cfg_unlocked(candidate)
    cfg["last_sync"] = next_cursor
    return merged


def _rebuild_kb_fts() -> None:
    """云端 kb_chunks 合并进本地后重建 FTS 索引（_insert_kb_chunks 直插不维护 kb_fts）。

    失败静默降级——FTS 缺失时检索自动退回纯覆盖率，绝不能让同步因此报错；
    行数不一致会由 scripts/kb_doctor.py 体检报出。
    """
    try:
        from orchestrator.knowledge import KnowledgeBase  # 延迟导入，避免模块级重依赖

        kb = KnowledgeBase(str(_DATA / "knowledge.db"))
        try:
            kb.rebuild_fts()
        finally:
            kb.close()
    except Exception:  # noqa: BLE001
        pass


def sync_all() -> dict[str, Any]:
    """对四张表各 push 本地 + pull 远端合并。未就绪则安全跳过。返回每表统计。"""
    # Do not queue UI/manual calls behind a long network sync. Retarget remains
    # responsive; per-request target fencing prevents cross-tenant merges.
    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "skipped": True, "reason": "已有云同步在运行"}
    try:
        cfg = load_cfg()
        if not (
            cfg["enabled"]
            and cfg["url"]
            and cfg["anon_key"]
            and cfg["access_token"]
            and cfg["user_id"]
        ):
            return {"ok": False, "skipped": True, "reason": "未配置、未登录或未启用"}
        result: dict[str, Any] = {"ok": True, "pushed": {}, "pulled": {}}
        try:
            for table in _ORDER:
                result["pushed"][table] = _push(cfg, table)
                result["pulled"][table] = _pull(cfg, table)
            if result["pulled"].get("kb_chunks"):
                _rebuild_kb_fts()  # 云端分块落地后补齐本地 FTS；内部静默降级
        except Exception as e:  # noqa: BLE001
            result["ok"] = False
            result["error"] = f"{type(e).__name__}: {e}"
        return result
    finally:
        _sync_lock.release()
