"""Quarantined registry for legacy, unaudited MCP server definitions.

MCP definitions are executable supply-chain inputs, not passive configuration.
Production therefore keeps activation disabled by default. Existing data stays
visible for migration/removal. Even after an operator enables trusted MCP, only
an absolute local executable whose bytes match the recorded SHA-256 is active;
the former unverified break-glass mode is permanently inert.
"""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
from pathlib import Path
from typing import Any, Optional

from gateway.runtime_profile import RuntimeCapability, current_runtime_profile
from gateway.url_safety import is_public_http_url


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ISOLATED_MCP_WORKER_WIRED = False


def _registry_allowed() -> bool:
    return current_runtime_profile().allows(RuntimeCapability.MCP_PLUGIN_REGISTRY)


def _require_registry_allowed() -> None:
    if not _registry_allowed():
        raise RuntimeError("当前运行配置已关闭 MCP 注册表")


def verified_mcp_enabled() -> bool:
    """MCP execution stays off until it runs in the isolated worker boundary."""

    return _ISOLATED_MCP_WORKER_WIRED and current_runtime_profile().allows(
        RuntimeCapability.MCP_PLUGIN_REGISTRY
    )


def unverified_mcp_enabled() -> bool:
    """Compatibility shim: the former unsafe break-glass switch is intentionally inert."""

    return False


def _path() -> Path:
    from gateway.config import PROJECT_ROOT

    return PROJECT_ROOT / "data" / "mcp.json"


# 历史 MCP 预设只用于说明/迁移。它们依赖 npx/uvx 远程解析且没有独立 SHA-256，
# runtime_available() 会固定返回 False，不能再“一键下载并执行”。
PRESETS: list[dict[str, Any]] = [
    {
        "name": "filesystem", "desc": "读写指定目录的文件", "runtime": "node",
        "command": "", "args": [], "audited": False,
        "note": "远程包预设已隔离；请安装审计后的本地二进制并登记 SHA-256",
    },
    {
        "name": "fetch", "desc": "抓取网页正文（喂给模型读）", "runtime": "python",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "puppeteer", "desc": "自动化网页/截图/表单", "runtime": "node",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "playwright", "desc": "浏览器自动化与网页验证", "runtime": "node",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "memory", "desc": "知识图谱式长期记忆", "runtime": "node",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "git", "desc": "在本地仓库跑 git 操作", "runtime": "python",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "sqlite", "desc": "查询本地 SQLite 数据库", "runtime": "python",
        "command": "", "args": [], "audited": False,
        "note": "远程包预设已隔离；数据库路径须在本地证明清单中绑定",
    },
    {
        "name": "sequentialthinking", "desc": "结构化分步推理", "runtime": "node",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "time", "desc": "时间 / 时区换算", "runtime": "python",
        "command": "", "args": [], "audited": False,
    },
    {
        "name": "context7", "desc": "按需读取库/框架最新文档", "runtime": "node",
        "command": "", "args": [], "audited": False,
    },
]


def runtime_available(runtime: str) -> bool:
    """远程包运行时永远不可一键启用；其它本地运行时仅作 UI 探测。"""
    if runtime in {"node", "python"}:
        return False
    return False


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verified_stdio(spec: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return a sanitized stdio spec only for an absolute, hash-pinned local executable."""

    try:
        command = Path(str(spec.get("command") or ""))
        expected = str(spec.get("sha256") or "").strip().lower()
        if not command.is_absolute() or not command.is_file():
            return None
        if command.name.lower() in {
            "npx", "npx.cmd", "npm", "npm.cmd", "uvx", "uvx.exe", "pip", "pip.exe",
            "pipx", "pipx.exe", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd",
        }:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            return None
        if not hmac.compare_digest(_file_sha256(command), expected):
            return None
        args = spec.get("args") or []
        if not isinstance(args, list) or len(args) > 64 or not all(isinstance(v, str) for v in args):
            return None
        return {"command": str(command), "args": list(args)}
    except (OSError, ValueError):
        return None


def probe(spec: dict) -> dict:
    """快速可用性自检：http 看有没有 url；stdio 看 command 在不在 PATH。不真启动 server。"""
    if spec.get("url"):
        return {"ok": False, "detail": "remote MCP is quarantined; no signed trust manifest"}
    verified = _verified_stdio(spec)
    if not verified_mcp_enabled():
        return {"ok": False, "detail": "verified MCP activation is disabled"}
    if not verified:
        return {"ok": False, "detail": "requires absolute local executable + matching SHA-256"}
    return {"ok": True, "detail": "local executable SHA-256 verified"}


def load() -> dict:
    if not _registry_allowed():
        return {"mcpServers": {}}
    p = _path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            pass
    return {"mcpServers": {}}


def save(cfg: dict) -> None:
    _require_registry_allowed()
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def list_servers() -> dict:
    return load().get("mcpServers", {})


def public_servers() -> dict:
    """Return UI-safe definitions without plaintext environment values."""

    out: dict[str, dict[str, Any]] = {}
    for name, raw in list_servers().items():
        if not isinstance(raw, dict):
            continue
        spec = {k: v for k, v in raw.items() if k != "env"}
        if isinstance(raw.get("env"), dict):
            spec["env_keys"] = sorted(str(k) for k in raw["env"])
        out[str(name)] = spec
    return out


def config_path() -> Optional[str]:
    """Expose a generated config containing only verified local executable definitions."""
    if not verified_mcp_enabled():
        return None
    active = {
        name: clean
        for name, raw in list_servers().items()
        if isinstance(raw, dict) and (clean := _verified_stdio(raw)) is not None
    }
    if not active:
        return None
    p = _path().with_name("mcp.active.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps({"mcpServers": active}, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)
    return str(p)


def active_server_names() -> list[str]:
    """Return only names whose current executable bytes pass attestation."""

    if not verified_mcp_enabled():
        return []
    return sorted(
        name
        for name, raw in list_servers().items()
        if isinstance(raw, dict) and _verified_stdio(raw) is not None
    )


def add_server(
    name: str,
    *,
    command: str = "",
    args: Optional[list[str]] = None,
    env: Optional[dict[str, str]] = None,
    url: str = "",
    sha256: str = "",
) -> dict:
    """Persist a definition; activation remains separately gated and attested."""
    _require_registry_allowed()
    if not _NAME_RE.fullmatch(str(name or "")):
        raise ValueError("invalid MCP server name")
    if env:
        raise ValueError("plaintext MCP env is forbidden; use a future secure secret reference")
    if bool(command) == bool(url):
        raise ValueError("provide exactly one of command or url")
    if url and not is_public_http_url(url):
        raise ValueError("MCP URL must be a public http/https URL")
    if len(str(command)) > 260 or len(args or []) > 64 or any(len(str(v)) > 2048 for v in (args or [])):
        raise ValueError("MCP command or arguments exceed limits")
    spec: dict[str, Any] = (
        {"url": url}
        if url
        else {"command": command, "args": args or [], "sha256": str(sha256 or "").lower()}
    )
    cfg = load()
    cfg.setdefault("mcpServers", {})[name] = spec
    save(cfg)
    return cfg["mcpServers"]


def remove_server(name: str) -> dict:
    _require_registry_allowed()
    cfg = load()
    cfg.get("mcpServers", {}).pop(name, None)
    save(cfg)
    return cfg.get("mcpServers", {})


def sync_codex(name: str, spec: dict) -> bool:
    """Compatibility shim; host-side MCP/CLI synchronization is disabled."""
    del name, spec
    return False


def sync_all_codex() -> int:
    """启动时把 data/mcp.json 里的全部 server 同步进 codex。返回成功数。"""
    if not verified_mcp_enabled():
        return 0
    return sum(1 for name, spec in list_servers().items() if sync_codex(name, spec))
