#!/usr/bin/env python
r"""开发源码巡检（不是桌面安装包自动更新）：**自动发现 + 报告落盘 + 可选飞书推送**。

本脚本与 0.2.0 early-access 的 Ed25519 签名安装包更新通道无关；不得把它当成产品更新器或未经机主授权注册计划任务。

设计哲学一句话：**发现 ≠ 应用**。本脚本只「看」不「改」——
它不会自动改代码、不会自动升级依赖、不会自动接入新模型。
它把四路信号汇成一份 markdown 报告落到 data/，想应用哪一项由机主一句话授权。

四个探测器，各自独立 try/except（一个挂了其它照跑）：
  ① 新模型     —— 各 openai_compat 连接拉 /models，对比已接入，列「上游有但本地没接」的新 id。
  ② Python 依赖 —— 项目 .venv 的绝对 Python，或显式 SHA-256 认证的 uv，只读列 top 15。
  ③ npm 依赖    —— 认证 Node + npm 全代码树后跑 outdated（非零退出码也算正常输出），列 top 15。
  ④ 上游动态    —— 认证 gh 后只读盯 SakanaAI/fugu 等 4 个仓库的 release / 最新 commit，
                    与上次快照(data/watch_state.json)比，只报有变化的；首跑全报并落快照。

硬约束（安全）：
  - 密钥**绝不**落报告/日志：连接的 api_key 只进 /models 请求头，从不写进任何输出文本。
  - 外发只有三种：各连接的 /models GET、gh api（只读）、可选飞书推送（机主 bot 发给机主自己）。
  - 子进程不解析 PATH；外部工具必须绑定绝对路径与 SHA-256，npm 还绑定整个传递代码树。
  - 全程降级容错，任一子进程/网络失败都不影响报告落盘。

用法：
  .\.venv\Scripts\python.exe scripts\watch_updates.py            # 跑一遍
  .\.venv\Scripts\python.exe scripts\watch_updates.py --feishu  # 可选飞书摘要
  .\.venv\Scripts\python.exe scripts\watch_updates.py --json     # 机器可读
  .\.venv\Scripts\python.exe scripts\watch_updates.py --dry      # 不联网自检
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat as stat_module
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# A directly launched script receives scripts/ rather than the repository root
# on sys.path.  Establish the project import root only after rejecting a
# symlink/reparse launch chain; otherwise the documented manual entrypoint
# fails before it can enforce any of its tool boundaries.
_SCRIPT_PATH = Path(__file__).absolute()
try:
    for _component in (_SCRIPT_PATH, *_SCRIPT_PATH.parents):
        _info = os.lstat(_component)
        if _component.is_symlink() or int(
            getattr(_info, "st_file_attributes", 0)
        ) & int(getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise OSError("watcher launch path contains a redirect")
    PROJECT_ROOT = _SCRIPT_PATH.resolve(strict=True).parent.parent
except OSError as _bootstrap_error:
    raise SystemExit("更新巡检入口路径不可信，已拒绝启动") from _bootstrap_error
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx

from gateway.connections import ConnectionStore
from gateway.providers.attested_cli import file_sha256, from_environment, matches_attestation
from gateway.secure_store import SecureStorageError

# Windows 控制台默认 GBK，emoji/✓/生僻字会噎死 → 统一 utf-8 输出（照 scripts/_edit_check.py）
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass

DATA_DIR = PROJECT_ROOT / "data"
CONNECTIONS_PATH = DATA_DIR / "connections.json"
STATE_PATH = DATA_DIR / "watch_state.json"

# 盯的上游项目（Fugu/OpenFugu/OpenManus/RouteLLM）——只读 releases/commits
WATCHED_REPOS = [
    "SakanaAI/fugu",
    "trotsky1997/OpenFugu",
    "FoundationAgents/OpenManus",
    "lm-sys/RouteLLM",
]

_HTTP_TIMEOUT = 10.0
_TOP_N = 15  # 依赖只列前 N 个，避免报告冗长

_BASE_CHILD_ENV = {
    # Native runtime/bootstrap and scratch paths.  PATH/COMSPEC are intentionally absent.
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "TMPDIR",
    # Read-only tools may need their normal configuration/cache or a corporate TLS proxy.
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
}
_GH_CHILD_ENV = {"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_CONFIG_DIR"}
_MAX_NPM_TREE_FILES = 20_000
_MAX_NPM_TREE_BYTES = 256 * 1024 * 1024


class _ToolUnavailable(RuntimeError):
    """A read-only probe has no valid, attested process boundary."""


@dataclass(frozen=True)
class _AttestedAsset:
    path: str
    sha256: str
    executable: bool
    tree: bool = False

    def verify(self) -> bool:
        if self.tree:
            return _matches_attested_tree(self.path, self.sha256)
        if self.executable:
            return matches_attestation(self.path, self.sha256)
        return _matches_attested_data_file(self.path, self.sha256)


@dataclass(frozen=True)
class _ToolCommand:
    name: str
    prefix: tuple[str, ...]
    assets: tuple[_AttestedAsset, ...]

    def argv(self, arguments: list[str]) -> list[str]:
        # Re-attest immediately before every launch.  A successful earlier probe
        # must not authorize a file that has since been replaced.
        if not self.assets or any(not asset.verify() for asset in self.assets):
            raise _ToolUnavailable(f"{self.name} 工具身份复核失败")
        return [*self.prefix, *arguments]


# ─────────────────────────── 工具 ───────────────────────────
def _log(msg: str) -> None:
    """打印一条不含任何密钥的进度/警告。"""
    print(msg, flush=True)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text("utf-8"))
    except Exception:  # noqa: BLE001  文件不存在/损坏 → 空
        return None


def _load_connections() -> dict[str, Any] | None:
    """透明读取/迁移 DPAPI 连接文件；安全存储异常时按不可用处理且不输出细节。"""
    try:
        return ConnectionStore(CONNECTIONS_PATH).all()
    except (SecureStorageError, OSError):
        return None


def _path_has_redirect(path: Path) -> bool:
    try:
        for component in reversed((path, *path.parents)):
            info = os.lstat(component)
            if component.is_symlink() or (
                int(getattr(info, "st_file_attributes", 0))
                & int(getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            ):
                return True
        return False
    except OSError:
        return True


def _matches_attested_data_file(raw_path: str, expected_sha256: str) -> bool:
    """Verify an interpreter-bound data file such as npm-cli.js."""
    candidate = Path(str(raw_path or ""))
    expected = str(expected_sha256 or "").strip().lower()
    if not candidate.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    try:
        info = os.lstat(candidate)
        if (
            not stat_module.S_ISREG(info.st_mode)
            or candidate.is_symlink()
            or int(getattr(info, "st_file_attributes", 0)) & 0x400
            or _path_has_redirect(candidate)
            or candidate.suffix.lower() not in {".js", ".cjs"}
        ):
            return False
        return hmac.compare_digest(file_sha256(candidate), expected)
    except OSError:
        return False


def _stable_file_identity(info: os.stat_result) -> tuple[int, ...]:
    # Windows can report creation/change time with different rounding across
    # stat views of the same file.  Keep the stable identity fields only.
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(getattr(info, "st_file_attributes", 0)),
    )


def _tree_file_sha256(path: Path, before: os.stat_result) -> str:
    """Hash one tree member; empty marker files are valid npm package content."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if _stable_file_identity(before) != _stable_file_identity(opened):
            raise OSError("tool tree file changed while opening")
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            total += len(chunk)
            if total > _MAX_NPM_TREE_BYTES:
                raise OSError("tool tree member exceeds the attestation bound")
            digest.update(chunk)
    after = os.lstat(path)
    if total != int(before.st_size) or _stable_file_identity(before) != _stable_file_identity(after):
        raise OSError("tool tree file changed while hashing")
    return digest.hexdigest()


def _attested_tree_sha256(root: Path) -> str:
    """Hash a closed npm package tree without following links or reparse points."""
    if not root.is_absolute() or _path_has_redirect(root):
        raise OSError("tool tree path is not an absolute non-reparse directory")
    root_info = os.lstat(root)
    if not stat_module.S_ISDIR(root_info.st_mode):
        raise OSError("tool tree root is not a directory")

    digest = hashlib.sha256(b"nachuan-watch-tool-tree-v1\0")
    pending = [root]
    files = 0
    total_bytes = 0
    while pending:
        directory = pending.pop()
        before_directory = os.lstat(directory)
        if (
            not stat_module.S_ISDIR(before_directory.st_mode)
            or int(getattr(before_directory, "st_file_attributes", 0)) & 0x400
        ):
            raise OSError("tool tree directory changed or became a reparse point")
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            # On Windows DirEntry.stat may report st_dev/st_ino as zero while
            # os.lstat returns the volume/file ID.  Use one stat view on both
            # sides of the hash so identity comparison is meaningful.
            info = os.lstat(path)
            if entry.is_symlink() or int(getattr(info, "st_file_attributes", 0)) & 0x400:
                raise OSError("tool tree contains a link or reparse point")
            relative = path.relative_to(root).as_posix().encode("utf-8")
            if len(relative) > 4096 or b"\0" in relative:
                raise OSError("tool tree contains an invalid path")
            if stat_module.S_ISDIR(info.st_mode):
                digest.update(b"D")
                digest.update(len(relative).to_bytes(4, "big"))
                digest.update(relative)
                child_directories.append(path)
                continue
            if not stat_module.S_ISREG(info.st_mode):
                raise OSError("tool tree contains a non-regular entry")
            files += 1
            total_bytes += int(info.st_size)
            if files > _MAX_NPM_TREE_FILES or total_bytes > _MAX_NPM_TREE_BYTES:
                raise OSError("tool tree exceeds the attestation bound")
            content_sha256 = _tree_file_sha256(path, info)
            digest.update(b"F")
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(int(info.st_size).to_bytes(8, "big"))
            digest.update(bytes.fromhex(content_sha256))
        after_directory = os.lstat(directory)
        if _stable_file_identity(before_directory) != _stable_file_identity(after_directory):
            raise OSError("tool tree directory changed while scanning")
        pending.extend(reversed(child_directories))
    if files <= 0:
        raise OSError("tool tree is empty")
    return digest.hexdigest()


def _matches_attested_tree(raw_path: str, expected_sha256: str) -> bool:
    root = Path(str(raw_path or ""))
    expected = str(expected_sha256 or "").strip().lower()
    if not root.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    try:
        return hmac.compare_digest(_attested_tree_sha256(root), expected)
    except OSError:
        return False


def _asset_from_environment(
    *,
    name: str,
    path_variable: str,
    hash_variable: str,
    executable: bool,
) -> _AttestedAsset:
    if executable:
        attested = from_environment(path_variable, hash_variable)
        if attested is None:
            raise _ToolUnavailable(
                f"{name} 未配置可信工具：需同时设置 {path_variable} 绝对路径与 {hash_variable}"
            )
        return _AttestedAsset(attested.path, attested.sha256, True)

    raw_path = str(os.environ.get(path_variable) or "").strip()
    expected = str(os.environ.get(hash_variable) or "").strip().lower()
    if not _matches_attested_data_file(raw_path, expected):
        raise _ToolUnavailable(
            f"{name} 未配置可信工具：需同时设置 {path_variable} 绝对路径与 {hash_variable}"
        )
    canonical = str(Path(raw_path).resolve(strict=True))
    return _AttestedAsset(canonical, expected, False)


def _current_python_pip_command() -> _ToolCommand:
    """Prefer the already-running project venv interpreter, never a PATH shim."""
    try:
        executable = Path(sys.executable).resolve(strict=True)
        project_venv = (PROJECT_ROOT / ".venv").resolve(strict=True)
        executable.relative_to(project_venv)
        if not (project_venv / "pyvenv.cfg").is_file():
            raise OSError("project venv marker is missing")
        expected = file_sha256(executable)
    except (OSError, ValueError) as ex:
        raise _ToolUnavailable("当前 Python 不是可复核的项目 .venv 解释器") from ex
    asset = _AttestedAsset(str(executable), expected, True)
    if not asset.verify():
        raise _ToolUnavailable("当前 Python 不是可复核的项目 .venv 解释器")
    return _ToolCommand(
        name="python-pip",
        prefix=(str(executable), "-I", "-m", "pip"),
        assets=(asset,),
    )


def _resolve_uv_command() -> _ToolCommand:
    asset = _asset_from_environment(
        name="uv",
        path_variable="NACHUAN_WATCH_UV_BIN",
        hash_variable="NACHUAN_WATCH_UV_SHA256",
        executable=True,
    )
    return _ToolCommand(name="uv", prefix=(asset.path, "pip"), assets=(asset,))


def _resolve_npm_command() -> _ToolCommand:
    node = _asset_from_environment(
        name="node",
        path_variable="NACHUAN_WATCH_NODE_BIN",
        hash_variable="NACHUAN_WATCH_NODE_SHA256",
        executable=True,
    )
    npm_cli = _asset_from_environment(
        name="npm-cli",
        path_variable="NACHUAN_WATCH_NPM_CLI",
        hash_variable="NACHUAN_WATCH_NPM_CLI_SHA256",
        executable=False,
    )
    npm_cli_path = Path(npm_cli.path)
    npm_root = npm_cli_path.parent.parent
    expected_cli = npm_root / "bin" / "npm-cli.js"
    if os.path.normcase(str(npm_cli_path)) != os.path.normcase(str(expected_cli)):
        raise _ToolUnavailable("npm-cli 必须是认证 npm 包根目录下的 bin/npm-cli.js")
    tree_sha256 = str(os.environ.get("NACHUAN_WATCH_NPM_TREE_SHA256") or "").strip().lower()
    npm_tree = _AttestedAsset(str(npm_root), tree_sha256, False, True)
    if not npm_tree.verify():
        raise _ToolUnavailable(
            "npm 包闭包未认证：需 NACHUAN_WATCH_NPM_TREE_SHA256 绑定整个 npm 代码树"
        )
    # npm.cmd is deliberately unsupported: hashing a command shim does not bind
    # the cmd.exe interpreter or the transitive JavaScript tree it dispatches to.
    return _ToolCommand(
        name="npm",
        prefix=(node.path, npm_cli.path),
        assets=(node, npm_cli, npm_tree),
    )


def _resolve_gh_command() -> _ToolCommand:
    asset = _asset_from_environment(
        name="gh",
        path_variable="NACHUAN_WATCH_GH_BIN",
        hash_variable="NACHUAN_WATCH_GH_SHA256",
        executable=True,
    )
    return _ToolCommand(name="gh", prefix=(asset.path,), assets=(asset,))


def _minimal_child_env(tool: str = "") -> dict[str, str]:
    allowed = {name.upper() for name in _BASE_CHILD_ENV}
    if tool == "gh":
        allowed.update(name.upper() for name in _GH_CHILD_ENV)
    out = {str(k): str(v) for k, v in os.environ.items() if str(k).upper() in allowed}
    out.update({"NO_COLOR": "1", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    if tool == "npm":
        # This is an inventory query, never an install.  Pin the public registry
        # and close Node/npm code-injection knobs by omitting them from the env.
        out.update(
            {
                "npm_config_registry": "https://registry.npmjs.org",
                "npm_config_ignore_scripts": "true",
                "npm_config_audit": "false",
                "npm_config_fund": "false",
            }
        )
    return out


def _run_cmd(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """跑子进程，返回 (returncode, stdout, stderr)；异常统一收敛为 (-1, "", err)。"""
    if not args or not Path(args[0]).is_absolute():
        return -1, "", "拒绝执行未绑定的相对命令或 PATH 命令"
    try:
        r = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            # Windows 默认按 locale(GBK) 解码子进程 stdout；gh/npm 返回 UTF-8 JSON，
            # 含中文/emoji commit message 时会 UnicodeDecodeError。强制 UTF-8 + 容错。
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            env=dict(env) if env is not None else _minimal_child_env(),
            **(
                {"creationflags": int(getattr(subprocess, "CREATE_NO_WINDOW", 0))}
                if os.name == "nt"
                else {}
            ),
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except FileNotFoundError:
        return -1, "", f"命令不存在: {args[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"命令超时: {' '.join(args)}"
    except Exception as ex:  # noqa: BLE001
        return -1, "", f"{type(ex).__name__}: {ex}"


def _run_tool(
    tool: _ToolCommand,
    arguments: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
) -> tuple[int, str, str]:
    try:
        argv = tool.argv(arguments)
    except _ToolUnavailable as ex:
        return -1, "", str(ex)
    return _run_cmd(
        argv,
        cwd=cwd,
        timeout=timeout,
        env=_minimal_child_env(tool.name),
    )


# ───────────────────── ① 新模型探测 ─────────────────────
def _preset_known_upstream() -> set[str]:
    """gateway/catalog.py 预设里所有 upstream_model（本地视作「已知/已接入」的候选集）。"""
    known: set[str] = set()
    try:
        from gateway.catalog import PROVIDER_PRESETS  # 延迟导入：无 gateway 环境也能跑其它探测器

        for p in PROVIDER_PRESETS:
            for m in p.get("models", []):
                up = m.get("upstream_model")
                mid = m.get("id")
                if up:
                    known.add(str(up))
                if mid:
                    known.add(str(mid))
    except Exception as ex:  # noqa: BLE001
        _log(f"[新模型] 读预设失败（不影响）：{ex}")
    return known


def _family_version(mid: str) -> tuple[str, tuple[int, ...]]:
    """把模型 id 拆成 (族骨架, 版本元组)：数字段抽成版本、原位置替换成 #。

    例：agnes-1.5-flash → ('agnes-#-flash', (1,5))；agnes-image-2.1-flash → ('agnes-image-#-flash', (2,1))。
    同骨架 = 同族，可比版本。抽不到数字则版本为空元组（视作无版本，不参与新旧判断）。
    """
    nums = tuple(int(n) for n in re.findall(r"\d+", mid))
    family = re.sub(r"\d+(?:\.\d+)*", "#", mid)
    return family, nums


def _split_stale(new_ids: list[str], local_ids: set[str]) -> tuple[list[str], list[str]]:
    """版本感知（机主实测被误导后补）：上游多出的 id 若与本地已接模型**同族**且版本**不高于**已接版
    → 归入 stale（上游没下架的旧版，接入=降级，报告里标注可忽略）；其余才是真·新模型/升级版。"""
    local_fam: dict[str, tuple[int, ...]] = {}
    for lid in local_ids:
        fam, ver = _family_version(lid)
        if ver and (fam not in local_fam or ver > local_fam[fam]):
            local_fam[fam] = ver  # 同族取本地最高版
    fresh: list[str] = []
    stale: list[str] = []
    for mid in new_ids:
        fam, ver = _family_version(mid)
        if ver and fam in local_fam and ver <= local_fam[fam]:
            stale.append(mid)
        else:
            fresh.append(mid)
    return fresh, stale


def _fetch_models(base_url: str, api_key: str) -> list[str]:
    """GET {base_url}/models，返回模型 id 列表。key 只用于请求头，绝不外泄。"""
    url = base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    r = httpx.get(url, headers=headers, timeout=_HTTP_TIMEOUT)
    r.raise_for_status()
    body = r.json()
    # OpenAI 兼容：{"data": [{"id": ...}, ...]}；少数厂商直接返回 list
    rows = body.get("data", body) if isinstance(body, dict) else body
    out: list[str] = []
    if isinstance(rows, list):
        for it in rows:
            if isinstance(it, dict) and it.get("id"):
                out.append(str(it["id"]))
            elif isinstance(it, str):
                out.append(it)
    return out


def probe_new_models(dry: bool = False) -> dict[str, Any]:
    """对每个 openai_compat 且有 base_url+key 的连接拉 /models，列上游有但本地没接入的新模型。"""
    result: dict[str, Any] = {"ok": True, "connections": [], "note": ""}
    if dry:
        result["note"] = "dry：跳过网络"
        return result

    conns = _load_connections()
    if not isinstance(conns, dict) or not conns:
        result["note"] = "无 connections.json 或为空"
        return result

    preset_known = _preset_known_upstream()

    for pname, conn in conns.items():
        if not isinstance(conn, dict):
            continue
        if conn.get("type") != "openai_compat":
            continue  # 只对通用 OpenAI 兼容连接拉 /models（其余类型 /models 语义不统一）
        base_url = (conn.get("base_url") or "").strip()
        api_key = (conn.get("api_key") or "").strip()
        if not base_url or not api_key:
            continue

        entry: dict[str, Any] = {"provider": pname, "new_models": [], "error": ""}
        try:
            upstream_ids = _fetch_models(base_url, api_key)
        except Exception as ex:  # noqa: BLE001  单连接失败跳过，不带出任何 key
            entry["error"] = f"{type(ex).__name__}"  # 只记异常类型，绝不含 url/key 细节
            result["connections"].append(entry)
            continue

        # 本地已接入 = 该连接 enabled_models 的 id + upstream_model
        local_known: set[str] = set(preset_known)
        for m in conn.get("enabled_models") or []:
            if isinstance(m, dict):
                if m.get("id"):
                    local_known.add(str(m["id"]))
                if m.get("upstream_model"):
                    local_known.add(str(m["upstream_model"]))

        new_ids = sorted(mid for mid in upstream_ids if mid not in local_known)
        # 该连接实际已接的 id（含 upstream 名），供同族版本比较——旧版不当"新模型"报
        conn_local = {
            str(m.get(k))
            for m in (conn.get("enabled_models") or [])
            if isinstance(m, dict)
            for k in ("id", "upstream_model")
            if m.get(k)
        }
        fresh, stale = _split_stale(new_ids, conn_local)
        entry["new_models"] = fresh
        entry["stale_models"] = stale
        result["connections"].append(entry)

    return result


# ───────────────────── ② Python 依赖 ─────────────────────
def _parse_outdated_json(raw: str) -> list[dict[str, str]]:
    """解析 pip/uv 的 --outdated --format json 输出为 [{name,current,latest}]。"""
    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        return []
    rows: list[dict[str, str]] = []
    if isinstance(data, list):
        for it in data:
            if not isinstance(it, dict):
                continue
            rows.append(
                {
                    "name": str(it.get("name", "")),
                    "current": str(it.get("version", it.get("current_version", ""))),
                    "latest": str(it.get("latest_version", it.get("latest", ""))),
                }
            )
    return rows


def probe_python_deps(dry: bool = False) -> dict[str, Any]:
    """用当前绝对 Python 或显式认证的 uv 查询过期依赖，列 top N。"""
    result: dict[str, Any] = {"ok": True, "outdated": [], "note": ""}
    if dry:
        result["note"] = "dry：跳过"
        return result

    commands: list[tuple[str, _ToolCommand]] = []
    try:
        commands.append(("当前 Python -I -m pip", _current_python_pip_command()))
    except _ToolUnavailable:
        pass
    try:
        commands.append(("认证 uv pip", _resolve_uv_command()))
    except _ToolUnavailable:
        pass

    tried: list[str] = []
    for label, command in commands:
        tried.append(label)
        code, out, err = _run_tool(
            command,
            ["list", "--outdated", "--format", "json"],
            cwd=PROJECT_ROOT,
            timeout=180,
        )
        if code == 0 and out.strip():
            rows = _parse_outdated_json(out)
            result["outdated"] = rows[:_TOP_N]
            result["note"] = f"via {label}（共 {len(rows)} 个过期）"
            return result

    result["ok"] = False
    attempts = "、".join(tried) if tried else "无可信命令"
    result["note"] = (
        f"Python 依赖未取到（尝试：{attempts}）；不回落 PATH，"
        "uv 需 NACHUAN_WATCH_UV_BIN + NACHUAN_WATCH_UV_SHA256"
    )
    return result


# ───────────────────── ③ npm 依赖 ─────────────────────
def probe_npm_deps(dry: bool = False) -> dict[str, Any]:
    """npm outdated --json --prefix desktop（注意：有过期项时 npm 以非零码退出，也算正常输出）。"""
    result: dict[str, Any] = {"ok": True, "outdated": [], "note": ""}
    if dry:
        result["note"] = "dry：跳过"
        return result

    desk = PROJECT_ROOT / "desktop"
    if not (desk / "package.json").exists():
        result["note"] = "无 desktop/package.json"
        return result

    try:
        npm = _resolve_npm_command()
    except _ToolUnavailable:
        result["ok"] = False
        result["note"] = (
            "npm 未配置可信 Node + npm-cli；需 NACHUAN_WATCH_NODE_BIN/SHA256 "
            "及 NACHUAN_WATCH_NPM_CLI/SHA256 + NACHUAN_WATCH_NPM_TREE_SHA256，"
            "且不回落 PATH/npm.cmd"
        )
        return result
    # npm outdated 发现过期时 returncode=1，但 stdout 仍是合法 JSON → 不看 returncode，只看能否解析
    code, out, err = _run_tool(
        npm,
        ["outdated", "--json", "--prefix", str(desk)],
        cwd=desk,
        timeout=180,
    )
    raw = out.strip()
    if not raw:
        # 空输出且退出码 0 = 没有过期；非零且空 = 命令本身出错
        if code == 0:
            result["note"] = "全部最新"
        else:
            result["ok"] = False
            result["note"] = f"npm 执行异常：{(err or '').strip()[:120]}"
        return result

    try:
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        result["ok"] = False
        result["note"] = "npm 输出非 JSON"
        return result

    rows: list[dict[str, str]] = []
    if isinstance(data, dict):
        for name, info in data.items():
            if not isinstance(info, dict):
                continue
            rows.append(
                {
                    "name": str(name),
                    "current": str(info.get("current", "")),
                    "latest": str(info.get("latest", "")),
                    "wanted": str(info.get("wanted", "")),
                }
            )
    result["outdated"] = rows[:_TOP_N]
    result["note"] = f"共 {len(rows)} 个过期"
    return result


# ───────────────────── ④ 上游项目动态 ─────────────────────
def _gh_api(path: str) -> Any:
    """gh api <path> --jq 不用（直接解析 JSON）；返回 dict/list 或 None。"""
    try:
        gh = _resolve_gh_command()
    except _ToolUnavailable:
        return None
    code, out, err = _run_tool(gh, ["api", path], timeout=30)
    if code != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:  # noqa: BLE001
        return None


def probe_upstream(dry: bool = False, state: dict[str, Any] | None = None) -> dict[str, Any]:
    """gh api 盯各仓库最新 release / commit，与上次快照比，只报有变化的；首跑全报并落新快照。"""
    result: dict[str, Any] = {
        "ok": True,
        "changed": [],  # 有变化（含首跑）的仓库
        "new_state": {},  # 本次抓到的快照（供落盘）
        "note": "",
        "first_run": False,
    }
    if dry:
        result["note"] = "dry：跳过"
        return result

    try:
        _resolve_gh_command()
    except _ToolUnavailable:
        result["ok"] = False
        result["note"] = (
            "gh 未配置可信绝对路径与 SHA-256，跳过上游探测；"
            "需 NACHUAN_WATCH_GH_BIN + NACHUAN_WATCH_GH_SHA256，且不回落 PATH"
        )
        return result

    prev = state or {}
    result["first_run"] = not bool(prev)

    for repo in WATCHED_REPOS:
        cur: dict[str, str] = {}
        rel = _gh_api(f"repos/{repo}/releases/latest")
        if isinstance(rel, dict) and rel.get("tag_name"):
            cur["release"] = str(rel.get("tag_name"))
            cur["release_url"] = str(rel.get("html_url", ""))
        commits = _gh_api(f"repos/{repo}/commits?per_page=1")
        if isinstance(commits, list) and commits and isinstance(commits[0], dict):
            sha = str(commits[0].get("sha", ""))[:7]
            if sha:
                cur["commit"] = sha
                msg = ((commits[0].get("commit") or {}).get("message") or "").splitlines()
                cur["commit_msg"] = (msg[0] if msg else "")[:80]

        if not cur:
            continue  # 该仓库全没抓到（私有/删库/限流）→ 跳过，别覆盖旧快照
        result["new_state"][repo] = cur

        old = prev.get(repo) or {}
        rel_changed = cur.get("release") and cur.get("release") != old.get("release")
        sha_changed = cur.get("commit") and cur.get("commit") != old.get("commit")
        if not prev or rel_changed or sha_changed:  # 首跑全报，否则只报变化
            result["changed"].append({"repo": repo, **cur})

    # 保留上次快照里这次没抓到的仓库（避免限流时快照被抹）
    for repo, val in prev.items():
        result["new_state"].setdefault(repo, val)

    return result


# ─────────────────────── 报告渲染 ───────────────────────
def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    line = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join(["---"] * len(headers)) + " |"
    body = "\n".join("| " + " | ".join(r) + " |" for r in rows)
    return "\n".join([line, sep, body])


def render_report(
    models: dict[str, Any],
    py: dict[str, Any],
    npm: dict[str, Any],
    upstream: dict[str, Any],
    *,
    date_str: str,
) -> str:
    """把四路结果渲染成 markdown 报告（每节空也写「(无更新)」）。绝不含任何密钥。"""
    lines: list[str] = [f"# 更新发现报告 · {date_str}", ""]
    lines.append("> 发现 ≠ 应用。以下仅为「上游有变动」的提示，是否采纳全凭机主一句话，脚本不自动改任何东西。")
    lines.append("")

    # ① 新模型
    lines.append("## ① 新模型（上游有、本地未接入）")
    any_new = False
    if not models.get("ok", True):
        lines.append(f"(探测失败：{models.get('note','')})")
    else:
        for c in models.get("connections", []):
            if c.get("error"):
                lines.append(f"- **{c['provider']}**：拉取失败（{c['error']}），跳过")
                continue
            nm = c.get("new_models") or []
            st = c.get("stale_models") or []
            if nm:
                any_new = True
                preview = ", ".join(nm[:20]) + (" …" if len(nm) > 20 else "")
                lines.append(f"- **{c['provider']}**（{len(nm)} 个新模型）：{preview}")
            if st:
                lines.append(
                    f"  - （另有 {len(st)} 个旧版本上游仍挂着：{', '.join(st[:10])}——"
                    "已接更新版，**可忽略**，接入=降级）"
                )
        if not any_new and not any(c.get("error") for c in models.get("connections", [])):
            note = models.get("note", "")
            lines.append("(无更新)" + (f"　{note}" if note else ""))
    lines.append("")

    # ② Python 依赖
    lines.append("## ② Python 依赖可升级")
    rows = py.get("outdated") or []
    if not py.get("ok", True):
        lines.append(f"(探测失败：{py.get('note','')})")
    elif rows:
        lines.append(_md_table(["包", "当前", "最新"], [[r["name"], r["current"], r["latest"]] for r in rows]))
        if py.get("note"):
            lines.append("")
            lines.append(f"_{py['note']}_")
    else:
        lines.append("(无更新)" + (f"　{py.get('note','')}" if py.get("note") else ""))
    lines.append("")

    # ③ npm 依赖
    lines.append("## ③ npm 依赖可升级（desktop）")
    nrows = npm.get("outdated") or []
    if not npm.get("ok", True):
        lines.append(f"(探测失败：{npm.get('note','')})")
    elif nrows:
        lines.append(
            _md_table(
                ["包", "当前", "wanted", "最新"],
                [[r["name"], r["current"], r.get("wanted", ""), r["latest"]] for r in nrows],
            )
        )
        if npm.get("note"):
            lines.append("")
            lines.append(f"_{npm['note']}_")
    else:
        lines.append("(无更新)" + (f"　{npm.get('note','')}" if npm.get("note") else ""))
    lines.append("")

    # ④ 上游动态
    lines.append("## ④ 上游项目动态（Fugu / OpenFugu / OpenManus / RouteLLM）")
    if not upstream.get("ok", True):
        lines.append(f"(探测失败：{upstream.get('note','')})")
    else:
        changed = upstream.get("changed") or []
        if changed:
            if upstream.get("first_run"):
                lines.append("_首次运行：以下为当前基线（已落快照，下次只报变化）_")
                lines.append("")
            for c in changed:
                bits = [f"**{c['repo']}**"]
                if c.get("release"):
                    bits.append(f"release `{c['release']}`")
                if c.get("commit"):
                    cm = f" — {c['commit_msg']}" if c.get("commit_msg") else ""
                    bits.append(f"commit `{c['commit']}`{cm}")
                lines.append("- " + "，".join(bits))
        else:
            lines.append("(无更新)")
    lines.append("")

    lines.append("---")
    lines.append("想应用哪项，把那一行复制给纳川里的我即可（例如「接入 xxx 模型」「升级 xxx 依赖」「看下 fugu 新 release」）。")
    lines.append("")
    return "\n".join(lines)


def _summary_for_feishu(
    models: dict[str, Any],
    py: dict[str, Any],
    npm: dict[str, Any],
    upstream: dict[str, Any],
    *,
    date_str: str,
) -> str:
    """飞书摘要：每节第一行，总 <500 字。"""

    def _first(section_title: str, body: str) -> str:
        return f"{section_title}：{body}"

    # ①
    new_total = sum(len(c.get("new_models") or []) for c in models.get("connections", []))
    s1 = f"{new_total} 个新模型待接入" if new_total else "无新模型"
    # ②
    s2 = f"{len(py.get('outdated') or [])} 个 Python 依赖可升级" if py.get("ok", True) else "探测失败"
    if py.get("ok", True) and not (py.get("outdated") or []):
        s2 = "Python 依赖全新"
    # ③
    s3 = f"{len(npm.get('outdated') or [])} 个 npm 依赖可升级" if npm.get("ok", True) else "探测失败"
    if npm.get("ok", True) and not (npm.get("outdated") or []):
        s3 = "npm 依赖全新"
    # ④
    ch = upstream.get("changed") or []
    if not upstream.get("ok", True):
        s4 = "探测失败/无 gh"
    else:
        s4 = f"{len(ch)} 个上游有动态（" + "、".join(c["repo"].split("/")[-1] for c in ch[:4]) + "）" if ch else "上游无动态"

    lines = [
        f"📡 更新发现 · {date_str}",
        _first("① 新模型", s1),
        _first("② Python 依赖", s2),
        _first("③ npm 依赖", s3),
        _first("④ 上游动态", s4),
        "详情见 data/update_report_%s.md，想应用哪项复制那一行给我。" % date_str.replace("-", ""),
    ]
    text = "\n".join(lines)
    return text[:500]


# ─────────────────────── 飞书推送 ───────────────────────
def push_feishu(summary: str) -> bool:
    """把摘要推给机主飞书（bot 发给机主自己）。凭证/UID 缺失→打印跳过；任何失败只警告不抛。"""
    try:
        from gateway.config import get_settings

        st = get_settings()
        app_id = (st.feishu_app_id or "").strip()
        app_secret = (st.feishu_app_secret or "").strip()
        owner = (st.feishu_owner_open_id or "").strip()
    except Exception as ex:  # noqa: BLE001
        _log(f"未配置飞书（读取配置失败：{ex}），跳过推送")
        return False

    if not (app_id and app_secret and owner):
        _log("未配置飞书（缺 app_id/app_secret/feishu_owner_open_id），跳过推送")
        return False

    base = "https://open.feishu.cn"
    try:
        with httpx.Client(timeout=15) as client:
            tk = client.post(
                f"{base}/open-apis/auth/v3/tenant_access_token/internal",
                json={"app_id": app_id, "app_secret": app_secret},
            )
            token = (tk.json() or {}).get("tenant_access_token", "")
            if not token:
                _log("飞书推送失败：拿不到 tenant_access_token（凭证或网络问题），跳过")
                return False
            r = client.post(
                f"{base}/open-apis/im/v1/messages",
                params={"receive_id_type": "open_id"},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={
                    "receive_id": owner,
                    "msg_type": "text",
                    "content": json.dumps({"text": summary}),
                },
            )
            code = (r.json() or {}).get("code", -1)
            if code == 0:
                _log("已推送报告摘要到机主飞书。")
                return True
            _log(f"飞书推送返回非 0（code={code}），报告已落盘不受影响。")
            return False
    except Exception as ex:  # noqa: BLE001
        _log(f"飞书推送异常（{type(ex).__name__}），报告已落盘不受影响。")
        return False


# ─────────────────────────── 主流程 ───────────────────────────
def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="自动更新发现（发现≠应用；不自动改代码）")
    parser.add_argument("--feishu", action="store_true", help="额外把报告摘要推给机主飞书")
    parser.add_argument("--json", action="store_true", dest="as_json", help="输出机器可读 JSON")
    parser.add_argument("--dry", action="store_true", help="不发任何网络请求（探测器返回占位）")
    args = parser.parse_args(argv)

    date_str = datetime.now().strftime("%Y-%m-%d")
    ymd = datetime.now().strftime("%Y%m%d")

    # 四探测器各自独立：任一异常都被自身 try/except 收敛，绝不影响其它 + 报告仍生成
    state = _load_json(STATE_PATH) or {}

    models = _safe(probe_new_models, dry=args.dry)
    py = _safe(probe_python_deps, dry=args.dry)
    npm = _safe(probe_npm_deps, dry=args.dry)
    upstream = _safe(lambda **kw: probe_upstream(state=state, **kw), dry=args.dry)

    # 落上游快照（仅当探测成功且拿到内容）
    if upstream.get("ok") and upstream.get("new_state") and not args.dry:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            STATE_PATH.write_text(
                json.dumps(upstream["new_state"], ensure_ascii=False, indent=2), "utf-8"
            )
        except Exception as ex:  # noqa: BLE001
            _log(f"[快照] 写 watch_state.json 失败（不影响报告）：{ex}")

    report = render_report(models, py, npm, upstream, date_str=date_str)

    # 落报告
    report_path = DATA_DIR / f"update_report_{ymd}.md"
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, "utf-8")
    except Exception as ex:  # noqa: BLE001
        _log(f"[报告] 落盘失败：{ex}")

    if args.as_json:
        payload = {
            "date": date_str,
            "report_path": str(report_path),
            "models": models,
            "python_deps": py,
            "npm_deps": npm,
            "upstream": upstream,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(report)
        _log(f"\n[报告已落盘] {report_path}")

    if args.feishu:
        summary = _summary_for_feishu(models, py, npm, upstream, date_str=date_str)
        push_feishu(summary)

    return 0


def _safe(fn: Any, **kwargs: Any) -> dict[str, Any]:
    """探测器兜底壳：把任何未捕获异常收敛成 {ok:False,note:...}，保证一个挂了其它照跑。"""
    try:
        return fn(**kwargs)
    except Exception as ex:  # noqa: BLE001
        return {"ok": False, "note": f"探测器异常 {type(ex).__name__}: {ex}"}


if __name__ == "__main__":
    raise SystemExit(run())
