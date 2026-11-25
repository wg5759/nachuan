"""P3 后端编码控制面核心引擎（Worktree 并行调度 + 可视化 Diff + 单文件 Revert / 本地 Commit + Plan/Build 审批执行闸）。

安全铁律：
1. 全部 git / 开发命令子进程严格使用参数列表且 ``shell=False``，Windows 强制
   ``creationflags=0x08000000``（CREATE_NO_WINDOW），杜绝 CMD 弹窗与命令注入。
2. 全部 git 调用强制附加 ``-c core.hooksPath=<NUL|/dev/null> -c core.fsmonitor=false -c core.pager=cat``
   及 ``GIT_TERMINAL_PROMPT=0``，防止恶意仓库 Git Hook RCE 或卡死终端。
3. 严禁移除主仓库工作树；严禁任何 ``git push``；严禁路径穿越、符号链接逃逸与操作 ``.git`` 目录。
4. Plan 模式仅放行严格只读白名单；Build 模式强制接入纳川 ``ApprovalStore``，审批凭证与
   ``worktree_path`` + ``command`` 原子绑定并单次消费，防篡改与防重放。
"""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import shlex
import shutil
import subprocess
import sys
from typing import Any

from orchestrator.approval import (
    catastrophic_command,
    is_protected_path,
    reads_secret,
)

# ── 常量与限制 ────────────────────────────────────────────────────────────────

MANAGED_WORKTREE_DIRNAME = ".nachuan-worktrees"
MANAGED_BRANCH_PREFIX = "nachuan/"
APPROVAL_SCOPE = "workspace_exec_plan"
DEFAULT_APPROVAL_USER_ID = "owner"

_MAX_UNTRACKED_PREVIEW_BYTES = 64 * 1024
_MAX_DIFF_BYTES_PER_FILE = 120 * 1024
_MAX_EXEC_OUTPUT_CHARS = 32 * 1024
_DEFAULT_GIT_TIMEOUT_SEC = 30.0
_DEFAULT_PLAN_TIMEOUT_SEC = 30.0
_DEFAULT_BUILD_TIMEOUT_SEC = 60.0

_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9._/@^~][A-Za-z0-9._/@^~-]{0,255}$")

# 无论 Plan 还是 Build 模式一律阻断的危险/注入模式
_BLOCKED_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell_chain_or_redirect", re.compile(r"(?:&&|\|\||[;|`<>]|\$\()")),
    ("destructive_rm", re.compile(r"\brm\b[^\n]*-[a-z]*[rf][a-z]*[^\n]*(?:/|~|\*|\.\.|[A-Za-z]:\\)", re.I)),
    ("windows_forced_del", re.compile(r"\bdel\b[^\n]*/[fsq]\b", re.I)),
    ("windows_rmdir_recursive", re.compile(r"\b(?:rmdir|rd)\b[^\n]*/s\b", re.I)),
    ("disk_format_or_wipe", re.compile(r"\b(?:format|mkfs|diskpart|dd\s+if=|dd\s+[^\n]*of=/dev/)", re.I)),
    ("windows_acl_or_owner", re.compile(r"\b(?:icacls|takeown|setintegritylevel)\b", re.I)),
    ("remote_pipe_shell", re.compile(r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n]*\|\s*(?:ba|z|k|c)?sh\b", re.I)),
    ("encoded_powershell", re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*-(?:e|enc|encodedcommand)\b", re.I)),
    ("powershell_iex", re.compile(r"\b(?:invoke-expression|iex)\b", re.I)),
    ("power_control", re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b", re.I)),
    ("registry_delete", re.compile(r"\breg\s+delete\b", re.I)),
    ("external_cli_credentials", re.compile(r"(?:\.claude\.json|\.codex[/\\]+auth\.json|\.ssh[/\\]+id_|\.aws[/\\]+credentials)", re.I)),
    ("remote_git_push", re.compile(r"\bgit\b[^\n]*\bpush\b", re.I)),
)

# Plan 模式允许的 git 只读子命令
_PLAN_GIT_READONLY_SUBCOMMANDS = frozenset(
    {
        "status",
        "diff",
        "log",
        "branch",
        "show",
        "rev-parse",
        "ls-files",
        "grep",
        "shortlog",
        "describe",
        "tag",
    }
)

# git branch / tag 的危险写参数（Plan 模式严禁）
_PLAN_GIT_BRANCH_WRITE_FLAGS = frozenset(
    {
        "-d",
        "-D",
        "-m",
        "-M",
        "-c",
        "-C",
        "-f",
        "--delete",
        "--move",
        "--copy",
        "--force",
        "--edit-description",
        "--set-upstream-to",
        "--unset-upstream",
        "--track",
        "--create-reflog",
    }
)
_PLAN_GIT_BRANCH_READ_FLAGS = frozenset(
    {
        "-a",
        "--all",
        "-r",
        "--remotes",
        "-v",
        "-vv",
        "--verbose",
        "-l",
        "--list",
        "--show-current",
        "--no-color",
        "--color=never",
        "--merged",
        "--no-merged",
        "--contains",
        "--no-contains",
    }
)
_PLAN_GIT_TAG_WRITE_FLAGS = frozenset(
    {"-a", "-s", "-u", "-f", "-d", "-m", "-F", "--annotate", "--sign", "--delete", "--force"}
)

# Plan 模式允许的只读文件/检索命令
_PLAN_READONLY_TOOLS = frozenset(
    {"rg", "grep", "findstr", "ls", "dir", "pwd", "cat", "head", "tail", "wc"}
)

# Build 模式允许执行的开发类可执行程序白名单
_BUILD_ALLOWED_COMMANDS = frozenset(
    {
        "git",
        "pytest",
        "python",
        "python3",
        "py",
        "npm",
        "npx",
        "node",
        "uv",
        "cargo",
        "go",
        "ruff",
        "mypy",
        "pip",
        "pnpm",
        "yarn",
        "tsc",
        "vitest",
        "eslint",
        "prettier",
        "make",
        "cmake",
        "dotnet",
    }
)


# ── 异常定义 ──────────────────────────────────────────────────────────────────


class WorkspaceControlError(ValueError):
    """工作区控制面请求参数或 Git 状态错误（路由层映射为 HTTP 400）。"""


class WorkspaceSecurityError(PermissionError):
    """工作区控制面安全门禁拦截（路径穿越、审批失效/篡改等，路由层映射为 HTTP 403）。"""


# ── 内部工具函数 ──────────────────────────────────────────────────────────────


def _win_no_window_kwargs() -> dict[str, Any]:
    """Windows 下强制静默无窗口运行子进程。"""
    return {"creationflags": 0x08000000} if os.name == "nt" else {}


def _norm_path(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(str(path)))


def _is_subpath(child: Path, parent: Path) -> bool:
    """判断 child 是否严格位于 parent 目录之下（不等于 parent 本身）。"""
    try:
        c = _norm_path(child)
        p = _norm_path(parent)
        return os.path.commonpath([c, p]) == p and c != p
    except (OSError, ValueError):
        return False


def _is_within_or_equal(child: Path, parent: Path) -> bool:
    """判断 child 是否位于 parent 目录内或等于 parent。"""
    try:
        c = _norm_path(child)
        p = _norm_path(parent)
        return os.path.commonpath([c, p]) == p
    except (OSError, ValueError):
        return False


def _safe_git_prefix() -> list[str]:
    null_hooks = "NUL" if os.name == "nt" else "/dev/null"
    return [
        "git",
        "-c",
        f"core.hooksPath={null_hooks}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.pager=cat",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "core.quotepath=false",
    ]


def _run_git(
    cwd: Path,
    args: list[str],
    *,
    timeout: float = _DEFAULT_GIT_TIMEOUT_SEC,
    check: bool = True,
    extra_config: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = _safe_git_prefix()
    if extra_config:
        cmd.extend(extra_config)
    cmd.extend(args)
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        res = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            env=env,
            **_win_no_window_kwargs(),
        )
    except FileNotFoundError as exc:
        raise WorkspaceControlError("未找到 git 可执行文件，请先安装 Git") from exc
    except subprocess.TimeoutExpired as exc:
        raise WorkspaceControlError(f"git 命令执行超时（>{timeout:.0f}s）") from exc
    if check and res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip()[:500]
        raise WorkspaceControlError(f"git {' '.join(args[:3])} 失败：{detail}")
    return res


def _require_existing_dir(raw_path: str, label: str = "路径") -> Path:
    text = (raw_path or "").strip()
    if not text or "\x00" in text:
        raise WorkspaceControlError(f"{label}不能为空")
    try:
        resolved = Path(text).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceControlError(f"{label}不存在或无法访问：{text}") from exc
    if not resolved.is_dir():
        raise WorkspaceControlError(f"{label}不是有效目录：{text}")
    return resolved


def _require_git_worktree(raw_path: str, label: str = "worktree_path") -> Path:
    resolved = _require_existing_dir(raw_path, label=label)
    probe = _run_git(resolved, ["rev-parse", "--is-inside-work-tree"], check=False)
    if probe.returncode != 0 or probe.stdout.strip().lower() != "true":
        raise WorkspaceControlError(f"{label} 不是有效的 Git 工作树：{resolved}")
    top = _run_git(resolved, ["rev-parse", "--show-toplevel"], check=False)
    if top.returncode != 0 or not top.stdout.strip():
        raise WorkspaceControlError(f"无法定位 Git 工作树根目录：{resolved}")
    return Path(top.stdout.strip()).resolve()


def _git_current_branch(wt_root: Path) -> str:
    sym = _run_git(wt_root, ["symbolic-ref", "--short", "HEAD"], check=False)
    if sym.returncode == 0 and sym.stdout.strip():
        return sym.stdout.strip()
    rev = _run_git(wt_root, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    if rev.returncode == 0 and rev.stdout.strip():
        return rev.stdout.strip()
    return ""


def _git_dirty_count(wt_root: Path) -> int:
    if not wt_root.is_dir():
        return 0
    res = _run_git(wt_root, ["status", "--porcelain=v1", "-z"], check=False)
    if res.returncode != 0 or not res.stdout:
        return 0
    return len(_parse_porcelain_z(res.stdout))


def _parse_porcelain_z(raw: str) -> list[tuple[str, str]]:
    """解析 `git status --porcelain=v1 -z` 输出，安全处理空格、中文路径与重命名条目。"""
    entries: list[tuple[str, str]] = []
    tokens = raw.split("\x00")
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        i += 1
        if not tok or len(tok) < 4:
            continue
        xy = tok[:2]
        path = tok[3:]
        # 重命名(R)/复制(C)在 -z 模式下紧跟一个 NUL 分隔的源路径，需跳过
        if ("R" in xy or "C" in xy) and i < n:
            i += 1
        if path:
            entries.append((xy, path))
    return entries


def _parse_worktree_porcelain(output: str) -> list[dict[str, Any]]:
    """解析 `git worktree list --porcelain` 输出为结构化块列表。"""
    blocks: list[dict[str, Any]] = []
    cur: dict[str, Any] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            if cur.get("path"):
                blocks.append(cur)
                cur = {}
            continue
        if line.startswith("worktree "):
            if cur.get("path"):
                blocks.append(cur)
                cur = {}
            cur["path"] = line[len("worktree ") :].strip()
        elif line.startswith("HEAD "):
            cur["head"] = line[len("HEAD ") :].strip()
        elif line.startswith("branch "):
            ref = line[len("branch ") :].strip()
            cur["branch"] = ref.removeprefix("refs/heads/")
        elif line == "detached":
            cur["detached"] = True
        elif line == "bare":
            cur["bare"] = True
        elif line == "locked" or line.startswith("locked "):
            cur["locked"] = True
    if cur.get("path"):
        blocks.append(cur)
    return blocks


def _slugify_task_name(task_name: str) -> str:
    """将 task_name 清洗为仅含 [a-z0-9-] 且绝不以 '-' 开头的安全 slug。"""
    raw = (task_name or "").strip().lower()
    cleaned = re.sub(r"[^a-z0-9-]+", "-", raw)
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    cleaned = cleaned[:36].strip("-")
    if not cleaned or cleaned.startswith("-"):
        return "task"
    return cleaned


def _validate_base_ref(main_root: Path, base_ref: str) -> str:
    ref = (base_ref or "").strip()
    if not ref or ref.startswith("-") or ".." in ref or "@{" in ref or "\x00" in ref:
        raise WorkspaceControlError(f"非法的 base_ref：{base_ref!r}")
    if not _SAFE_REF_RE.fullmatch(ref):
        raise WorkspaceControlError(f"base_ref 包含非法字符：{base_ref!r}")
    verify = _run_git(
        main_root,
        ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        check=False,
    )
    if verify.returncode != 0 or not verify.stdout.strip():
        raise WorkspaceControlError(f"base_ref 未指向有效提交：{ref}")
    return ref


def _ensure_local_git_exclude(main_root: Path, pattern: str = f"{MANAGED_WORKTREE_DIRNAME}/") -> None:
    """将托管 worktree 目录写入本地 `.git/info/exclude`，防止污染主仓库 git status。"""
    res = _run_git(main_root, ["rev-parse", "--git-common-dir"])
    raw_dir = res.stdout.strip()
    git_dir = Path(raw_dir)
    if not git_dir.is_absolute():
        git_dir = (main_root / git_dir).resolve()
    exclude_path = git_dir / "info" / "exclude"
    exclude_path.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if exclude_path.is_file():
        existing = exclude_path.read_text(encoding="utf-8", errors="replace")
    lines = {ln.strip() for ln in existing.splitlines()}
    bare = pattern.rstrip("/")
    if pattern in lines or bare in lines:
        return
    prefix = "" if (not existing or existing.endswith("\n")) else "\n"
    with exclude_path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{prefix}{pattern}\n")


def _resolve_worktree_rel_path(wt_root: Path, file_path: str) -> tuple[Path, str]:
    """严格校验目标文件相对路径，禁止路径穿越、绝对路径、符号链接逃逸与 `.git` 目录。"""
    if not isinstance(file_path, str):
        raise WorkspaceSecurityError("file_path 必须是字符串")
    raw = file_path.strip()
    if not raw or "\x00" in raw or "\r" in raw or "\n" in raw:
        raise WorkspaceSecurityError("非法的 file_path")
    # 拒绝任何绝对路径、盘符路径或 UNC 路径
    if (
        raw.startswith(("/", "\\"))
        or Path(raw).is_absolute()
        or bool(PureWindowsPath(raw).drive)
    ):
        raise WorkspaceSecurityError(f"禁止使用绝对路径：{file_path}")
    normalized_slash = raw.replace("\\", "/")
    parts = [p for p in normalized_slash.split("/") if p not in ("", ".")]
    if not parts:
        raise WorkspaceSecurityError("file_path 不能指向工作树根目录")
    if any(p == ".." for p in parts):
        raise WorkspaceSecurityError(f"安全拦截：禁止路径穿越（{file_path}）")
    if parts[0].lower() == ".git" or any(p.lower() == ".git" for p in parts):
        raise WorkspaceSecurityError("安全拦截：禁止操作 .git 内部目录")

    rel_posix = "/".join(parts)
    candidate = wt_root.joinpath(*parts)

    # 检查父目录链路与目标解析结果是否严格留在 wt_root 内
    if candidate.is_symlink():
        parent_resolved = candidate.parent.resolve(strict=False)
        if not _is_within_or_equal(parent_resolved, wt_root):
            raise WorkspaceSecurityError(f"安全拦截：符号链接父目录越界（{file_path}）")
    else:
        resolved = candidate.resolve(strict=False)
        if not _is_subpath(resolved, wt_root):
            raise WorkspaceSecurityError(f"安全拦截：解析路径越出工作树边界（{file_path}）")

    return candidate, rel_posix


def _count_diff_stats(diff_text: str) -> tuple[int, int]:
    """统计 unified diff 中的新增行与删除行数。"""
    additions = 0
    deletions = 0
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        if line.startswith("diff --git "):
            in_hunk = False
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            additions += 1
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1
    return additions, deletions


def _truncate_diff_bytes(diff_text: str, limit_bytes: int = _MAX_DIFF_BYTES_PER_FILE) -> tuple[str, bool]:
    encoded = diff_text.encode("utf-8", errors="replace")
    if len(encoded) <= limit_bytes:
        return diff_text, False
    sliced = encoded[:limit_bytes].decode("utf-8", errors="ignore")
    return f"{sliced}\n... [diff truncated at {limit_bytes // 1024}KB]\n", True


def _build_untracked_file_diff(wt_root: Path, rel_path: str) -> tuple[str, int, int, bool]:
    """为未跟踪文件读取前 64KB 生成标准 unified diff；二进制文件安全标注。"""
    candidate, rel_posix = _resolve_worktree_rel_path(wt_root, rel_path)
    if not candidate.exists() or candidate.is_dir():
        return "", 0, 0, False
    if candidate.is_symlink():
        target_str = os.readlink(candidate)
        diff = (
            f"diff --git a/{rel_posix} b/{rel_posix}\n"
            f"new file mode 120000\n"
            f"--- /dev/null\n"
            f"+++ b/{rel_posix}\n"
            f"@@ -0,0 +1,1 @@\n"
            f"+{target_str}\n"
        )
        return diff, 1, 0, False

    try:
        with candidate.open("rb") as fh:
            raw = fh.read(_MAX_UNTRACKED_PREVIEW_BYTES + 1)
    except OSError:
        return "", 0, 0, False

    truncated = len(raw) > _MAX_UNTRACKED_PREVIEW_BYTES
    if truncated:
        raw = raw[:_MAX_UNTRACKED_PREVIEW_BYTES]

    if b"\x00" in raw[:8192]:
        diff = (
            f"diff --git a/{rel_posix} b/{rel_posix}\n"
            f"new file mode 100644\n"
            f"Binary file {rel_posix} differs\n"
        )
        return diff, 0, 0, False

    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    header = [
        f"diff --git a/{rel_posix} b/{rel_posix}",
        "new file mode 100644",
        "--- /dev/null",
        f"+++ b/{rel_posix}",
    ]
    if lines:
        header.append(f"@@ -0,0 +1,{len(lines)} @@")
        diff_body = "\n".join(header + [f"+{ln}" for ln in lines]) + "\n"
    else:
        diff_body = "\n".join(header) + "\n"

    diff_body, diff_truncated = _truncate_diff_bytes(diff_body)
    return diff_body, len(lines), 0, bool(truncated or diff_truncated)


# ── 核心 API 1~6：Worktree / Diff / Revert / Commit ──────────────────────────


def list_worktrees(repo_path: str) -> dict[str, Any]:
    """列出指定仓库的全部 Git Worktree 及脏文件统计；非 Git 目录优雅降级返回。"""
    resolved = _require_existing_dir(repo_path, label="repo_path")
    top = _run_git(resolved, ["rev-parse", "--show-toplevel"], check=False)
    if top.returncode != 0 or not top.stdout.strip():
        return {
            "repo_root": str(resolved),
            "is_git_repo": False,
            "current_branch": "",
            "worktrees": [],
        }

    queried_root = Path(top.stdout.strip()).resolve()
    current_branch = _git_current_branch(queried_root)

    wt_list_res = _run_git(queried_root, ["worktree", "list", "--porcelain"])
    blocks = _parse_worktree_porcelain(wt_list_res.stdout)
    if not blocks:
        # 极端情况（如刚 init 无 worktree 记录）保底返回主目录
        blocks = [{"path": str(queried_root), "branch": current_branch, "head": ""}]

    main_root = Path(blocks[0]["path"]).resolve()
    managed_dir = main_root / MANAGED_WORKTREE_DIRNAME

    worktrees: list[dict[str, Any]] = []
    for idx, block in enumerate(blocks):
        wt_path = Path(block["path"]).resolve()
        is_main = idx == 0
        branch = str(block.get("branch") or "")
        if not branch:
            if block.get("detached"):
                branch = "HEAD"
            else:
                branch = _git_current_branch(wt_path)
        is_managed = (not is_main) and (
            _is_subpath(wt_path, managed_dir) or branch.startswith(MANAGED_BRANCH_PREFIX)
        )
        dirty_files = 0 if block.get("bare") else _git_dirty_count(wt_path)
        worktrees.append(
            {
                "path": str(wt_path),
                "branch": branch,
                "head": str(block.get("head") or ""),
                "is_main": is_main,
                "is_managed": is_managed,
                "dirty_files": dirty_files,
                "locked": bool(block.get("locked", False)),
            }
        )

    return {
        "repo_root": str(main_root),
        "is_git_repo": True,
        "current_branch": current_branch,
        "worktrees": worktrees,
    }


def create_worktree(
    repo_path: str,
    task_name: str,
    base_ref: str | None = None,
) -> dict[str, Any]:
    """创建隔离托管 Worktree 及 `nachuan/<slug>-<shortid>` 分支，自动写入本地 exclude 防污染。"""
    listed = list_worktrees(repo_path)
    if not listed["is_git_repo"]:
        raise WorkspaceControlError(f"目标目录不是 Git 仓库：{listed['repo_root']}")
    main_root = Path(listed["repo_root"]).resolve()

    validated_ref: str | None = None
    if base_ref is not None and str(base_ref).strip():
        validated_ref = _validate_base_ref(main_root, str(base_ref))
    else:
        head_ok = _run_git(
            main_root,
            ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
            check=False,
        )
        if head_ok.returncode != 0:
            raise WorkspaceControlError("仓库尚无任何提交（HEAD 不存在），请先创建初始提交")

    slug = _slugify_task_name(task_name)
    short_id = secrets.token_hex(3)
    folder_name = f"{slug}-{short_id}"
    branch_name = f"{MANAGED_BRANCH_PREFIX}{folder_name}"

    # 先写入本地 .git/info/exclude，确保主仓库 git status 零污染
    _ensure_local_git_exclude(main_root, f"{MANAGED_WORKTREE_DIRNAME}/")

    managed_root = main_root / MANAGED_WORKTREE_DIRNAME
    managed_root.mkdir(parents=True, exist_ok=True)
    target_path = (managed_root / folder_name).resolve()
    if not _is_subpath(target_path, managed_root):
        raise WorkspaceSecurityError("安全拦截：目标 Worktree 路径越出托管目录")

    add_args = ["worktree", "add", "-b", branch_name, str(target_path)]
    if validated_ref:
        add_args.append(validated_ref)
    _run_git(main_root, add_args)

    refreshed = list_worktrees(str(main_root))
    target_norm = _norm_path(target_path)
    for item in refreshed["worktrees"]:
        if _norm_path(item["path"]) == target_norm:
            return {"ok": True, "worktree": item}

    head_sha = _run_git(target_path, ["rev-parse", "HEAD"], check=False).stdout.strip()
    return {
        "ok": True,
        "worktree": {
            "path": str(target_path),
            "branch": branch_name,
            "head": head_sha,
            "is_main": False,
            "is_managed": True,
            "dirty_files": 0,
            "locked": False,
        },
    }


def remove_worktree(
    repo_path: str,
    worktree_path: str,
    force: bool = False,
    delete_branch: bool = False,
) -> dict[str, Any]:
    """安全移除纳川托管 Worktree；严禁移除主仓库或非托管工作树。"""
    listed = list_worktrees(repo_path)
    if not listed["is_git_repo"]:
        raise WorkspaceControlError(f"目标目录不是 Git 仓库：{listed['repo_root']}")
    main_root = Path(listed["repo_root"]).resolve()

    raw_wt = (worktree_path or "").strip()
    if not raw_wt or "\x00" in raw_wt:
        raise WorkspaceControlError("worktree_path 不能为空")

    target_norm = _norm_path(raw_wt)
    matched: dict[str, Any] | None = None
    for item in listed["worktrees"]:
        if _norm_path(item["path"]) == target_norm:
            matched = item
            break

    if matched is None:
        raise WorkspaceControlError(f"未找到对应的已注册 Worktree：{raw_wt}")
    if matched["is_main"]:
        raise WorkspaceControlError("安全拦截：严禁移除主仓库工作树")
    if not matched["is_managed"]:
        raise WorkspaceControlError("安全拦截：仅允许移除处于纳川托管范围内的 Worktree")

    target_str = str(matched["path"])
    if target_str.startswith("-"):
        raise WorkspaceSecurityError("非法的 Worktree 路径")

    rm_args = ["worktree", "remove"]
    if force:
        rm_args.append("--force")
    rm_args.append(target_str)
    _run_git(main_root, rm_args)
    _run_git(main_root, ["worktree", "prune"], check=False)

    branch_name = str(matched.get("branch") or "")
    if delete_branch and branch_name.startswith(MANAGED_BRANCH_PREFIX):
        flag = "-D" if force else "-d"
        del_res = _run_git(main_root, ["branch", flag, "--", branch_name], check=False)
        if del_res.returncode != 0 and not force:
            stderr_low = (del_res.stderr or "").lower()
            if "not fully merged" in stderr_low:
                _run_git(main_root, ["branch", "-D", "--", branch_name], check=True)
            elif "not found" not in stderr_low:
                raise WorkspaceControlError(
                    f"Worktree 已移除，但删除托管分支失败：{(del_res.stderr or '').strip()[:300]}"
                )

    return {"ok": True, "removed": target_str}


def get_workspace_diff(worktree_path: str, staged: bool = False) -> dict[str, Any]:
    """收集工作树的文件变更、增删行数统计与标准 Unified Diff（单文件上限 120KB）。"""
    wt_root = _require_git_worktree(worktree_path, label="worktree_path")
    branch = _git_current_branch(wt_root)
    has_head = (
        _run_git(wt_root, ["rev-parse", "--verify", "--quiet", "HEAD"], check=False).returncode == 0
    )

    status_res = _run_git(wt_root, ["status", "--porcelain=v1", "-z", "-uall"])
    entries = _parse_porcelain_z(status_res.stdout)

    files: list[dict[str, Any]] = []
    for xy, rel_path in entries:
        x, y = xy[0], xy[1]
        if staged:
            if x in (" ", "?"):
                continue
            file_status = x
            diff_res = _run_git(wt_root, ["diff", "--cached", "--no-color", "--", rel_path])
            raw_diff = diff_res.stdout
            additions, deletions = _count_diff_stats(raw_diff)
            diff_text, truncated = _truncate_diff_bytes(raw_diff)
            files.append(
                {
                    "path": rel_path,
                    "status": file_status,
                    "additions": additions,
                    "deletions": deletions,
                    "diff": diff_text,
                    "truncated": truncated,
                }
            )
            continue

        # 未跟踪新文件
        if xy == "??":
            diff_text, additions, deletions, truncated = _build_untracked_file_diff(wt_root, rel_path)
            files.append(
                {
                    "path": rel_path,
                    "status": "?",
                    "additions": additions,
                    "deletions": deletions,
                    "diff": diff_text,
                    "truncated": truncated,
                }
            )
            continue

        file_status = y if y != " " else x
        if has_head:
            diff_res = _run_git(wt_root, ["diff", "HEAD", "--no-color", "--", rel_path])
            raw_diff = diff_res.stdout
        else:
            diff_res = _run_git(wt_root, ["diff", "--no-color", "--", rel_path])
            raw_diff = diff_res.stdout
            if not raw_diff:
                raw_diff = _run_git(
                    wt_root, ["diff", "--cached", "--no-color", "--", rel_path]
                ).stdout

        additions, deletions = _count_diff_stats(raw_diff)
        diff_text, truncated = _truncate_diff_bytes(raw_diff)
        files.append(
            {
                "path": rel_path,
                "status": file_status,
                "additions": additions,
                "deletions": deletions,
                "diff": diff_text,
                "truncated": truncated,
            }
        )

    total_additions = sum(item["additions"] for item in files)
    total_deletions = sum(item["deletions"] for item in files)
    return {
        "worktree_path": str(wt_root),
        "branch": branch,
        "summary": {
            "total_files": len(files),
            "additions": total_additions,
            "deletions": total_deletions,
        },
        "files": files,
    }


def revert_workspace_file(worktree_path: str, file_path: str) -> dict[str, Any]:
    """单文件撤销变更：严格防路径穿越，未跟踪文件安全删除，已跟踪文件取消暂存并还原。"""
    wt_root = _require_git_worktree(worktree_path, label="worktree_path")
    candidate, rel_posix = _resolve_worktree_rel_path(wt_root, file_path)

    tracked = (
        _run_git(
            wt_root,
            ["ls-files", "--error-unmatch", "--", rel_posix],
            check=False,
        ).returncode
        == 0
    )

    if not tracked:
        if not candidate.exists() and not candidate.is_symlink():
            raise WorkspaceControlError(f"未找到待撤销的文件：{rel_posix}")
        if candidate.is_dir() and not candidate.is_symlink():
            raise WorkspaceControlError(f"目标为目录，不支持单文件撤销：{rel_posix}")
        try:
            candidate.unlink()
        except OSError as exc:
            raise WorkspaceControlError(f"删除未跟踪文件失败：{exc}") from exc
        return {"ok": True, "file_path": rel_posix}

    in_head = (
        _run_git(
            wt_root,
            ["cat-file", "-e", f"HEAD:{rel_posix}"],
            check=False,
        ).returncode
        == 0
    )
    if in_head:
        _run_git(wt_root, ["reset", "-q", "HEAD", "--", rel_posix])
        _run_git(wt_root, ["checkout", "--", rel_posix])
    else:
        # 仅在暂存区的新文件（HEAD 中尚不存在）
        _run_git(wt_root, ["rm", "--cached", "-q", "-f", "--", rel_posix])
        if candidate.exists() or candidate.is_symlink():
            if candidate.is_dir() and not candidate.is_symlink():
                raise WorkspaceControlError(f"目标为目录，无法删除：{rel_posix}")
            candidate.unlink()

    return {"ok": True, "file_path": rel_posix}


def commit_workspace(
    worktree_path: str,
    message: str,
    files: list[str] | None = None,
) -> dict[str, Any]:
    """执行本地 Git Commit（严禁执行 git push），支持全量或指定文件提交。"""
    wt_root = _require_git_worktree(worktree_path, label="worktree_path")
    commit_msg = (message or "").strip()
    if not commit_msg or "\x00" in commit_msg:
        raise WorkspaceControlError("提交说明 message 不能为空")
    if len(commit_msg) > 16_384:
        raise WorkspaceControlError("提交说明超过长度限制（16384 字符）")

    rel_files: list[str] = []
    if files is not None:
        if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
            raise WorkspaceControlError("files 必须是字符串数组")
        if len(files) > 0:
            for f in files:
                _, rel_posix = _resolve_worktree_rel_path(wt_root, f)
                rel_files.append(rel_posix)

    if rel_files:
        _run_git(wt_root, ["add", "--", *rel_files])
        staged_probe = _run_git(
            wt_root, ["diff", "--cached", "--name-only", "-z", "--", *rel_files]
        )
    else:
        _run_git(wt_root, ["add", "-A"])
        staged_probe = _run_git(wt_root, ["diff", "--cached", "--name-only", "-z"])

    staged_files = [item for item in staged_probe.stdout.split("\x00") if item]
    if not staged_files:
        raise WorkspaceControlError("没有可提交的已暂存变更")

    # 仅在仓库与全局均未配置 Git 作者身份时提供安全本地兜底
    extra_cfg: list[str] = []
    if not _run_git(wt_root, ["config", "--get", "user.name"], check=False).stdout.strip():
        extra_cfg.extend(["-c", "user.name=Nachuan"])
    if not _run_git(wt_root, ["config", "--get", "user.email"], check=False).stdout.strip():
        extra_cfg.extend(["-c", "user.email=nachuan@local"])

    commit_args = ["commit", "-m", commit_msg]
    if rel_files:
        commit_args.extend(["--", *rel_files])
    _run_git(wt_root, commit_args, extra_config=extra_cfg)

    sha = _run_git(wt_root, ["rev-parse", "HEAD"]).stdout.strip()
    branch = _git_current_branch(wt_root)
    return {
        "ok": True,
        "commit_sha": sha,
        "branch": branch,
        "files_committed": len(staged_files),
    }


# ── 核心 API 7：Plan / Build 受控审批执行闸 ───────────────────────────────────


def _split_command_argv(command: str) -> list[str]:
    """兼容 Windows 路径的命令分词器，不丢失反斜杠且正确剥离成对引号。"""
    tokens = shlex.split(command, posix=(os.name != "nt"))
    if os.name != "nt":
        return tokens
    cleaned: list[str] = []
    for tok in tokens:
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
            inner = tok[1:-1]
            if tok[0] == '"':
                inner = inner.replace('\\"', '"')
            cleaned.append(inner)
        else:
            cleaned.append(tok)
    return cleaned


def _detect_dangerous_command(command: str, argv: list[str], wt_root: Path) -> str:
    """检测高危毁灭命令、注入链、敏感凭据访问或路径逃逸；命中返回中文原因，安全返回空串。"""
    if "\r" in command or "\n" in command or "\x00" in command:
        return "命令包含非法换行或控制字符"
    cat_reason = catastrophic_command(command)
    if cat_reason:
        return f"高危毁灭性命令拦截：{cat_reason}"
    secret_reason = reads_secret(command)
    if secret_reason:
        return f"高危凭据读取拦截：{secret_reason}"
    for label, pattern in _BLOCKED_COMMAND_PATTERNS:
        if pattern.search(command):
            return f"高危命令/注入模式拦截（{label}）"

    for tok in argv[1:]:
        norm_tok = tok.replace("\\", "/")
        # 检查显式目录逃逸段 ..
        if (
            norm_tok == ".."
            or norm_tok.startswith("../")
            or norm_tok.endswith("/..")
            or "/../" in norm_tok
        ):
            return f"高危路径逃逸拦截：参数含上级目录跳转（{tok}）"
        # 检查绝对路径参数是否越出当前 worktree
        looks_abs = bool(PureWindowsPath(tok).drive) or (
            os.name != "nt" and tok.startswith("/") and not tok.startswith("//")
        )
        if looks_abs:
            try:
                resolved_tok = Path(tok).resolve(strict=False)
            except (OSError, RuntimeError):
                return f"无法解析的绝对路径参数：{tok}"
            if not _is_within_or_equal(resolved_tok, wt_root):
                return f"高危路径逃逸拦截：绝对路径越出 Worktree（{tok}）"
        # 若相对路径文件存在且命中受保护凭据路径
        if not tok.startswith("-"):
            probe = (wt_root / tok) if not looks_abs else Path(tok)
            prot = is_protected_path(str(probe))
            if prot:
                return f"高危凭据路径拦截：{prot}（{tok}）"
    return ""


def _base_prog_name(token: str) -> str:
    name = Path(token).name.lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


def _is_plan_readonly_command(argv: list[str]) -> tuple[bool, str]:
    """校验命令是否严格属于 Plan 模式只读探索白名单。"""
    if not argv:
        return False, "命令为空"
    prog = _base_prog_name(argv[0])
    rest = argv[1:]

    if prog == "git":
        if not rest:
            return False, "git 命令缺少只读子命令"
        # 禁止用户通过 -c / --config-env / -C 篡改 git 配置或切出目录
        if rest[0].startswith("-"):
            return False, "Plan 模式禁止为 git 附加全局覆写选项"
        sub = rest[0].lower()
        sub_args = rest[1:]
        if sub not in _PLAN_GIT_READONLY_SUBCOMMANDS:
            return False, f"Plan 模式仅允许 git 只读子命令，拒绝 `git {sub}`"
        if sub == "branch":
            for arg in sub_args:
                if arg in _PLAN_GIT_BRANCH_WRITE_FLAGS:
                    return False, f"Plan 模式禁止写分支选项：{arg}"
                if not arg.startswith("-"):
                    return False, "Plan 模式禁止创建或修改分支，请切至 Build 模式"
                if arg not in _PLAN_GIT_BRANCH_READ_FLAGS and not arg.startswith("--sort="):
                    return False, f"Plan 模式拒绝未知 git branch 参数：{arg}"
        if sub == "tag":
            for arg in sub_args:
                if arg in _PLAN_GIT_TAG_WRITE_FLAGS or not arg.startswith("-"):
                    return False, "Plan 模式禁止创建或删除标签"
        return True, ""

    if prog in {"python", "python3", "py"}:
        # 仅放行 --version / -V 或 `-m pytest --collect-only`
        trimmed = list(rest)
        if prog == "py" and trimmed and re.fullmatch(r"-3(?:\.\d+)?", trimmed[0]):
            trimmed = trimmed[1:]
        if trimmed in (["--version"], ["-V"]):
            return True, ""
        if (
            len(trimmed) >= 3
            and trimmed[0] == "-m"
            and trimmed[1] == "pytest"
            and any(flag in {"--collect-only", "--co"} for flag in trimmed[2:])
        ):
            return True, ""
        return False, "Plan 模式仅允许 python 执行 `pytest --collect-only` 只读收集"

    if prog == "pytest":
        if any(flag in {"--collect-only", "--co", "--version"} for flag in rest):
            return True, ""
        return False, "Plan 模式仅允许 `pytest --collect-only`，运行测试请切至 Build 模式"

    if prog in _PLAN_READONLY_TOOLS:
        # 防止 rg --pre 触发外部命令执行
        if prog == "rg" and any(a == "--pre" or a.startswith("--pre=") for a in rest):
            return False, "Plan 模式禁止 rg --pre 执行外部程序"
        return True, ""

    return False, f"Plan 模式仅允许只读探索命令，拒绝 `{prog}`；请切换至 Build 模式经审批后执行"


def _resolve_executable(prog_token: str) -> str | None:
    """将命令名解析为安全可执行文件路径（优先复用当前虚拟环境 Python / pytest）。"""
    prog = _base_prog_name(prog_token)
    if prog in {"python", "python3"}:
        return sys.executable
    if prog == "pytest":
        venv_pytest = Path(sys.executable).parent / ("pytest.exe" if os.name == "nt" else "pytest")
        if venv_pytest.is_file():
            return str(venv_pytest)
    found = shutil.which(prog_token)
    if found:
        return found
    if os.name == "nt":
        for ext in (".exe", ".cmd", ".bat"):
            found = shutil.which(prog + ext)
            if found:
                return found
    return None


def _run_builtin_readonly_tool(wt_root: Path, argv: list[str]) -> tuple[int, str, str] | None:
    """在 Windows 缺少 POSIX 只读工具（pwd/ls/dir/cat/head/tail/wc）时的安全纯 Python 只读兜底。"""
    prog = _base_prog_name(argv[0])
    args = argv[1:]

    if prog == "pwd":
        return 0, f"{wt_root}\n", ""

    if prog in {"ls", "dir"}:
        target = wt_root
        non_flags = [a for a in args if not a.startswith(("-", "/"))]
        if non_flags:
            candidate, _ = _resolve_worktree_rel_path(wt_root, non_flags[0])
            target = candidate
        if not target.exists():
            return 1, "", f"路径不存在：{target}"
        if target.is_file():
            return 0, f"{target.name}\n", ""
        names = sorted(p.name + ("/" if p.is_dir() else "") for p in target.iterdir())
        return 0, ("\n".join(names) + ("\n" if names else "")), ""

    if prog in {"cat", "head", "tail", "wc"}:
        line_limit = 10 if prog in {"head", "tail"} else None
        files: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if prog in {"head", "tail"} and a == "-n" and i + 1 < len(args):
                try:
                    line_limit = max(0, int(args[i + 1]))
                except ValueError:
                    return 2, "", f"无效行数参数：{args[i + 1]}"
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            files.append(a)
            i += 1
        if not files:
            return 2, "", f"{prog} 缺少目标文件参数"
        out_chunks: list[str] = []
        for rel in files:
            candidate, rel_posix = _resolve_worktree_rel_path(wt_root, rel)
            if not candidate.is_file():
                return 1, "", f"文件不存在：{rel_posix}"
            if is_protected_path(str(candidate)):
                return 1, "", f"拒绝读取受保护文件：{rel_posix}"
            text = candidate.read_text(encoding="utf-8", errors="replace")
            if prog == "cat":
                out_chunks.append(text)
            elif prog == "head":
                out_chunks.append("\n".join(text.splitlines()[:line_limit]) + "\n")
            elif prog == "tail":
                lines = text.splitlines()
                tail_lines = lines[-line_limit:] if line_limit else []
                out_chunks.append("\n".join(tail_lines) + ("\n" if tail_lines else ""))
            elif prog == "wc":
                lines_cnt = len(text.splitlines())
                words_cnt = len(text.split())
                bytes_cnt = len(text.encode("utf-8"))
                out_chunks.append(f"{lines_cnt} {words_cnt} {bytes_cnt} {rel_posix}\n")
        return 0, "".join(out_chunks), ""

    return None


def _execute_argv_safely(
    wt_root: Path,
    argv: list[str],
    *,
    timeout: float,
    allow_builtin_readonly: bool = False,
) -> tuple[int, str, str]:
    """在 cwd=wt_root、shell=False、无弹窗、有界输出与有界超时下执行白名单命令。"""
    prog = _base_prog_name(argv[0])
    if prog == "git":
        cmd = _safe_git_prefix() + argv[1:]
    else:
        exe = _resolve_executable(argv[0])
        if exe is None:
            if allow_builtin_readonly:
                builtin = _run_builtin_readonly_tool(wt_root, argv)
                if builtin is not None:
                    rc, out, err = builtin
                    return rc, out[:_MAX_EXEC_OUTPUT_CHARS], err[:_MAX_EXEC_OUTPUT_CHARS]
            raise WorkspaceControlError(f"未找到可执行命令：{argv[0]}")
        cmd = [exe, *argv[1:]]

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        res = subprocess.run(
            cmd,
            cwd=str(wt_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            env=env,
            **_win_no_window_kwargs(),
        )
    except subprocess.TimeoutExpired as exc:
        out_raw = exc.stdout if isinstance(exc.stdout, str) else ""
        err_raw = exc.stderr if isinstance(exc.stderr, str) else ""
        return (
            124,
            out_raw[:_MAX_EXEC_OUTPUT_CHARS],
            (err_raw + f"\n[命令执行超时 >{timeout:.0f}s]").strip()[:_MAX_EXEC_OUTPUT_CHARS],
        )

    return (
        int(res.returncode),
        (res.stdout or "")[:_MAX_EXEC_OUTPUT_CHARS],
        (res.stderr or "")[:_MAX_EXEC_OUTPUT_CHARS],
    )


def run_workspace_exec_plan(
    worktree_path: str,
    mode: str,
    command: str,
    approval_id: str | None,
    approval_store: Any,
    *,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Plan/Build 双模受控审批执行闸。

    - 危险命令 / 链式注入 / 路径逃逸 → 无论模式一律返回 ``status="blocked"`` (``risk_level="critical"``)
    - ``mode="plan"`` → 仅放行只读探索命令；非只读命令返回 ``status="blocked"`` 并提示切换至 ``build``
    - ``mode="build"`` → 未带 ``approval_id`` 时在 ``approval_store`` 建单返回 ``status="approval_required"``；
      带 ``approval_id`` 时原子核验状态已批准且与 ``worktree_path`` + ``command`` 精确绑定后单次消费执行。
    """
    wt_root = _require_git_worktree(worktree_path, label="worktree_path")
    norm_mode = (mode or "").strip().lower()
    if norm_mode not in {"plan", "build"}:
        raise WorkspaceControlError("mode 必须为 'plan' 或 'build'")

    cmd_str = (command or "").strip()
    if not cmd_str:
        raise WorkspaceControlError("command 不能为空")
    if len(cmd_str) > 8192:
        raise WorkspaceControlError("command 超过最大长度限制（8192 字符）")

    # 1. 先解析 argv 并执行高危/注入/路径逃逸拦截
    try:
        argv = _split_command_argv(cmd_str)
    except ValueError as exc:
        return {
            "status": "blocked",
            "mode": norm_mode,
            "command": cmd_str,
            "risk_level": "critical",
            "reason": f"命令语法解析失败（疑似未闭合引号或注入）：{exc}",
        }
    if not argv:
        raise WorkspaceControlError("command 解析为空")

    danger_reason = _detect_dangerous_command(cmd_str, argv, wt_root)
    if danger_reason:
        return {
            "status": "blocked",
            "mode": norm_mode,
            "command": cmd_str,
            "risk_level": "critical",
            "reason": danger_reason,
        }

    # 2. Plan 模式：严格只读探索白名单
    if norm_mode == "plan":
        ok_plan, plan_reason = _is_plan_readonly_command(argv)
        if not ok_plan:
            return {
                "status": "blocked",
                "mode": "plan",
                "command": cmd_str,
                "risk_level": "medium",
                "reason": plan_reason,
            }
        rc, stdout, stderr = _execute_argv_safely(
            wt_root,
            argv,
            timeout=timeout or _DEFAULT_PLAN_TIMEOUT_SEC,
            allow_builtin_readonly=True,
        )
        return {
            "status": "executed",
            "mode": "plan",
            "command": cmd_str,
            "exit_code": rc,
            "stdout": stdout,
            "stderr": stderr,
        }

    # 3. Build 模式：校验开发命令白名单 + 审批单绑定与单次原子消费
    prog = _base_prog_name(argv[0])
    if prog not in _BUILD_ALLOWED_COMMANDS:
        return {
            "status": "blocked",
            "mode": "build",
            "command": cmd_str,
            "risk_level": "high",
            "reason": f"Build 模式仅允许合法开发命令白名单，拒绝 `{prog}`",
        }
    if prog == "git" and len(argv) > 1 and argv[1].startswith("-"):
        return {
            "status": "blocked",
            "mode": "build",
            "command": cmd_str,
            "risk_level": "critical",
            "reason": "Build 模式禁止向 git 传入全局 `-c` 配置覆写参数",
        }

    if approval_store is None:
        raise WorkspaceControlError("审批存储未就绪，无法处理 Build 模式执行请求")

    bound_worktree = str(wt_root)
    manifest = {
        "worktree_path": bound_worktree,
        "command": cmd_str,
    }

    raw_aid = ("" if approval_id is None else str(approval_id)).strip()
    if not raw_aid:
        summary = f"[Worktree Build] {cmd_str}"[:80]
        payload = {
            "scope": APPROVAL_SCOPE,
            "task": cmd_str,
            "workdir": bound_worktree,
            "mode": "build",
            "worktree_path": bound_worktree,
            "command": cmd_str,
        }
        aid = approval_store.create(
            DEFAULT_APPROVAL_USER_ID,
            "action",
            summary,
            payload,
        )
        if not isinstance(aid, int) or aid <= 0:
            raise WorkspaceControlError("创建 Build 审批单失败")
        return {
            "status": "approval_required",
            "mode": "build",
            "command": cmd_str,
            "approval_id": str(aid),
            "risk_level": "medium",
            "reason": "Build command requires explicit user approval",
        }

    try:
        aid_int = int(raw_aid)
        if aid_int <= 0:
            raise ValueError("non-positive approval_id")
    except ValueError as exc:
        raise WorkspaceSecurityError("无效的审批凭证 approval_id") from exc

    claimed = approval_store.claim_action(
        aid_int,
        user_id=DEFAULT_APPROVAL_USER_ID,
        task=cmd_str,
        workdir=bound_worktree,
        scope=APPROVAL_SCOPE,
        mode="build",
        manifest=manifest,
    )
    if not claimed:
        raise WorkspaceSecurityError(
            "审批凭证不存在、未批准、已消费、已过期，或与当前 command / worktree_path 不匹配"
        )

    succeeded = False
    try:
        rc, stdout, stderr = _execute_argv_safely(
            wt_root,
            argv,
            timeout=timeout or _DEFAULT_BUILD_TIMEOUT_SEC,
            allow_builtin_readonly=False,
        )
        succeeded = rc == 0
    finally:
        approval_store.finish_action(aid_int, success=succeeded)

    return {
        "status": "executed",
        "mode": "build",
        "command": cmd_str,
        "approval_id": str(aid_int),
        "exit_code": rc,
        "stdout": stdout,
        "stderr": stderr,
    }
