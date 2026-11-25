"""P3 多 Git Worktree 并行编码控制面与 Plan/Build 受控审批沙箱。

设计目标（正面超越 T3 Code + 吸收 OpenCode Plan/Build 双模 + 纳川安全审批基因）：
1. 安全隔离的多 Worktree 并行开发：每个 Agent 任务拥有独立 Git 分支与隔离工作树，
   所有 git 调用强制附加 `-c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.pager=cat`
   并在 Windows 上强制 `CREATE_NO_WINDOW`，杜绝恶意仓库 Git Hook 执行与弹窗。
2. 结构化 Diff 审阅与精细采纳/回滚：实时返回逐文件状态、增删行数、Unified Diff，
   支持单文件回滚、单文件或全量采纳提交、安全销毁 Worktree 与分支。
3. Plan / Build 双模受控审批执行闸：
   - `plan` 模式严格只读（禁止写入与高危执行），适合方案设计与代码审查；
   - `build` 模式允许在 Worktree 内执行安全验证命令（pytest/vitest/tsc/git diff 等），
     写操作与非常规命令自动拦截并挂起为可跨端审批的 `PendingCommandApproval`，
     通过桌面端或手机 Web PWA / Telegram / Discord / Slack 一键 Approve 后再执行；
   - 致命高危命令（越界删盘、读 ~/.claude.json / ~/.codex/auth.json、icacls 等）永久硬拦截。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import threading
import time
from typing import Any

_MAX_DIFF_BYTES_PER_FILE = 64 * 1024
_MAX_CMD_OUTPUT_CHARS = 16_000
_DEFAULT_APPROVAL_TTL_SEC = 600
_SAFE_SESSION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$")
_VALID_MODES = frozenset({"plan", "build"})
_VALID_ENGINES = frozenset(
    {
        "codex",
        "claude-code",
        "opencode",
        "kimi-code",
        "local-ollama",
        "byok-cloud",
    }
)

# 无论 Plan 还是 Build 模式都永久拒绝的致命高危命令/敏感凭据读取模式
_FORBIDDEN_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("destructive_root_rm", re.compile(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\*|[A-Za-z]:\\)", re.I)),
    ("disk_format_or_dd", re.compile(r"\b(?:format|mkfs|diskpart|dd\s+if=)\b", re.I)),
    ("system_power_ctl", re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b", re.I)),
    ("windows_acl_tamper", re.compile(r"\b(?:icacls|takeown|setintegritylevel)\b", re.I)),
    ("pipe_shell_exec", re.compile(r"(?:curl|wget)[^|\n]+\|\s*(?:sh|bash|zsh|pwsh|powershell)", re.I)),
    ("encoded_powershell", re.compile(r"powershell(?:\.exe)?\s+.*-(?:e|enc|encodedcommand)\b", re.I)),
    ("external_cli_secret_access", re.compile(r"(?:\.claude\.json|\.codex[/\\]+auth\.json|\.ssh[/\\]+id_|\.aws[/\\]+credentials)", re.I)),
)

# 在 Build 模式下无需二次审批即可自动放行的纯验证/只读命令前缀
_SAFE_AUTO_EXEC_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("git", "status"),
    ("git", "diff"),
    ("git", "log"),
    ("git", "branch"),
    ("pytest",),
    ("python", "-m", "pytest"),
    ("py", "-3", "-m", "pytest"),
    ("npm", "test"),
    ("npm", "run", "test"),
    ("npm", "run", "typecheck"),
    ("npm", "run", "lint"),
    ("npx", "vitest", "run"),
    ("npx", "tsc", "--noEmit"),
    ("ruff", "check"),
    ("cargo", "test"),
    ("go", "test"),
)


class CodingStudioError(ValueError):
    """编码工作台基础异常。"""


class CodingSecurityError(PermissionError):
    """触发路径越界、重解析点、高危命令或 Plan 只读闸拦截时抛出。"""


def _subprocess_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    return kwargs


def _is_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junc = getattr(path, "is_junction", None)
        if is_junc and is_junc():
            return True
        attrs = int(getattr(os.lstat(path), "st_file_attributes", 0))
        return bool(attrs & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))
    except OSError:
        return False


def _ensure_within(target: Path, root: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved_target = target.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise CodingSecurityError(f"路径越出受控 Worktree 边界：{target}") from exc
    if target.exists() and _is_reparse(target):
        raise CodingSecurityError(f"拒绝访问符号链接或重解析点：{target}")
    return resolved_target


def _safe_git(
    cwd: Path,
    args: list[str],
    *,
    timeout: float = 30.0,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """以禁用 Git Hooks / fsmonitor / pager 的安全模式调用 git。"""
    null_hooks = "NUL" if os.name == "nt" else "/dev/null"
    cmd = [
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
        *args,
    ]
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    res = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        **_subprocess_kwargs(),
    )
    if check and res.returncode != 0:
        detail = (res.stderr or res.stdout or "").strip()[:500]
        raise CodingStudioError(f"git {' '.join(args[:3])} 失败：{detail}")
    return res


def _slugify_branch(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip().lower()).strip("-._")
    return (cleaned or "task")[:36]


@dataclass
class WorktreeSession:
    session_id: str
    title: str
    repo_path: str
    worktree_path: str
    branch: str
    base_ref: str
    mode: str = "plan"
    agent_engine: str = "codex"
    status: str = "active"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PendingCommandApproval:
    approval_id: str
    session_id: str
    command: str
    reason: str
    status: str = "pending"  # pending | approved | rejected | expired
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + _DEFAULT_APPROVAL_TTL_SEC)
    resolved_at: float | None = None
    resolver_note: str = ""
    exec_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify_command_safety(command: str, *, mode: str) -> tuple[str, str]:
    """判定命令安全等级：返回 ('deny' | 'allow' | 'require_approval', reason)。"""
    raw = str(command or "").strip()
    if not raw:
        return "deny", "命令不能为空"
    if len(raw) > 2000:
        return "deny", "命令超过最大长度限制"

    for rule_name, pat in _FORBIDDEN_COMMAND_PATTERNS:
        if pat.search(raw):
            return "deny", f"命中永久拦截安全红线 ({rule_name})"

    if mode == "plan":
        # Plan 模式仅允许只读 git status/diff/log 检查
        try:
            tokens = shlex.split(raw, posix=(os.name != "nt"))
        except ValueError:
            return "deny", "Plan 模式禁止无法解析的复杂 Shell 表达式"
        if any(op in raw for op in ("&&", "||", ";", "|", ">", "<", "`", "$(")):
            return "deny", "Plan 只读模式禁止链式/重定向 Shell 表达式"
        lower_tokens = tuple(t.lower() for t in tokens)
        if lower_tokens[:2] in {("git", "status"), ("git", "diff"), ("git", "log"), ("git", "branch")}:
            return "allow", "plan_readonly_git_inspect"
        return "deny", "当前处于 Plan 只读规划模式，执行命令前请先切换为 Build 模式"

    # Build 模式：若包含复合连接符/重定向，一律走审批
    if any(op in raw for op in ("&&", "||", ";", "|", ">", "<", "`", "$(")):
        return "require_approval", "包含复合管道或重定向，需桌面/手机端审批放行"

    try:
        tokens = shlex.split(raw, posix=(os.name != "nt"))
    except ValueError:
        return "require_approval", "包含特殊 Shell 引号语法，需审批放行"

    lower_tokens = tuple(t.lower() for t in tokens)
    for prefix in _SAFE_AUTO_EXEC_PREFIXES:
        if lower_tokens[: len(prefix)] == prefix:
            return "allow", "build_safe_verification_whitelist"
    return "require_approval", "非常规构建/写入命令，需人工审批放行"


class CodingStudioManager:
    """多 Worktree 并行编码会话与 Plan/Build 审批执行总控。"""

    def __init__(
        self,
        *,
        state_path: str | Path,
        allowed_repo_roots: list[str | Path] | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._state_path = Path(state_path)
        self._allowed_repo_roots: list[Path] = [
            Path(p).resolve(strict=False) for p in (allowed_repo_roots or [])
        ]
        self._sessions: dict[str, WorktreeSession] = {}
        self._approvals: dict[str, PendingCommandApproval] = {}
        self._load()

    def _load(self) -> None:
        if not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for sid, raw in (data.get("sessions") or {}).items():
                    if isinstance(raw, dict):
                        self._sessions[sid] = WorktreeSession(**raw)
                for aid, raw in (data.get("approvals") or {}).items():
                    if isinstance(raw, dict):
                        self._approvals[aid] = PendingCommandApproval(**raw)
        except Exception:
            # 损坏状态文件不阻断启动，重新初始化内存视图
            pass

    def _save(self) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "sessions": {sid: s.to_dict() for sid, s in self._sessions.items()},
            "approvals": {aid: a.to_dict() for aid, a in self._approvals.items()},
        }
        tmp = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self._state_path)

    def _validate_repo_path(self, repo_path: str | Path) -> Path:
        raw = Path(repo_path).expanduser()
        if not raw.is_absolute():
            raise CodingStudioError("repo_path 必须是绝对路径")
        if not raw.exists() or not raw.is_dir():
            raise CodingStudioError(f"仓库目录不存在：{repo_path}")
        if _is_reparse(raw):
            raise CodingSecurityError("拒绝操作符号链接或重解析点仓库")
        resolved = raw.resolve(strict=True)
        if self._allowed_repo_roots:
            allowed = False
            for root in self._allowed_repo_roots:
                try:
                    resolved.relative_to(root)
                    allowed = True
                    break
                except ValueError:
                    continue
            if not allowed:
                raise CodingSecurityError(f"仓库路径不在允许的受控根白名单内：{resolved}")
        res = _safe_git(resolved, ["rev-parse", "--is-inside-work-tree"], check=False)
        if res.returncode != 0 or res.stdout.strip().lower() != "true":
            raise CodingStudioError(f"目标目录不是有效的 Git 仓库：{resolved}")
        return resolved

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            out: list[dict[str, Any]] = []
            for s in sorted(self._sessions.values(), key=lambda x: x.created_at, reverse=True):
                d = s.to_dict()
                d["worktree_exists"] = Path(s.worktree_path).exists()
                out.append(d)
            return out

    def get_session(self, session_id: str) -> WorktreeSession:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                raise CodingStudioError(f"Worktree 会话不存在：{session_id}")
            return s

    def create_session(
        self,
        *,
        repo_path: str | Path,
        title: str,
        base_ref: str = "HEAD",
        mode: str = "plan",
        agent_engine: str = "codex",
    ) -> dict[str, Any]:
        norm_mode = str(mode or "plan").strip().lower()
        if norm_mode not in _VALID_MODES:
            raise CodingStudioError(f"mode 必须是 plan 或 build，收到：{mode}")
        norm_engine = str(agent_engine or "codex").strip().lower()
        if norm_engine not in _VALID_ENGINES:
            raise CodingStudioError(f"不支持的编码引擎：{agent_engine}")
        clean_title = str(title or "").strip()[:120]
        if not clean_title:
            raise CodingStudioError("任务标题 title 不能为空")
        clean_base = str(base_ref or "HEAD").strip()
        if not _SAFE_SESSION_NAME_RE.fullmatch(clean_base):
            raise CodingStudioError(f"base_ref 名称非法：{base_ref}")

        repo = self._validate_repo_path(repo_path)
        sid = f"wt-{secrets.token_hex(4)}"
        branch = f"nachuan/{_slugify_branch(clean_title)}-{sid[-4:]}"
        wt_root = repo / ".nachuan-worktrees"
        wt_root.mkdir(parents=True, exist_ok=True)
        wt_path = wt_root / sid

        # 隔离创建 git worktree + 独立分支
        _safe_git(repo, ["worktree", "add", "-b", branch, str(wt_path), clean_base])
        now = time.time()
        session = WorktreeSession(
            session_id=sid,
            title=clean_title,
            repo_path=str(repo),
            worktree_path=str(wt_path),
            branch=branch,
            base_ref=clean_base,
            mode=norm_mode,
            agent_engine=norm_engine,
            status="active",
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            self._sessions[sid] = session
            self._save()
        res = session.to_dict()
        res["worktree_exists"] = True
        return res

    def set_mode(self, session_id: str, mode: str) -> dict[str, Any]:
        norm_mode = str(mode or "").strip().lower()
        if norm_mode not in _VALID_MODES:
            raise CodingStudioError("mode 必须是 plan 或 build")
        with self._lock:
            s = self.get_session(session_id)
            s.mode = norm_mode
            s.updated_at = time.time()
            self._save()
            return s.to_dict()

    def inspect_diff(self, session_id: str) -> dict[str, Any]:
        s = self.get_session(session_id)
        wt = Path(s.worktree_path)
        if not wt.exists():
            raise CodingStudioError(f"Worktree 目录不存在或已被清理：{wt}")

        status_res = _safe_git(wt, ["status", "--porcelain=v1", "-uall"])
        files: list[dict[str, Any]] = []
        total_additions = 0
        total_deletions = 0

        for line in status_res.stdout.splitlines():
            if len(line) < 4:
                continue
            code = line[:2].strip() or "M"
            rel_path = line[3:].strip().strip('"')
            if " -> " in rel_path:
                rel_path = rel_path.split(" -> ", 1)[1].strip().strip('"')
            if code == "??":
                # 未追踪新文件：合成标准 Unified Diff 供前端直观审阅
                fp = _ensure_within(wt / rel_path, wt)
                try:
                    raw_bytes = fp.read_bytes()[:_MAX_DIFF_BYTES_PER_FILE]
                    text = raw_bytes.decode("utf-8", errors="replace")
                    lines = text.splitlines()
                    add_cnt = len(lines)
                    diff_body = "\n".join(
                        [
                            f"--- /dev/null",
                            f"+++ b/{rel_path}",
                            f"@@ -0,0 +1,{add_cnt} @@",
                            *[f"+{ln}" for ln in lines],
                        ]
                    )
                except OSError:
                    add_cnt = 0
                    diff_body = "(binary or unreadable new file)"
                del_cnt = 0
            else:
                diff_res = _safe_git(wt, ["diff", "HEAD", "--", rel_path], check=False)
                diff_body = diff_res.stdout[:_MAX_DIFF_BYTES_PER_FILE]
                add_cnt = sum(
                    1
                    for ln in diff_body.splitlines()
                    if ln.startswith("+") and not ln.startswith("+++")
                )
                del_cnt = sum(
                    1
                    for ln in diff_body.splitlines()
                    if ln.startswith("-") and not ln.startswith("---")
                )
            total_additions += add_cnt
            total_deletions += del_cnt
            files.append(
                {
                    "path": rel_path,
                    "status": code,
                    "additions": add_cnt,
                    "deletions": del_cnt,
                    "diff": diff_body,
                }
            )

        return {
            "session_id": s.session_id,
            "branch": s.branch,
            "mode": s.mode,
            "agent_engine": s.agent_engine,
            "file_count": len(files),
            "total_additions": total_additions,
            "total_deletions": total_deletions,
            "files": files,
        }

    def revert_file(self, session_id: str, rel_path: str) -> dict[str, Any]:
        s = self.get_session(session_id)
        wt = Path(s.worktree_path)
        clean_rel = str(rel_path or "").strip()
        if not clean_rel or clean_rel.startswith(("/", "\\")) or ".." in Path(clean_rel).parts:
            raise CodingSecurityError(f"非法回滚文件路径：{rel_path}")
        target = _ensure_within(wt / clean_rel, wt)

        # 判断是否已追踪
        tracked = _safe_git(wt, ["ls-files", "--error-unmatch", "--", clean_rel], check=False)
        if tracked.returncode == 0:
            _safe_git(wt, ["checkout", "HEAD", "--", clean_rel])
            action = "reverted_to_head"
        else:
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            action = "deleted_untracked"
        return {"ok": True, "session_id": session_id, "path": clean_rel, "action": action}

    def accept_and_commit(
        self,
        session_id: str,
        *,
        message: str,
        files: list[str] | None = None,
    ) -> dict[str, Any]:
        s = self.get_session(session_id)
        wt = Path(s.worktree_path)
        clean_msg = str(message or "").strip()
        if not clean_msg or len(clean_msg) > 500:
            raise CodingStudioError("提交说明 message 不能为空且不超过 500 字")

        if files:
            safe_paths: list[str] = []
            for fp in files:
                clean_rel = str(fp or "").strip()
                if not clean_rel or clean_rel.startswith(("/", "\\")) or ".." in Path(clean_rel).parts:
                    raise CodingSecurityError(f"非法文件路径：{fp}")
                _ensure_within(wt / clean_rel, wt)
                safe_paths.append(clean_rel)
            _safe_git(wt, ["add", "--", *safe_paths])
        else:
            _safe_git(wt, ["add", "-A"])

        # 检查是否有待提交改动
        staged = _safe_git(wt, ["diff", "--cached", "--name-only"])
        staged_files = [x.strip() for x in staged.stdout.splitlines() if x.strip()]
        if not staged_files:
            raise CodingStudioError("当前没有可采纳提交的变更文件")

        _safe_git(
            wt,
            [
                "-c",
                "user.name=Nachuan Studio",
                "-c",
                "user.email=studio@nachuan.local",
                "commit",
                "--no-verify",
                "-m",
                clean_msg,
            ],
        )
        sha = _safe_git(wt, ["rev-parse", "--short", "HEAD"]).stdout.strip()
        return {
            "ok": True,
            "session_id": session_id,
            "branch": s.branch,
            "commit_sha": sha,
            "committed_files": staged_files,
        }

    def destroy_session(
        self, session_id: str, *, delete_branch: bool = True
    ) -> dict[str, Any]:
        with self._lock:
            s = self.get_session(session_id)
            repo = Path(s.repo_path)
            wt = Path(s.worktree_path)
            if wt.exists():
                _safe_git(repo, ["worktree", "remove", "--force", str(wt)], check=False)
                if wt.exists():
                    shutil.rmtree(wt, ignore_errors=True)
            _safe_git(repo, ["worktree", "prune"], check=False)
            if delete_branch and s.branch:
                _safe_git(repo, ["branch", "-D", s.branch], check=False)
            self._sessions.pop(session_id, None)
            self._save()
            return {"ok": True, "session_id": session_id, "destroyed": True}

    def _run_sandboxed_command(self, wt: Path, command: str, timeout: float = 60.0) -> dict[str, Any]:
        tokens = shlex.split(command, posix=(os.name != "nt"))
        t0 = time.perf_counter()
        try:
            res = subprocess.run(
                tokens,
                cwd=str(wt),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(1.0, min(timeout, 120.0)),
                shell=False,
                **_subprocess_kwargs(),
            )
            return {
                "exit_code": res.returncode,
                "stdout": (res.stdout or "")[:_MAX_CMD_OUTPUT_CHARS],
                "stderr": (res.stderr or "")[:_MAX_CMD_OUTPUT_CHARS],
                "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }
        except FileNotFoundError as exc:
            return {
                "exit_code": 127,
                "stdout": "",
                "stderr": f"Executable not found: {exc}",
                "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": 124,
                "stdout": "",
                "stderr": "Command timed out in coding sandbox",
                "duration_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            }

    def request_exec(
        self, session_id: str, *, command: str, timeout: float = 60.0
    ) -> dict[str, Any]:
        s = self.get_session(session_id)
        wt = Path(s.worktree_path)
        if not wt.exists():
            raise CodingStudioError("Worktree 目录不存在")

        verdict, reason = classify_command_safety(command, mode=s.mode)
        if verdict == "deny":
            raise CodingSecurityError(reason)

        if verdict == "allow":
            result = self._run_sandboxed_command(wt, command, timeout=timeout)
            return {
                "status": "executed",
                "session_id": session_id,
                "mode": s.mode,
                "policy": reason,
                "result": result,
            }

        # 需要桌面/手机端审批放行
        aid = f"cap-{secrets.token_hex(5)}"
        now = time.time()
        approval = PendingCommandApproval(
            approval_id=aid,
            session_id=session_id,
            command=command.strip(),
            reason=reason,
            status="pending",
            created_at=now,
            expires_at=now + _DEFAULT_APPROVAL_TTL_SEC,
        )
        with self._lock:
            self._approvals[aid] = approval
            self._save()
        return {
            "status": "pending_approval",
            "session_id": session_id,
            "mode": s.mode,
            "approval": approval.to_dict(),
        }

    def list_approvals(self, *, status: str | None = None) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            changed = False
            for a in self._approvals.values():
                if a.status == "pending" and now > a.expires_at:
                    a.status = "expired"
                    changed = True
            if changed:
                self._save()
            items = [
                a.to_dict()
                for a in sorted(self._approvals.values(), key=lambda x: x.created_at, reverse=True)
                if not status or a.status == status
            ]
            return items

    def resolve_approval(
        self,
        approval_id: str,
        *,
        decision: str,
        note: str = "",
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        norm = str(decision or "").strip().lower()
        if norm not in {"approve", "reject"}:
            raise CodingStudioError("decision 必须是 approve 或 reject")
        with self._lock:
            a = self._approvals.get(approval_id)
            if a is None:
                raise CodingStudioError(f"审批单不存在：{approval_id}")
            if a.status != "pending":
                raise CodingStudioError(f"审批单已终态（{a.status}），禁止重放")
            if time.time() > a.expires_at:
                a.status = "expired"
                self._save()
                raise CodingStudioError("审批单已过期，请重新发起")

            # 二次防线：批准前依然校验命令未命中永久黑名单
            verdict, reason = classify_command_safety(a.command, mode="build")
            if verdict == "deny":
                a.status = "rejected"
                a.resolver_note = reason
                a.resolved_at = time.time()
                self._save()
                raise CodingSecurityError(reason)

            a.resolver_note = str(note or "")[:300]
            a.resolved_at = time.time()
            if norm == "reject":
                a.status = "rejected"
                self._save()
                return a.to_dict()

            a.status = "approved"
            s = self.get_session(a.session_id)
            wt = Path(s.worktree_path)
            if not wt.exists():
                raise CodingStudioError("目标 Worktree 已被销毁，无法执行已批准命令")
            a.exec_result = self._run_sandboxed_command(wt, a.command, timeout=timeout)
            self._save()
            return a.to_dict()


__all__ = [
    "CodingSecurityError",
    "CodingStudioError",
    "CodingStudioManager",
    "PendingCommandApproval",
    "WorktreeSession",
    "classify_command_safety",
]
