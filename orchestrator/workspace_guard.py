"""Fail-closed workspace boundary for model-controlled file access.

An in-process agent is not an OS sandbox. Its file tools may therefore see only
one explicitly configured, dedicated workspace tree. The user home, repository
root, runtime data, credential directories and reparse points are never valid
workspace roots.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from gateway.config import PROJECT_ROOT, get_settings


class WorkspaceBoundaryError(ValueError):
    pass


_SENSITIVE_PARTS = frozenset(
    {
        ".ssh",
        ".aws",
        ".azure",
        ".config",
        ".gnupg",
        ".codex",
        ".claude",
        "user data",
    }
)


def _same_or_within(path: Path, root: Path) -> bool:
    try:
        normalized_root = os.path.normcase(str(root))
        return os.path.commonpath(
            [os.path.normcase(str(path)), normalized_root]
        ) == normalized_root
    except (OSError, ValueError):
        return False


def _is_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        attributes = int(getattr(os.lstat(path), "st_file_attributes", 0))
        return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))
    except OSError:
        return True


def _assert_existing_components_are_real(path: Path) -> None:
    for candidate in reversed((path, *path.parents)):
        if candidate.exists() and _is_reparse(candidate):
            raise WorkspaceBoundaryError(
                "Agent 路径不能经过符号链接、目录联接或其它重解析点"
            )


def _guard_home() -> Path:
    configured = str(os.getenv("NACHUAN_GUARD_HOME") or "").strip()
    try:
        lexical = Path(configured) if configured else Path.home()
        if not lexical.is_absolute():
            raise WorkspaceBoundaryError("NACHUAN_GUARD_HOME 必须是绝对路径")
        _assert_existing_components_are_real(lexical)
        resolved = lexical.resolve(strict=True)
        if not resolved.is_dir():
            raise WorkspaceBoundaryError("用户 HOME 边界不是目录")
        return resolved
    except WorkspaceBoundaryError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WorkspaceBoundaryError("无法安全解析用户 HOME 拒绝边界") from exc


def _assert_safe_workspace_root(
    root: Path, *, home: Path, project: Path, runtime_data: Path
) -> None:
    anchor = Path(root.anchor).resolve(strict=False) if root.anchor else root
    if root in {anchor, home, project} or _same_or_within(root, runtime_data):
        raise WorkspaceBoundaryError("Agent 工作区不能是磁盘根、用户 HOME、项目根或运行态 data")
    if any(part.casefold() in _SENSITIVE_PARTS for part in root.parts):
        raise WorkspaceBoundaryError("Agent 工作区不能位于凭据/工具配置目录中")


def workspace_root(*, create: bool = True) -> Path:
    settings = get_settings()
    raw = str(settings.agent_exec_workdir or (PROJECT_ROOT / "workspaces"))
    lexical = Path(raw).expanduser()
    if not lexical.is_absolute():
        raise WorkspaceBoundaryError("Agent 专用工作区必须配置为绝对路径")
    _assert_existing_components_are_real(lexical)
    try:
        candidate = lexical.resolve(strict=False)
        home = _guard_home()
        project = PROJECT_ROOT.resolve(strict=True)
        runtime_data = Path(
            os.getenv("DATA_DIR") or (PROJECT_ROOT / "data")
        ).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceBoundaryError("Agent 专用工作区不存在或无法安全解析") from exc

    # Validate the non-existent candidate before mkdir: a rejected .ssh/data/home
    # configuration must not leave attacker-controlled or confusing garbage behind.
    _assert_safe_workspace_root(
        candidate, home=home, project=project, runtime_data=runtime_data
    )
    try:
        if create:
            lexical.mkdir(parents=True, exist_ok=True)
        _assert_existing_components_are_real(lexical)
        root = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceBoundaryError("Agent 专用工作区不存在或无法安全解析") from exc
    _assert_safe_workspace_root(
        root, home=home, project=project, runtime_data=runtime_data
    )
    return root


def resolve_workspace(workdir: str, *, create_root: bool = True) -> Path:
    root = workspace_root(create=create_root)
    try:
        lexical = Path(workdir).expanduser().absolute()
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WorkspaceBoundaryError("workdir 不存在或无法安全解析") from exc
    if not resolved.is_dir() or not _same_or_within(resolved, root):
        raise WorkspaceBoundaryError("workdir 必须位于 Agent 专用工作区根内")

    # ``resolve`` catches escapes; rejecting every existing component below
    # the root also removes same-tree symlink/junction ambiguity.
    try:
        relative = lexical.relative_to(Path(str(root)))
    except ValueError as exc:
        raise WorkspaceBoundaryError("workdir 的词法路径越出 Agent 工作区") from exc
    current = Path(str(root))
    for part in relative.parts:
        current /= part
        if _is_reparse(current):
            raise WorkspaceBoundaryError("workdir 不能经过符号链接或目录联接")
    return resolved
