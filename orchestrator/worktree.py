"""Retired in-process Git/worktree execution boundary.

The gateway coding-team endpoints are intentionally closed until repository
mutation runs in a separately authenticated, low-privilege worker. Keeping the
old helper dormant was still unsafe: a future caller could execute repository
Git hooks with the gateway identity. These compatibility functions therefore
fail before resolving Git, inspecting a repository, or mutating the filesystem.
"""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn


class WorktreeError(Exception):
    """Raised when retired in-process worktree execution is requested."""


_DISABLED_REASON = (
    "Git/worktree execution is disabled in the gateway process; "
    "use an independently authenticated low-privilege worker"
)


def _disabled() -> NoReturn:
    raise WorktreeError(_DISABLED_REASON)


def create_worktree(repo: str | Path, name: str, base: str = "HEAD") -> Path:
    """Compatibility surface; always fails before any repository action."""

    _disabled()


def worktree_diff(repo: str | Path, wt_path: str | Path) -> str:
    """Compatibility surface; always fails before staging or reading a diff."""

    _disabled()


def remove_worktree(
    repo: str | Path, wt_path: str | Path, branch: str | None = None
) -> None:
    """Compatibility surface; always fails before cleanup or branch deletion."""

    _disabled()


def list_worktrees(repo: str | Path) -> list[str]:
    """Compatibility surface; always fails before invoking Git."""

    _disabled()
