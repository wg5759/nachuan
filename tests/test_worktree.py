"""The retired in-process Git/worktree execution surface stays fail-closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.agent_runner import AGENT_RUNNERS
from orchestrator.worktree import (
    WorktreeError,
    create_worktree,
    list_worktrees,
    remove_worktree,
    worktree_diff,
)


def test_retired_claude_agent_is_not_selectable() -> None:
    assert "claude" not in AGENT_RUNNERS


def test_every_worktree_entrypoint_fails_before_filesystem_mutation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    calls = (
        lambda: create_worktree(repo, "impl1"),
        lambda: list_worktrees(repo),
        lambda: worktree_diff(repo, repo / ".worktrees" / "impl1"),
        lambda: remove_worktree(repo, repo / ".worktrees" / "impl1", "agent/impl1"),
    )

    for call in calls:
        with pytest.raises(WorktreeError, match="low-privilege worker"):
            call()

    assert list(repo.iterdir()) == []


def test_retired_module_has_no_process_launch_or_git_command_surface() -> None:
    source = (Path(__file__).parents[1] / "orchestrator" / "worktree.py").read_text("utf-8")

    assert "import subprocess" not in source
    assert "subprocess." not in source
    assert '["git"' not in source
    assert "sanitized_cli_env" not in source


def test_desktop_does_not_offer_the_retired_coding_team_as_a_working_feature() -> None:
    pane = (
        Path(__file__).parents[1]
        / "desktop"
        / "src"
        / "renderer"
        / "src"
        / "components"
        / "OrchestratePane.tsx"
    ).read_text("utf-8")

    assert "runCodingTeam" not in pane
    assert 'k="coding"' not in pane
    assert "<CodingMode" not in pane
