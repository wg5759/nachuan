from __future__ import annotations

import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "relative",
    (
        Path(".claude/settings.json"),
        Path(".codex/hooks.json"),
    ),
)
def test_project_agent_config_never_auto_executes_repository_code(relative: Path) -> None:
    """Same-user writable repositories are not a trust boundary for command hooks."""
    path = ROOT / relative
    if not path.exists():
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data.get("hooks") in ({}, None), (
        f"{relative.as_posix()} must not register project hooks; "
        "run checks explicitly or from an administrator-managed external policy"
    )


def test_claude_project_explicitly_disables_all_hooks() -> None:
    data = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
    assert data.get("disableAllHooks") is True


def test_local_claude_permissions_do_not_auto_allow_uv_execution() -> None:
    """Cover the current workstation override when it exists; CI need not have it."""
    path = ROOT / ".claude/settings.local.json"
    if not path.exists():
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    permissions = data.get("permissions") or {}
    allow = permissions.get("allow") or []
    assert not any("uv run" in str(rule).casefold() for rule in allow)


def test_update_watcher_docs_do_not_reintroduce_writable_repo_persistence() -> None:
    text = (ROOT / "docs" / "自动更新机制.md").read_text(encoding="utf-8")
    forbidden = (
        "Register-ScheduledTask",
        "schtasks /create",
        "New-ScheduledTaskAction",
        "Start-ScheduledTask",
    )
    assert not any(token.casefold() in text.casefold() for token in forbidden)
