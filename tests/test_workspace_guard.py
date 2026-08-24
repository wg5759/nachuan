from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app
from orchestrator import workspace_guard
from orchestrator.tool_agent import execute_tool


AUTH = {"Authorization": "Bearer test-key"}


def test_guard_accepts_only_dedicated_root_and_descendants(tmp_path, monkeypatch):
    root = tmp_path / "workspaces"
    child = root / "project-a"
    child.mkdir(parents=True)
    monkeypatch.setattr(
        workspace_guard,
        "get_settings",
        lambda: SimpleNamespace(agent_exec_workdir=str(root)),
    )

    assert workspace_guard.resolve_workspace(str(root)) == root.resolve()
    assert workspace_guard.resolve_workspace(str(child)) == child.resolve()
    with pytest.raises(workspace_guard.WorkspaceBoundaryError):
        workspace_guard.resolve_workspace(str(tmp_path))


def test_packaged_guard_home_does_not_depend_on_inherited_home_variables(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    root = tmp_path / "app-data" / "workspaces"
    home.mkdir()
    root.mkdir(parents=True)
    monkeypatch.setenv("NACHUAN_GUARD_HOME", str(home.resolve()))
    monkeypatch.setattr(
        workspace_guard,
        "get_settings",
        lambda: SimpleNamespace(agent_exec_workdir=str(root.resolve())),
    )

    def inherited_home_must_not_be_used():
        raise RuntimeError("minimal packaged environment has no inherited HOME")

    monkeypatch.setattr(Path, "home", inherited_home_must_not_be_used)
    assert workspace_guard.workspace_root() == root.resolve()


@pytest.mark.parametrize(
    "forbidden",
    [Path.home(), appmod.PROJECT_ROOT, appmod.PROJECT_ROOT / "data"],
)
def test_dangerous_workspace_roots_are_rejected(forbidden, monkeypatch):
    monkeypatch.setattr(
        workspace_guard,
        "get_settings",
        lambda: SimpleNamespace(agent_exec_workdir=str(forbidden)),
    )
    with pytest.raises(workspace_guard.WorkspaceBoundaryError):
        workspace_guard.workspace_root()


def test_rejected_sensitive_root_is_never_created(tmp_path, monkeypatch):
    forbidden = tmp_path / ".ssh" / "agent-garbage"
    monkeypatch.setattr(
        workspace_guard,
        "get_settings",
        lambda: SimpleNamespace(agent_exec_workdir=str(forbidden)),
    )
    with pytest.raises(workspace_guard.WorkspaceBoundaryError):
        workspace_guard.workspace_root()
    assert not forbidden.exists()


def test_workspace_rejects_reparse_escape(tmp_path, monkeypatch):
    root = tmp_path / "workspaces"
    root.mkdir()
    link = root / "outside-link"
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("current Windows policy does not permit test symlinks")
    monkeypatch.setattr(
        workspace_guard,
        "get_settings",
        lambda: SimpleNamespace(agent_exec_workdir=str(root)),
    )
    with pytest.raises(workspace_guard.WorkspaceBoundaryError):
        workspace_guard.resolve_workspace(str(link))


async def test_low_level_file_tool_rejects_home_even_for_read_only():
    result = await execute_tool("list_dir", {"path": "."}, workdir=str(Path.home()))
    assert "拦截" in result
    assert "工作区" in result


def test_agent_run_rejects_home_before_calling_any_model(monkeypatch):
    async def fail_model(*_args, **_kwargs):
        raise AssertionError("unsafe workdir must be rejected before model execution")

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fail_model)
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/run",
            headers=AUTH,
            json={
                "task": "读取目录",
                "mode": "plan",
                "allow": ["read_file"],
                "workdir": str(Path.home()),
            },
        )
    assert response.status_code == 403
    assert "工作区" in response.json()["detail"]
