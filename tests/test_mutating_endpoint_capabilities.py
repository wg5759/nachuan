"""Every endpoint that can launch code or register executable tools is capability-gated."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app
from gateway import mcp_registry
from orchestrator import conv_summary


AUTH = {"Authorization": "Bearer test-key"}


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    return repo


def test_coding_team_is_closed_before_manifest_or_approval(
    monkeypatch, tmp_path: Path
) -> None:
    repo = _repo(tmp_path)
    calls: list[dict] = []

    async def fake_team(_router, **kwargs):  # noqa: ANN001
        calls.append(kwargs)
        return {"plan": "p", "implementations": [], "review": "reviewed"}

    monkeypatch.setattr(appmod, "run_coding_team", fake_team)
    payload = {
        "repo": str(repo),
        "task": "实现功能",
        "planner": "echo",
        "reviewer": "echo",
        "implementers": [{"name": "codex-impl", "agent": "codex"}],
        "user_id": "coding-cap-user",
    }
    with TestClient(app) as client:
        for candidate in (payload, {**payload, "approval_id": 1}):
            response = client.post(
                "/v1/orchestrate/coding", headers=AUTH, json=candidate
            )
            assert response.status_code == 503
            assert "低权限执行 worker" in response.json()["detail"]
    assert calls == []


def test_arch_editor_is_closed_before_git_or_capability(
    monkeypatch, tmp_path: Path
) -> None:
    repo = _repo(tmp_path)
    calls = 0

    async def fake_editor(_router, **_kwargs):  # noqa: ANN001
        nonlocal calls
        calls += 1
        return {"diff": "safe"}

    monkeypatch.setattr(appmod, "run_arch_editor", fake_editor)
    payload = {
        "repo": str(repo),
        "task": "编辑项目",
        "architect": "echo",
        "editor": "echo",
        "user_id": "arch-cap-user",
    }
    with TestClient(app) as client:
        for candidate in (payload, {**payload, "approval_id": 1}):
            response = client.post(
                "/v1/orchestrate/arch-editor", headers=AUTH, json=candidate
            )
            assert response.status_code == 503
    assert calls == 0


def test_mcp_is_quarantined_and_secrets_are_redacted(monkeypatch, tmp_path: Path) -> None:
    registry = tmp_path / "mcp.json"
    registry.write_text(
        json.dumps({
            "mcpServers": {
                "old": {"command": "tool", "args": [], "env": {"TOKEN": "do-not-leak"}}
            }
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(mcp_registry, "_path", lambda: registry)
    monkeypatch.delenv("NACHUAN_ENABLE_UNVERIFIED_MCP", raising=False)
    monkeypatch.delenv("NACHUAN_ENABLE_VERIFIED_MCP", raising=False)
    with TestClient(app) as client:
        listed = client.get("/v1/mcp", headers=AUTH)
        blocked = client.post(
            "/v1/mcp", headers=AUTH, json={"name": "x", "command": "tool"}
        )

    assert listed.status_code == 200 and listed.json()["enabled"] is False
    assert listed.json()["mcpServers"]["old"]["env_keys"] == ["TOKEN"]
    assert "do-not-leak" not in listed.text
    assert blocked.status_code == 403


def test_verified_local_mcp_switch_cannot_bypass_worker_boundary(
    monkeypatch, tmp_path: Path
) -> None:
    registry = tmp_path / "mcp.json"
    executable = (tmp_path / "reviewed-mcp.exe").resolve()
    executable.write_bytes(b"reviewed MCP executable fixture")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setattr(mcp_registry, "_path", lambda: registry)
    monkeypatch.setenv("NACHUAN_ENABLE_VERIFIED_MCP", "1")
    payload = {
        "name": "local-tool",
        "command": str(executable),
        "args": ["--safe"],
        "sha256": digest,
        "user_id": "mcp-cap-user",
    }
    with TestClient(app) as client:
        response = client.post("/v1/mcp", headers=AUTH, json=payload)

    assert response.status_code == 403
    assert mcp_registry.verified_mcp_enabled() is False
    assert mcp_registry.list_servers() == {}


def test_legacy_unverified_mcp_switch_is_inert(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(mcp_registry, "_path", lambda: tmp_path / "mcp.json")
    monkeypatch.setenv("NACHUAN_ENABLE_UNVERIFIED_MCP", "1")
    monkeypatch.delenv("NACHUAN_ENABLE_VERIFIED_MCP", raising=False)
    with TestClient(app) as client:
        response = client.post(
            "/v1/mcp",
            headers=AUTH,
            json={"name": "unsafe", "command": "npx", "sha256": "0" * 64},
        )
    assert response.status_code == 403


def test_local_model_switch_requires_capability(monkeypatch, approval_auth_headers) -> None:
    calls: list[str] = []

    def fake_switch(model_id: str) -> bool:
        calls.append(model_id)
        return True

    async def fake_reload() -> None:
        return None

    monkeypatch.setattr(appmod.local_model, "switch", fake_switch)
    payload = {
        "model_id": appmod.local_model.CATALOG[0]["id"],
        "user_id": "local-model-cap-user",
    }
    with TestClient(app) as client:
        monkeypatch.setattr(app.state.router, "reload", fake_reload)
        held = client.post("/v1/local/select", headers=AUTH, json=payload).json()
        assert held["needs_approval"] is True and calls == []
        aid = held["approval_id"]
        client.post(
            f"/v1/approvals/{aid}/resolve",
            headers=approval_auth_headers,
            json={"decision": "approve"},
        )
        ok = client.post(
            "/v1/local/select", headers=AUTH, json={**payload, "approval_id": aid}
        )
    assert ok.status_code == 200 and calls == [payload["model_id"]]


def test_studio_execution_requires_capability(monkeypatch, approval_auth_headers) -> None:
    calls = 0

    def fake_start(_router, _plan, _out_dir):  # noqa: ANN001
        nonlocal calls
        calls += 1
        return "studio-job"

    monkeypatch.setattr(appmod, "start_execution", fake_start)
    payload = {
        "plan": {"title": "t", "shots": [{"n": 1, "desc": "x", "seconds": 5}]},
        "user_id": "studio-cap-user",
    }
    with TestClient(app) as client:
        held = client.post("/v1/studio/execute", headers=AUTH, json=payload).json()
        assert held["needs_approval"] is True and calls == 0
        aid = held["approval_id"]
        client.post(
            f"/v1/approvals/{aid}/resolve",
            headers=approval_auth_headers,
            json={"decision": "approve"},
        )
        ok = client.post(
            "/v1/studio/execute", headers=AUTH, json={**payload, "approval_id": aid}
        )
    assert ok.status_code == 200 and ok.json()["job_id"] == "studio-job" and calls == 1


def test_daily_video_launcher_is_closed_before_capability(
    monkeypatch, tmp_path: Path
) -> None:
    payload = {
        "root": str(tmp_path / "video-root"),
        "date": "2026-07-13",
        "user_id": "daily-video-cap-user",
    }
    with TestClient(app) as client:
        for candidate in (payload, {**payload, "approval_id": 1}):
            response = client.post(
                "/v1/workflows/daily-video/start",
                headers=AUTH,
                json=candidate,
            )
            assert response.status_code == 503
            assert "低权限执行 worker" in response.json()["detail"]


def test_daily_video_invalid_inputs_do_not_precede_worker_boundary(
    monkeypatch, tmp_path: Path
) -> None:
    payload = {
        "root": str(tmp_path / "missing"),
        "date": "2026-07-13",
        "user_id": "daily-video-tamper-user",
    }
    with TestClient(app) as client:
        response = client.post(
            "/v1/workflows/daily-video/start",
            headers=AUTH,
            json={**payload, "approval_id": 1},
        )
    assert response.status_code == 503


def _approve(client: TestClient, approval_id: int, headers: dict[str, str]) -> None:
    response = client.post(
        f"/v1/approvals/{approval_id}/resolve",
        headers=headers,
        json={"decision": "approve"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"


def test_memory_clear_requires_exact_snapshot_capability(
    approval_auth_headers,
) -> None:
    user_id = "memory-delete-cap-user"
    other_user = "memory-delete-cap-other"
    with TestClient(app) as client:
        app.state.memory.clear(user_id)
        app.state.memory.clear(other_user)
        app.state.memory.add(user_id, "first memory")
        app.state.memory.add(other_user, "must survive")

        legacy = client.delete(
            "/v1/agent/memory", headers=AUTH, params={"user_id": user_id}
        )
        assert legacy.status_code == 410
        assert app.state.memory.all_for(user_id)

        held = client.post(
            "/v1/agent/memory/clear",
            headers=AUTH,
            json={"user_id": user_id},
        ).json()
        assert held["needs_approval"] is True
        _approve(client, held["approval_id"], approval_auth_headers)

        # The approved snapshot did not contain this fact, so it must not be
        # silently swept into the destructive operation.
        app.state.memory.add(user_id, "arrived after approval")
        drifted = client.post(
            "/v1/agent/memory/clear",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": held["approval_id"]},
        )
        assert drifted.status_code == 403
        assert len(app.state.memory.all_for(user_id)) == 2

        fresh = client.post(
            "/v1/agent/memory/clear",
            headers=AUTH,
            json={"user_id": user_id},
        ).json()
        _approve(client, fresh["approval_id"], approval_auth_headers)
        tampered = client.post(
            "/v1/agent/memory/clear",
            headers=AUTH,
            json={"user_id": other_user, "approval_id": fresh["approval_id"]},
        )
        ok = client.post(
            "/v1/agent/memory/clear",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )
        replay = client.post(
            "/v1/agent/memory/clear",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )

        assert tampered.status_code == 403
        assert ok.status_code == 200 and ok.json()["ok"] is True
        assert replay.status_code == 403
        assert app.state.memory.all_for(user_id) == []
        assert [m["text"] for m in app.state.memory.all_for(other_user)] == [
            "must survive"
        ]


def test_kb_delete_requires_exact_document_capability(
    approval_auth_headers,
) -> None:
    user_id = "kb-delete-cap-user"
    other_user = "kb-delete-cap-other"
    with TestClient(app) as client:
        doc = app.state.kb.add_document(
            user_id, "approved title", "approved body for the exact capability flow"
        )
        other = app.state.kb.add_document(
            other_user, "other title", "must survive the whole capability flow"
        )
        doc_id = int(doc["doc_id"])

        legacy = client.delete(
            f"/v1/kb/docs/{doc_id}", headers=AUTH, params={"user_id": user_id}
        )
        assert legacy.status_code == 410
        assert any(d["id"] == doc_id for d in app.state.kb.list_documents(user_id))

        held = client.post(
            f"/v1/kb/docs/{doc_id}/delete",
            headers=AUTH,
            json={"user_id": user_id},
        ).json()
        _approve(client, held["approval_id"], approval_auth_headers)

        # Model a concurrent edit/re-index between review and execution. The
        # capability is bound to the reviewed document snapshot, not just its id.
        with app.state.kb._lock:  # noqa: SLF001 - security regression fixture
            app.state.kb._conn.execute(  # noqa: SLF001
                "UPDATE kb_docs SET title=? WHERE user_id=? AND id=?",
                ("changed after approval", user_id, doc_id),
            )
            app.state.kb._conn.commit()  # noqa: SLF001
        drifted = client.post(
            f"/v1/kb/docs/{doc_id}/delete",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": held["approval_id"]},
        )
        assert drifted.status_code == 403

        fresh = client.post(
            f"/v1/kb/docs/{doc_id}/delete",
            headers=AUTH,
            json={"user_id": user_id},
        ).json()
        _approve(client, fresh["approval_id"], approval_auth_headers)
        tampered = client.post(
            f"/v1/kb/docs/{doc_id}/delete",
            headers=AUTH,
            json={"user_id": other_user, "approval_id": fresh["approval_id"]},
        )
        ok = client.post(
            f"/v1/kb/docs/{doc_id}/delete",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )
        replay = client.post(
            f"/v1/kb/docs/{doc_id}/delete",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )

        assert tampered.status_code == 403
        assert ok.status_code == 200 and ok.json()["ok"] is True
        assert replay.status_code == 403
        assert not any(d["id"] == doc_id for d in app.state.kb.list_documents(user_id))
        assert any(
            d["id"] == int(other["doc_id"])
            for d in app.state.kb.list_documents(other_user)
        )


def test_summary_clear_requires_exact_snapshot_and_scope(
    approval_auth_headers,
) -> None:
    user_id = "summary-delete-cap-user"
    conv_id = "summary-delete-conversation"
    other_conv = "summary-delete-other"
    with TestClient(app) as client:
        store = conv_summary._get_store()  # noqa: SLF001 - integration assertion
        assert store is not None
        store.put(conv_id, "reviewed summary", 10)
        store.put(other_conv, "must survive", 3)

        held = client.post(
            f"/v1/conv/{conv_id}/clear-summary",
            headers=AUTH,
            json={"user_id": user_id},
        ).json()
        assert held["needs_approval"] is True
        _approve(client, held["approval_id"], approval_auth_headers)

        store.put(conv_id, "changed after approval", 11)
        drifted = client.post(
            f"/v1/conv/{conv_id}/clear-summary",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": held["approval_id"]},
        )
        assert drifted.status_code == 403
        assert store.get(conv_id) == ("changed after approval", 11)

        fresh = client.post(
            f"/v1/conv/{conv_id}/clear-summary",
            headers=AUTH,
            json={"user_id": user_id},
        ).json()
        _approve(client, fresh["approval_id"], approval_auth_headers)
        wrong_target = client.post(
            f"/v1/conv/{other_conv}/clear-summary",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )
        ok = client.post(
            f"/v1/conv/{conv_id}/clear-summary",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )
        replay = client.post(
            f"/v1/conv/{conv_id}/clear-summary",
            headers=AUTH,
            json={"user_id": user_id, "approval_id": fresh["approval_id"]},
        )

        assert wrong_target.status_code == 403
        assert ok.status_code == 200 and ok.json()["ok"] is True
        assert replay.status_code == 403
        assert store.get(conv_id) == ("", 0)
        assert store.get(other_conv) == ("must survive", 3)
