from __future__ import annotations

import asyncio
import sqlite3

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from gateway import auth
from gateway.config import Settings
from orchestrator import approval
from orchestrator.approval import ApprovalStore


class _AuthSettings:
    api_keys = {"runtime-key"}
    approval_admin_key = "independent-approval-key"


def test_runtime_api_key_cannot_authenticate_as_approval_admin(monkeypatch) -> None:
    monkeypatch.setattr(auth, "get_settings", lambda: _AuthSettings())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth.require_approval_admin_key("runtime-key"))

    assert exc.value.status_code == 401


def test_approval_header_is_separate_from_authorization_header(monkeypatch) -> None:
    monkeypatch.setattr(auth, "get_settings", lambda: _AuthSettings())
    monkeypatch.setattr(auth, "desktop_engine_keys", lambda: frozenset())
    api = FastAPI()

    @api.post("/approve")
    async def approve(_: str = Depends(auth.require_approval_admin_key)) -> dict[str, bool]:
        return {"ok": True}

    with TestClient(api) as client:
        runtime_only = client.post(
            "/approve", headers={"Authorization": "Bearer runtime-key"}
        )
        approved = client.post(
            "/approve",
            headers={"X-Nachuan-Approval-Key": "independent-approval-key"},
        )

    assert runtime_only.status_code == 401
    assert approved.status_code == 200


def test_approval_admin_auth_is_fail_closed_and_independent(monkeypatch) -> None:
    monkeypatch.setattr(auth, "get_settings", lambda: _AuthSettings())

    with pytest.raises(HTTPException) as missing:
        asyncio.run(auth.require_approval_admin_key(None))
    assert missing.value.status_code == 401

    assert (
        asyncio.run(auth.require_approval_admin_key("independent-approval-key"))
        == "approval-admin"
    )

    class _Unconfigured:
        api_keys = {"runtime-key"}
        approval_admin_key = ""

    monkeypatch.setattr(auth, "get_settings", lambda: _Unconfigured())
    with pytest.raises(HTTPException) as unconfigured:
        asyncio.run(auth.require_approval_admin_key("runtime-key"))
    assert unconfigured.value.status_code == 503


def test_approval_admin_key_must_not_overlap_runtime_keys(monkeypatch) -> None:
    class _Overlapping:
        api_keys = {"same-secret"}
        approval_admin_key = "same-secret"

    monkeypatch.setattr(auth, "get_settings", lambda: _Overlapping())
    monkeypatch.setattr(auth, "desktop_engine_keys", lambda: frozenset())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth.require_approval_admin_key("same-secret"))

    assert exc.value.status_code == 503


def test_action_approval_ttl_configuration_is_bounded_to_five_to_fifteen_minutes(
    monkeypatch,
) -> None:
    monkeypatch.delenv("APPROVAL_ACTION_TTL_SEC", raising=False)
    assert Settings(_env_file=None).approval_action_ttl_sec == 600
    assert Settings(_env_file=None, approval_action_ttl_sec=300).approval_action_ttl_sec == 300
    assert Settings(_env_file=None, approval_action_ttl_sec=900).approval_action_ttl_sec == 900

    with pytest.raises(ValidationError):
        Settings(_env_file=None, approval_action_ttl_sec=299)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, approval_action_ttl_sec=901)


def test_expired_action_is_not_listed_resolved_or_claimed(tmp_path, monkeypatch) -> None:
    now = [1_000.0]
    monkeypatch.setattr(approval.time, "time", lambda: now[0])
    store = ApprovalStore(str(tmp_path / "approvals.db"), action_ttl_sec=300)
    payload = {
        "scope": "agent_exec",
        "task": "write report",
        "workdir": str(tmp_path),
        "mode": "plan",
    }
    approval_id = store.create("owner", "action", "write report", payload)
    assert store.list_pending("owner")[0]["expires_at"] == 1_300.0

    now[0] = 1_301.0
    assert store.list_pending("owner") == []
    assert store.count_pending("owner") == 0
    assert store.get(approval_id)["status"] == "expired"
    assert store.resolve(approval_id, "approve")["status"] == "expired"
    assert not store.claim_action(
        approval_id,
        user_id="owner",
        task="write report",
        workdir=str(tmp_path),
        scope="agent_exec",
        mode="plan",
    )
    store.close()


def test_approved_action_capability_expires_before_claim(tmp_path, monkeypatch) -> None:
    now = [2_000.0]
    monkeypatch.setattr(approval.time, "time", lambda: now[0])
    store = ApprovalStore(str(tmp_path / "approvals.db"), action_ttl_sec=300)
    payload = {
        "scope": "agent_exec",
        "task": "write report",
        "workdir": str(tmp_path),
        "mode": "plan",
    }
    approval_id = store.create("owner", "action", "write report", payload)
    assert store.resolve(approval_id, "approve")["status"] == "approved"

    now[0] = 2_301.0
    assert store.approved_action_spec(approval_id, scope="agent_exec") is None
    assert not store.claim_action(
        approval_id,
        user_id="owner",
        task="write report",
        workdir=str(tmp_path),
        scope="agent_exec",
        mode="plan",
    )
    assert store.get(approval_id)["status"] == "expired"
    store.close()


def test_skill_card_does_not_inherit_action_expiration(tmp_path, monkeypatch) -> None:
    now = [3_000.0]
    monkeypatch.setattr(approval.time, "time", lambda: now[0])
    store = ApprovalStore(str(tmp_path / "approvals.db"), action_ttl_sec=300)
    approval_id = store.create("owner", "skill_card", "verified lesson", {"x": 1})

    now[0] = 30_000.0
    assert store.get(approval_id)["status"] == "pending"
    assert store.list_pending("owner")[0]["id"] == approval_id
    store.close()


def test_legacy_action_without_expiry_is_invalidated_on_migration(tmp_path) -> None:
    db_path = tmp_path / "approvals.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """CREATE TABLE approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            summary TEXT NOT NULL,
            payload TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            note TEXT,
            created_at REAL,
            resolved_at REAL
        )"""
    )
    connection.execute(
        "INSERT INTO approvals (user_id,kind,summary,payload,status,created_at) "
        "VALUES ('owner','action','legacy','{}','pending',1)"
    )
    connection.commit()
    connection.close()

    store = ApprovalStore(str(db_path), action_ttl_sec=300)
    assert store.get(1)["status"] == "expired"
    assert store.list_pending("owner") == []
    store.close()


@pytest.mark.parametrize("ttl", [0, 299, 901, 3_600])
def test_approval_store_rejects_ttl_outside_security_window(tmp_path, ttl: int) -> None:
    with pytest.raises(ValueError):
        ApprovalStore(str(tmp_path / f"{ttl}.db"), action_ttl_sec=ttl)
