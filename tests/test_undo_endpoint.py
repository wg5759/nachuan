"""The HTTP undo surface accepts only exact server-issued receipts."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from gateway.app import app


AUTH = {"Authorization": "Bearer test-key"}


def test_legacy_arbitrary_write_contract_is_gone(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("safe", encoding="utf-8")
    with TestClient(app) as client:
        response = client.post(
            "/v1/agent/undo",
            headers=AUTH,
            json={"path": str(victim), "workdir": str(tmp_path), "content": "forged"},
        )
    assert response.status_code == 410
    assert victim.read_text(encoding="utf-8") == "safe"


def test_endpoint_consumes_exact_receipt_once(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("before", encoding="utf-8")
    with TestClient(app) as client:
        token = app.state.undo_receipts.issue(
            workdir=str(tmp_path),
            path="victim.txt",
            before="before",
            after="after",
            existed=True,
        )
        victim.write_text("after", encoding="utf-8")
        restored = client.post(
            "/v1/agent/undo", headers=AUTH, json={"receipt": token, "content": "before"}
        )
        replay = client.post(
            "/v1/agent/undo", headers=AUTH, json={"receipt": token, "content": "before"}
        )

    assert restored.status_code == 200
    assert victim.read_text(encoding="utf-8") == "before"
    assert replay.status_code == 409
