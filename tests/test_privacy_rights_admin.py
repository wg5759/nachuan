from __future__ import annotations

import hashlib
import importlib

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from gateway import privacy_admin
from gateway.auth import require_api_key, require_approval_admin_key
from gateway.privacy_rights import PrivacyRightsLedger


SNAPSHOT_KEYS = {
    "request_id",
    "action",
    "state",
    "scope_sha256",
    "total_steps",
    "completed_steps",
    "unknown_steps",
    "retryable_steps",
    "permanent_error_steps",
    "not_applicable_steps",
    "ready_to_finalize",
    "created_at_ms",
    "updated_at_ms",
}


def _assert_content_free_snapshot(response) -> dict:  # noqa: ANN001
    document = response.json()
    assert set(document) == SNAPSHOT_KEYS
    serialized = str(document)
    assert "subject_digest" not in serialized
    assert "evidence_sha256" not in serialized
    assert "rejection_evidence" not in serialized
    return document


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _request_id(label: str = "request") -> str:
    return "dsr-v1:" + _digest(label)


def _receipt_id(label: str) -> str:
    return "receipt-v1:" + _digest(label)


def _app(
    tmp_path,
    *,
    with_ledger: bool = True,
    max_requests: int = 100_000,
) -> FastAPI:
    app = FastAPI()
    app.include_router(privacy_admin.router)
    app.dependency_overrides[require_api_key] = lambda: "runtime"
    app.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    if with_ledger:
        app.state.privacy_rights = PrivacyRightsLedger(
            tmp_path / "privacy-rights.db",
            max_requests=max_requests,
        )
    return app


def test_admin_lifecycle_requires_durable_receipts_and_returns_no_store(
    tmp_path,
) -> None:
    request_id = _request_id()
    with TestClient(_app(tmp_path)) as client:
        created = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": request_id,
                "action": "delete",
                "subject_digest": _digest("tenant/subject"),
            },
        )
        assert created.status_code == 200
        assert created.headers["cache-control"] == "no-store"
        assert _assert_content_free_snapshot(created)["state"] == "identity_pending"

        identity = client.post(
            f"/admin/privacy-rights/requests/{request_id}/identity",
            json={"evidence_sha256": _digest("identity-evidence")},
        )
        assert identity.status_code == 200
        _assert_content_free_snapshot(identity)

        scope = client.post(
            f"/admin/privacy-rights/requests/{request_id}/scope",
            json={
                "steps": [
                    {
                        "step_id": "erase-content",
                        "store_id": "conversations_and_summaries",
                        "operation": "erase",
                        "depends_on": [],
                    },
                    {
                        "step_id": "notify-processor",
                        "store_id": "conversations_and_summaries",
                        "operation": "notify_processor",
                        "depends_on": ["erase-content"],
                    },
                ]
            },
        )
        assert scope.status_code == 200
        assert _assert_content_free_snapshot(scope)["total_steps"] == 2

        started = client.post(
            f"/admin/privacy-rights/requests/{request_id}/start", json={}
        )
        assert started.status_code == 200
        _assert_content_free_snapshot(started)

        incomplete = client.post(
            f"/admin/privacy-rights/requests/{request_id}/finalize", json={}
        )
        assert incomplete.status_code == 409

        first = client.post(
            f"/admin/privacy-rights/requests/{request_id}/receipts",
            json={
                "step_id": "erase-content",
                "receipt_id": _receipt_id("erased"),
                "outcome": "completed",
                "evidence_sha256": _digest("erase-receipt"),
                "affected_count": 3,
            },
        )
        assert first.status_code == 200
        assert _assert_content_free_snapshot(first)["completed_steps"] == 1

        second = client.post(
            f"/admin/privacy-rights/requests/{request_id}/receipts",
            json={
                "step_id": "notify-processor",
                "receipt_id": _receipt_id("notified"),
                "outcome": "completed",
                "evidence_sha256": _digest("processor-receipt"),
            },
        )
        assert second.status_code == 200
        assert _assert_content_free_snapshot(second)["ready_to_finalize"] is True

        completed = client.post(
            f"/admin/privacy-rights/requests/{request_id}/finalize", json={}
        )
        assert completed.status_code == 200
        completed_document = _assert_content_free_snapshot(completed)
        assert completed_document["state"] == "completed"
        fetched = client.get(
            f"/admin/privacy-rights/requests/{request_id}"
        )
        assert _assert_content_free_snapshot(fetched) == completed_document


def test_authentication_and_ledger_gate_run_before_body_parsing(tmp_path) -> None:
    denied = FastAPI()
    denied.include_router(privacy_admin.router)

    def reject_runtime() -> str:
        raise HTTPException(status_code=401, detail="denied")

    denied.dependency_overrides[require_api_key] = reject_runtime
    denied.dependency_overrides[require_approval_admin_key] = lambda: "approval"
    with TestClient(denied) as client:
        response = client.post(
            "/admin/privacy-rights/requests",
            content=b"not-json-and-must-not-be-parsed",
        )
    assert response.status_code == 401

    with TestClient(_app(tmp_path, with_ledger=False)) as client:
        unavailable = client.post(
            "/admin/privacy-rights/requests",
            content=b"not-json-and-must-not-be-parsed",
        )
    assert unavailable.status_code == 503
    assert unavailable.headers["cache-control"] == "no-store"


def test_body_contract_is_bounded_closed_and_rejects_duplicate_keys(tmp_path) -> None:
    with TestClient(_app(tmp_path)) as client:
        extra = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": _request_id("extra"),
                "action": "delete",
                "subject_digest": _digest("subject"),
                "raw_customer_content": "must-not-enter",
            },
        )
        assert extra.status_code == 422

        duplicate = client.post(
            "/admin/privacy-rights/requests",
            content=(
                '{"request_id":"%s","request_id":"%s",'
                '"action":"delete","subject_digest":"%s"}'
                % (_request_id("one"), _request_id("two"), _digest("subject"))
            ).encode("ascii"),
            headers={"Content-Type": "application/json"},
        )
        assert duplicate.status_code == 422

        oversized = client.post(
            "/admin/privacy-rights/requests",
            content=b"{" + (b" " * (privacy_admin.MAX_BODY_BYTES + 1)),
            headers={"Content-Type": "application/json"},
        )
        assert oversized.status_code == 413


def test_isolated_unicode_surrogate_is_stable_422_not_response_encoding_500(
    tmp_path,
) -> None:
    request_id = _request_id("surrogate")
    app = _app(tmp_path)
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": request_id,
                "action": "delete",
                "subject_digest": _digest("subject"),
            },
        ).status_code == 200
        assert client.post(
            f"/admin/privacy-rights/requests/{request_id}/identity",
            json={"evidence_sha256": _digest("identity")},
        ).status_code == 200
        response = client.post(
            f"/admin/privacy-rights/requests/{request_id}/scope",
            content=(
                b'{"steps":[{"step_id":"s","store_id":"x",'
                b'"operation":"\\ud800"}]}'
            ),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"


def test_validation_not_found_and_conflict_have_stable_statuses(tmp_path) -> None:
    request_id = _request_id("errors")
    with TestClient(_app(tmp_path)) as client:
        invalid = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": "raw-ticket-id",
                "action": "delete",
                "subject_digest": _digest("subject"),
            },
        )
        assert invalid.status_code == 422

        missing = client.get(
            f"/admin/privacy-rights/requests/{_request_id('missing')}"
        )
        assert missing.status_code == 404

        assert client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": request_id,
                "action": "delete",
                "subject_digest": _digest("subject"),
            },
        ).status_code == 200
        conflict = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": request_id,
                "action": "export",
                "subject_digest": _digest("subject"),
            },
        )
        assert conflict.status_code == 409

        contradictory = client.post(
            f"/admin/privacy-rights/requests/{request_id}/receipts",
            json={
                "step_id": "blocked-step",
                "receipt_id": _receipt_id("contradictory-count"),
                "outcome": "not_applicable",
                "evidence_sha256": _digest("no-action-taken"),
                "affected_count": 5,
                "error_code": "dependency_permanent_error",
            },
        )
        assert contradictory.status_code == 422
        assert contradictory.headers["cache-control"] == "no-store"


def test_gateway_app_wires_privacy_router_and_dedicated_database(
    tmp_path,
    monkeypatch,
) -> None:
    gateway_app_module = importlib.import_module("gateway.app")
    public_fastapi_app = gateway_app_module._public_fastapi_app
    # Current FastAPI keeps included routers behind lazy _IncludedRouter
    # entries; the generated contract is the stable public route view.
    paths = set(public_fastapi_app.openapi()["paths"])
    assert "/admin/privacy-rights/requests" in paths
    assert "/admin/privacy-rights/requests/{request_id}/receipts" in paths

    marker = object()
    captured = {}

    def open_ledger(path):  # noqa: ANN001, ANN202
        captured["path"] = path
        return marker

    monkeypatch.setattr(privacy_admin, "PrivacyRightsLedger", open_ledger)
    assert privacy_admin.initialize_privacy_rights(tmp_path) is marker
    assert captured["path"] == tmp_path / "privacy_rights.db"


def test_request_capacity_is_stable_409_and_keeps_existing_request(tmp_path) -> None:
    first_id = _request_id("capacity-first")
    with TestClient(_app(tmp_path, max_requests=1)) as client:
        first = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": first_id,
                "action": "delete",
                "subject_digest": _digest("subject-one"),
            },
        )
        assert first.status_code == 200
        replay = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": first_id,
                "action": "delete",
                "subject_digest": _digest("subject-one"),
            },
        )
        assert replay.status_code == 200
        full = client.post(
            "/admin/privacy-rights/requests",
            json={
                "request_id": _request_id("capacity-second"),
                "action": "delete",
                "subject_digest": _digest("subject-two"),
            },
        )
        assert full.status_code == 409
        assert full.json()["detail"]["code"] == "privacy_rights_capacity"
        assert client.get(
            f"/admin/privacy-rights/requests/{first_id}"
        ).status_code == 200
