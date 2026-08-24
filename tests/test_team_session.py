from __future__ import annotations

import hashlib

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.team_session import (
    SESSION_COOKIE_NAME,
    Principal,
    router,
)


SESSION_SECRET = "session-secret-" + ("a" * 48)


class _SessionStore:
    def __init__(self, principal: Principal | None) -> None:
        self._principal = principal
        self.observed_digests: list[str] = []

    def resolve_session(self, session_secret_sha256: str) -> Principal | None:
        self.observed_digests.append(session_secret_sha256)
        return self._principal


def _app(store: _SessionStore) -> FastAPI:
    app = FastAPI()
    app.state.team_session_store = store
    app.include_router(router)
    return app


def _principal() -> Principal:
    return Principal(
        user_id="user-alice",
        active_organization_id="org-acme",
        session_id="session-public-123",
        roles=("member",),
        permissions=("chat.read", "chat.write"),
    )


def test_session_returns_only_server_resolved_principal() -> None:
    store = _SessionStore(_principal())
    with TestClient(_app(store)) as client:
        response = client.get(
            "/v1/session",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={SESSION_SECRET}"},
        )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["vary"] == "Cookie"
    assert response.json() == {
        "user_id": "user-alice",
        "active_organization_id": "org-acme",
        "session_id": "session-public-123",
        "roles": ["member"],
        "permissions": ["chat.read", "chat.write"],
    }
    assert store.observed_digests == [
        hashlib.sha256(SESSION_SECRET.encode("ascii")).hexdigest()
    ]
    assert SESSION_SECRET not in response.text


def test_query_identity_fields_cannot_override_server_principal() -> None:
    store = _SessionStore(_principal())
    with TestClient(_app(store)) as client:
        response = client.get(
            "/v1/session",
            params={
                "user_id": "user-mallory",
                "active_organization_id": "org-foreign",
            },
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={SESSION_SECRET}"},
        )

    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"
    assert "user-mallory" not in response.text
    assert "org-foreign" not in response.text


def test_body_identity_fields_cannot_override_server_principal() -> None:
    store = _SessionStore(_principal())
    with TestClient(_app(store)) as client:
        response = client.request(
            "GET",
            "/v1/session",
            json={
                "user_id": "user-mallory",
                "active_organization_id": "org-foreign",
            },
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={SESSION_SECRET}"},
        )

    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"
    assert "user-mallory" not in response.text
    assert "org-foreign" not in response.text


def test_missing_or_unknown_server_session_is_rejected_without_secret_leak() -> None:
    store = _SessionStore(None)
    with TestClient(_app(store)) as client:
        missing = client.get(
            "/v1/session",
            headers={"Authorization": "Bearer test-key"},
        )
        unknown = client.get(
            "/v1/session",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={SESSION_SECRET}"},
        )

    for response in (missing, unknown):
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"
        assert SESSION_SECRET not in response.text


def test_gateway_registers_team_session_route_but_fails_closed_without_store() -> None:
    from gateway.app import app

    app.state.team_session_store = None
    with TestClient(app) as client:
        response = client.get(
            "/v1/session",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={SESSION_SECRET}"},
        )

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert SESSION_SECRET not in response.text
