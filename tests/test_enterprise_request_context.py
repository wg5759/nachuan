from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.auth import require_api_key
from gateway.enterprise_context import (
    EnterpriseContextError,
    EnterpriseRequestContext,
)
from gateway.enterprise_rag import router


def _context() -> EnterpriseRequestContext:
    return EnterpriseRequestContext(
        tenant_id="tenant-a",
        subject_id="user-a",
        session_id="session-a",
        groups=("project-red",),
        roles=("employee",),
        attributes={"department": "sales", "clearance": 2},
        purpose="customer_support",
        device_trust="managed",
        region="cn-east",
        policy_epoch=7,
        session_epoch=3,
    )


def _app(resolver=...):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_api_key] = lambda: "runtime"
    if resolver is not ...:
        app.state.enterprise_context_resolver = resolver
    return app


def test_context_is_frozen_and_canonical() -> None:
    context = _context()

    assert context.groups == ("project-red",)
    assert context.attributes["clearance"] == 2
    with pytest.raises(FrozenInstanceError):
        context.tenant_id = "tenant-b"  # type: ignore[misc]
    with pytest.raises(TypeError):
        context.attributes["clearance"] = 9  # type: ignore[index]


@pytest.mark.parametrize(
    "change",
    [
        {"tenant_id": ""},
        {"groups": ("dup", "dup")},
        {"attributes": {"bad key": "value"}},
        {"policy_epoch": 0},
        {"session_epoch": True},
    ],
)
def test_context_rejects_ambiguous_or_nonmonotonic_fields(change) -> None:
    values = {
        "tenant_id": "tenant-a",
        "subject_id": "user-a",
        "session_id": "session-a",
        "groups": (),
        "roles": (),
        "attributes": {},
        "purpose": "support",
        "device_trust": "managed",
        "region": "cn-east",
        "policy_epoch": 1,
        "session_epoch": 1,
    }
    values.update(change)
    with pytest.raises(EnterpriseContextError):
        EnterpriseRequestContext(**values)


def test_missing_or_untrusted_resolver_fails_closed() -> None:
    with TestClient(_app()) as client:
        missing = client.post("/v1/enterprise/kb/query", json={"query": "hello"})
    with TestClient(_app(lambda _request: {"tenant_id": "forged"})) as client:
        untrusted = client.post("/v1/enterprise/kb/query", json={"query": "hello"})

    assert missing.status_code == 503
    assert missing.json()["detail"] == "enterprise_identity_unavailable"
    assert untrusted.status_code == 503
    assert untrusted.json()["detail"] == "enterprise_identity_unavailable"


def test_client_cannot_override_identity_fields() -> None:
    with TestClient(_app(lambda _request: _context())) as client:
        response = client.post(
            "/v1/enterprise/kb/query",
            json={
                "query": "hello",
                "tenant_id": "tenant-b",
                "subject_id": "user-b",
                "roles": ["admin"],
                "policy_epoch": 999,
            },
        )

    assert response.status_code == 422


def test_verified_identity_never_falls_back_to_personal_kb() -> None:
    with TestClient(_app(lambda _request: _context())) as client:
        response = client.post(
            "/v1/enterprise/kb/query", json={"query": "hello", "k": 5}
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "enterprise_rag_not_ready"


def test_production_gateway_mounts_the_fail_closed_enterprise_route() -> None:
    from gateway.app import _public_fastapi_app

    operation = _public_fastapi_app.openapi()["paths"]["/v1/enterprise/kb/query"]
    assert set(operation) == {"post"}
