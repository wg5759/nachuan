"""Cloud mutation endpoints belong to the independent approval-admin domain."""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.app import app


RUNTIME = {"Authorization": "Bearer test-key"}


def test_runtime_bearer_cannot_change_cloud_state(approval_auth_headers):
    del approval_auth_headers  # fixture configures an independent authority
    requests = (
        ("/v1/sync/config", {"url": "https://demo.supabase.co", "anon_key": "anon"}),
        ("/v1/sync/signup", {"email": "owner@example.com", "password": "secret"}),
        ("/v1/sync/login", {"email": "owner@example.com", "password": "secret"}),
        ("/v1/sync/toggle", {"enabled": True}),
        ("/v1/sync/run", {}),
    )
    with TestClient(app) as client:
        for path, body in requests:
            response = client.post(path, headers=RUNTIME, json=body)
            assert response.status_code == 401, path
