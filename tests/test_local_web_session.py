from __future__ import annotations

from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import gateway.auth as auth
from gateway.local_web_session import (
    APPROVAL_COOKIE,
    RUNTIME_COOKIE,
    LocalWebSessionManager,
    register_local_web_session_routes,
)

PORT = 18080
ORIGIN = f"http://127.77.77.77:{PORT}"
RUNTIME = f"nc-runtime-v1-{'R' * 43}"
APPROVAL = f"nc-approval-v1-{'A' * 43}"
BOOTSTRAP = f"nc-web-bootstrap-v1-{'B' * 43}"


def _browser_headers(*, origin: bool = False) -> dict[str, str]:
    return {
        "X-Nachuan-Web-Session": "1",
        "Sec-Fetch-Site": "same-origin",
        **({"Origin": ORIGIN} if origin else {}),
    }


def _session_app() -> FastAPI:
    app = FastAPI()
    register_local_web_session_routes(
        app,
        manager=LocalWebSessionManager(
            runtime_key=RUNTIME,
            approval_key=APPROVAL,
            bootstrap_token=BOOTSTRAP,
            port=PORT,
        ),
    )
    return app


def test_one_time_fragment_exchange_sets_renewable_httponly_host_cookies() -> None:
    with TestClient(_session_app(), base_url=ORIGIN) as client:
        response = client.post(
            "/v1/local-web/session/bootstrap",
            json={"token": BOOTSTRAP},
            headers=_browser_headers(origin=True),
        )
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "approval": True}
        cookies = response.headers.get_list("set-cookie")
        assert len(cookies) == 2
        assert all("HttpOnly" in item and "SameSite=strict" in item for item in cookies)
        assert all("Domain=" not in item for item in cookies)
        assert BOOTSTRAP not in response.text

        status = client.get(
            "/v1/local-web/session",
            headers=_browser_headers(),
        )
        assert status.status_code == 200
        assert status.json() == {"authenticated": True, "approval": True}
        assert len(status.headers.get_list("set-cookie")) == 2

        replay = client.post(
            "/v1/local-web/session/bootstrap",
            json={"token": BOOTSTRAP},
            headers=_browser_headers(origin=True),
        )
        assert replay.status_code == 401


def test_bootstrap_rejects_cross_site_missing_origin_duplicates_and_expiry() -> None:
    app = _session_app()
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.post(
            "/v1/local-web/session/bootstrap",
            json={"token": BOOTSTRAP},
            headers={"X-Nachuan-Web-Session": "1", "Sec-Fetch-Site": "cross-site"},
        ).status_code == 401
        assert client.post(
            "/v1/local-web/session/bootstrap",
            content='{"token":"one","token":"two"}',
            headers={
                **_browser_headers(origin=True),
                "Content-Type": "application/json",
            },
        ).status_code == 401

    manager = LocalWebSessionManager(
        runtime_key=RUNTIME,
        approval_key=APPROVAL,
        bootstrap_token=BOOTSTRAP,
        port=PORT,
        now=100.0,
    )
    assert manager.consume(BOOTSTRAP, now=221.0) is False


def test_manual_adoption_persists_both_keys_without_putting_them_in_body_or_url() -> None:
    with TestClient(_session_app(), base_url=ORIGIN) as client:
        response = client.post(
            "/v1/local-web/session/adopt",
            headers={
                **_browser_headers(origin=True),
                "Authorization": f"Bearer {RUNTIME}",
                "X-Nachuan-Approval-Key": APPROVAL,
            },
        )
        assert response.status_code == 200
        assert RUNTIME not in response.text
        assert APPROVAL not in response.text
        assert RUNTIME not in str(response.request.url)
        assert APPROVAL not in str(response.request.url)


def test_cookie_session_authenticates_runtime_and_approval_but_only_on_exact_origin(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(
            api_keys={RUNTIME},
            approval_admin_key=APPROVAL,
            gateway_port=PORT,
        ),
    )
    monkeypatch.setattr(auth, "desktop_engine_keys", lambda: set())
    app = FastAPI()

    @app.get("/protected")
    async def protected(
        _runtime: str = Depends(auth.require_api_key),
        _approval: str = Depends(auth.require_approval_admin_key),
    ) -> dict[str, bool]:
        return {"ok": True}

    cookie = f"{RUNTIME_COOKIE}={RUNTIME}; {APPROVAL_COOKIE}={APPROVAL}"
    with TestClient(app, base_url=ORIGIN) as client:
        accepted = client.get(
            "/protected",
            headers={**_browser_headers(), "Cookie": cookie},
        )
        assert accepted.status_code == 200
        assert accepted.json() == {"ok": True}

        conflict = client.get(
            "/protected",
            headers={
                **_browser_headers(),
                "Cookie": cookie,
                "Authorization": "Bearer foreign-key",
            },
        )
        assert conflict.status_code == 400

    with TestClient(app, base_url=f"http://127.0.0.1:{PORT}") as client:
        rejected = client.get(
            "/protected",
            headers={**_browser_headers(), "Cookie": cookie},
        )
        assert rejected.status_code == 401


def test_cookie_auth_requires_custom_same_origin_fetch_header(monkeypatch) -> None:
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(
            api_keys={RUNTIME},
            approval_admin_key=APPROVAL,
            gateway_port=PORT,
        ),
    )
    monkeypatch.setattr(auth, "desktop_engine_keys", lambda: set())
    app = FastAPI()

    @app.get("/runtime")
    async def runtime(_runtime: str = Depends(auth.require_api_key)) -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, base_url=ORIGIN) as client:
        response = client.get(
            "/runtime",
            headers={"Cookie": f"{RUNTIME_COOKIE}={RUNTIME}"},
        )
        assert response.status_code == 401
