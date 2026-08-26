"""Persistent, browser-safe authentication for the single-owner local Web UI.

The CLI hands one short-lived bootstrap capability to the browser in a URL
fragment.  The fragment is posted once, then exchanged for host-only HttpOnly
cookies.  Cookie authentication is accepted only with an exact same-origin
custom header, so a cross-site form or image cannot exercise gateway APIs.
"""

from __future__ import annotations

import hmac
import json
import re
import threading
import time
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

WEB_SESSION_HEADER = "X-Nachuan-Web-Session"
BOOTSTRAP_ENV = "NACHUAN_LOCAL_WEB_BOOTSTRAP_TOKEN"
RUNTIME_COOKIE = "nachuan_local_runtime"
APPROVAL_COOKIE = "nachuan_local_approval"
LOCAL_WEB_HOST = "127.77.77.77"
COOKIE_MAX_AGE_SEC = 180 * 24 * 60 * 60
BOOTSTRAP_TTL_SEC = 120

_BOOTSTRAP = re.compile(r"^nc-web-bootstrap-v1-[A-Za-z0-9_-]{43,86}$")
_RUNTIME = re.compile(r"^nc-runtime-v1-[A-Za-z0-9_-]{43,86}$")
_APPROVAL = re.compile(r"^nc-approval-v1-[A-Za-z0-9_-]{43,86}$")


class LocalWebSessionRejected(ValueError):
    pass


def _single_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    if len(values) > 1:
        raise LocalWebSessionRejected("duplicate local Web session header")
    return values[0].strip() if values else None


def _session_cookie_values(request: Request) -> tuple[str | None, str | None]:
    headers = request.headers.getlist("cookie")
    if len(headers) > 1:
        raise LocalWebSessionRejected("duplicate Cookie header")
    runtime: str | None = None
    approval: str | None = None
    for segment in (headers[0].split(";") if headers else ()):
        if "=" not in segment:
            continue
        name, value = (item.strip() for item in segment.split("=", 1))
        if name == RUNTIME_COOKIE:
            if runtime is not None:
                raise LocalWebSessionRejected("duplicate runtime session cookie")
            runtime = value
        elif name == APPROVAL_COOKIE:
            if approval is not None:
                raise LocalWebSessionRejected("duplicate approval session cookie")
            approval = value
    if runtime is not None and _RUNTIME.fullmatch(runtime) is None:
        raise LocalWebSessionRejected("runtime session cookie is malformed")
    if approval is not None and _APPROVAL.fullmatch(approval) is None:
        raise LocalWebSessionRejected("approval session cookie is malformed")
    return runtime, approval


def _require_browser_session_request(
    request: Request,
    *,
    port: int,
    require_origin: bool,
) -> None:
    if (
        request.url.scheme != "http"
        or request.url.hostname != LOCAL_WEB_HOST
        or request.url.port != port
        or _single_header(request, WEB_SESSION_HEADER) != "1"
        or _single_header(request, "Sec-Fetch-Site") != "same-origin"
    ):
        raise LocalWebSessionRejected("local Web session request is not same-origin")
    origin = _single_header(request, "Origin")
    expected = f"http://{LOCAL_WEB_HOST}:{port}"
    if require_origin and origin != expected:
        raise LocalWebSessionRejected("local Web session origin is invalid")
    if origin is not None and origin != expected:
        raise LocalWebSessionRejected("local Web session origin drifted")


def local_web_runtime_cookie(
    request: Request | None,
    configured_keys: set[str],
    *,
    port: int,
) -> str | None:
    if request is None:
        return None
    runtime, _approval = _session_cookie_values(request)
    if runtime is None:
        return None
    _require_browser_session_request(request, port=port, require_origin=False)
    if not any(hmac.compare_digest(runtime, value) for value in configured_keys):
        raise LocalWebSessionRejected("local Web runtime session is invalid")
    return runtime


def local_web_approval_cookie(
    request: Request | None,
    configured_key: str,
    *,
    port: int,
) -> bool:
    if request is None:
        return False
    _runtime, approval = _session_cookie_values(request)
    if approval is None:
        return False
    _require_browser_session_request(request, port=port, require_origin=False)
    if not configured_key or not hmac.compare_digest(approval, configured_key):
        raise LocalWebSessionRejected("local Web approval session is invalid")
    return True


def _closed_json(payload: bytes) -> Mapping[str, Any]:
    if not 1 <= len(payload) <= 1024:
        raise LocalWebSessionRejected("local Web session body is invalid")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise LocalWebSessionRejected("local Web session JSON is invalid") from exc
    if not isinstance(value, Mapping):
        raise LocalWebSessionRejected("local Web session JSON must be an object")
    return value


class LocalWebSessionManager:
    def __init__(
        self,
        *,
        runtime_key: str,
        approval_key: str,
        bootstrap_token: str,
        port: int,
        now: float | None = None,
    ) -> None:
        if _RUNTIME.fullmatch(runtime_key) is None or _APPROVAL.fullmatch(approval_key) is None:
            raise ValueError("local Web owner credentials are invalid")
        if runtime_key == approval_key or _BOOTSTRAP.fullmatch(bootstrap_token) is None:
            raise ValueError("local Web bootstrap authority is invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("local Web session port is invalid")
        self.runtime_key = runtime_key
        self.approval_key = approval_key
        self.bootstrap_token = bootstrap_token
        self.port = port
        self._expires_at = (time.monotonic() if now is None else now) + BOOTSTRAP_TTL_SEC
        self._consumed = False
        self._lock = threading.Lock()

    def consume(self, candidate: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            if self._consumed or current > self._expires_at:
                return False
            if not hmac.compare_digest(candidate, self.bootstrap_token):
                return False
            self._consumed = True
            return True

    def browser_credentials(self, request: Request) -> tuple[bool, bool]:
        runtime, approval = _session_cookie_values(request)
        _require_browser_session_request(request, port=self.port, require_origin=False)
        runtime_ok = bool(runtime and hmac.compare_digest(runtime, self.runtime_key))
        approval_ok = bool(approval and hmac.compare_digest(approval, self.approval_key))
        return runtime_ok, approval_ok


def _cookie_response(
    payload: Mapping[str, object],
    manager: LocalWebSessionManager,
    *,
    include_approval: bool,
) -> JSONResponse:
    response = JSONResponse(dict(payload), headers={"Cache-Control": "no-store"})
    response.set_cookie(
        RUNTIME_COOKIE,
        manager.runtime_key,
        max_age=COOKIE_MAX_AGE_SEC,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    if include_approval:
        response.set_cookie(
            APPROVAL_COOKIE,
            manager.approval_key,
            max_age=COOKIE_MAX_AGE_SEC,
            httponly=True,
            secure=False,
            samesite="strict",
            path="/",
        )
    return response


def register_local_web_session_routes(
    app: FastAPI,
    *,
    manager: LocalWebSessionManager | None,
) -> None:
    app.state.local_web_session_manager = manager

    @app.get("/v1/local-web/session")
    async def local_web_session_status(request: Request) -> JSONResponse:
        if manager is None:
            return JSONResponse(
                {"authenticated": False, "approval": False},
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
        try:
            runtime_ok, approval_ok = manager.browser_credentials(request)
        except LocalWebSessionRejected:
            runtime_ok = approval_ok = False
        if not runtime_ok:
            return JSONResponse(
                {"authenticated": False, "approval": False},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        return _cookie_response(
            {"authenticated": True, "approval": approval_ok},
            manager,
            include_approval=approval_ok,
        )

    @app.post("/v1/local-web/session/bootstrap")
    async def local_web_session_bootstrap(request: Request) -> JSONResponse:
        if manager is None:
            return JSONResponse(
                {"authenticated": False, "approval": False},
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
        try:
            _require_browser_session_request(
                request,
                port=manager.port,
                require_origin=True,
            )
            body = _closed_json(await request.body())
            if set(body) != {"token"} or not isinstance(body.get("token"), str):
                raise LocalWebSessionRejected("local Web bootstrap body is not closed")
            accepted = manager.consume(str(body["token"]))
        except LocalWebSessionRejected:
            accepted = False
        if not accepted:
            return JSONResponse(
                {"authenticated": False, "approval": False},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        return _cookie_response(
            {"authenticated": True, "approval": True},
            manager,
            include_approval=True,
        )

    @app.post("/v1/local-web/session/adopt")
    async def local_web_session_adopt(request: Request) -> JSONResponse:
        if manager is None:
            return JSONResponse(
                {"authenticated": False, "approval": False},
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
        try:
            _require_browser_session_request(
                request,
                port=manager.port,
                require_origin=True,
            )
            authorization = _single_header(request, "Authorization") or ""
            approval = _single_header(request, "X-Nachuan-Approval-Key") or ""
            if not authorization.lower().startswith("bearer "):
                raise LocalWebSessionRejected("local Web adoption runtime key is missing")
            runtime = authorization.split(" ", 1)[1].strip()
            if not hmac.compare_digest(runtime, manager.runtime_key) or not hmac.compare_digest(
                approval, manager.approval_key
            ):
                raise LocalWebSessionRejected("local Web adoption credentials are invalid")
        except LocalWebSessionRejected:
            return JSONResponse(
                {"authenticated": False, "approval": False},
                status_code=401,
                headers={"Cache-Control": "no-store"},
            )
        return _cookie_response(
            {"authenticated": True, "approval": True},
            manager,
            include_approval=True,
        )


__all__ = [
    "APPROVAL_COOKIE",
    "BOOTSTRAP_ENV",
    "BOOTSTRAP_TTL_SEC",
    "COOKIE_MAX_AGE_SEC",
    "LOCAL_WEB_HOST",
    "LocalWebSessionManager",
    "LocalWebSessionRejected",
    "RUNTIME_COOKIE",
    "WEB_SESSION_HEADER",
    "local_web_approval_cookie",
    "local_web_runtime_cookie",
    "register_local_web_session_routes",
]
