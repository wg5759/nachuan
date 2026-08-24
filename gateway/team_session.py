"""Server-resolved identity boundary for the central team Web service."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from fastapi import APIRouter, Depends, HTTPException, Request, Response


SESSION_COOKIE_NAME = "__Host-nachuan-session"
_SESSION_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{32,192}$")


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated identity and active tenant selected by the server."""

    user_id: str
    active_organization_id: str
    session_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]


class TeamSessionStore(Protocol):
    """Resolve an opaque cookie digest without receiving the cookie secret."""

    def resolve_session(self, session_secret_sha256: str) -> Principal | None: ...


def _session_secret(request: Request) -> str:
    values: list[str] = []
    for header in request.headers.getlist("cookie"):
        for item in header.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == SESSION_COOKIE_NAME:
                values.append(value)
    if len(values) != 1 or _SESSION_SECRET_RE.fullmatch(values[0]) is None:
        raise HTTPException(
            status_code=401,
            detail="A valid team Web session is required.",
            headers={"Cache-Control": "no-store"},
        )
    return values[0]


def require_principal(request: Request) -> Principal:
    """Resolve the principal from a server-side session; never from request data."""

    store = getattr(request.app.state, "team_session_store", None)
    resolver = getattr(store, "resolve_session", None)
    if not callable(resolver):
        raise HTTPException(
            status_code=503,
            detail="Team Web session storage is unavailable.",
            headers={"Cache-Control": "no-store"},
        )
    secret = _session_secret(request)
    digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
    principal = resolver(digest)
    if not isinstance(principal, Principal):
        raise HTTPException(
            status_code=401,
            detail="A valid team Web session is required.",
            headers={"Cache-Control": "no-store"},
        )
    return principal


router = APIRouter(prefix="/v1")


@router.get("/session")
async def current_session(
    request: Request,
    response: Response,
    principal: Principal = Depends(require_principal),
) -> dict[str, object]:
    if request.query_params:
        raise HTTPException(
            status_code=422,
            detail="The session endpoint does not accept query parameters.",
            headers={"Cache-Control": "no-store"},
        )
    content_lengths = request.headers.getlist("content-length")
    if len(content_lengths) > 1:
        raise HTTPException(
            status_code=422,
            detail="The session endpoint does not accept a request body.",
            headers={"Cache-Control": "no-store"},
        )
    if content_lengths:
        try:
            body_length = int(content_lengths[0], 10)
        except (TypeError, ValueError, OverflowError) as exc:
            raise HTTPException(
                status_code=422,
                detail="The session endpoint does not accept a request body.",
                headers={"Cache-Control": "no-store"},
            ) from exc
        if body_length != 0:
            raise HTTPException(
                status_code=422,
                detail="The session endpoint does not accept a request body.",
                headers={"Cache-Control": "no-store"},
            )
    else:
        async for chunk in request.stream():
            if chunk:
                raise HTTPException(
                    status_code=422,
                    detail="The session endpoint does not accept a request body.",
                    headers={"Cache-Control": "no-store"},
                )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Vary"] = "Cookie"
    return {
        "user_id": principal.user_id,
        "active_organization_id": principal.active_organization_id,
        "session_id": principal.session_id,
        "roles": list(principal.roles),
        "permissions": list(principal.permissions),
    }


__all__ = [
    "Principal",
    "SESSION_COOKIE_NAME",
    "TeamSessionStore",
    "require_principal",
    "router",
]
