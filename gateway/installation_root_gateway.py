"""Outermost raw-ASGI boundary for the private Installation Root protocol.

The private protocol must see the original ASGI ``raw_path`` and raw header
list before FastAPI routing or user middleware can normalize either value.
This wrapper therefore sits outside the public application and delegates only
the seven byte-exact frozen paths to the authenticated dispatcher.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from gateway.installation_root import (
    InstallationRoot,
    default_installation_root_path,
)
from gateway.installation_root_api import (
    ERROR_SCHEMA,
    INSTALLATION_ROOT_ROUTES,
    create_installation_root_dispatcher,
)


_BOOT_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_RAW_INSTALLATION_ROOT_PATHS = frozenset(
    path.encode("ascii") for path in INSTALLATION_ROOT_ROUTES
)
_INSTALLATION_ROOT_PREFIX = "/internal/v1/installation-root"
_RAW_INSTALLATION_ROOT_PREFIX = _INSTALLATION_ROOT_PREFIX.encode("ascii")
_UNAVAILABLE_BODY = json.dumps(
    {"schema": ERROR_SCHEMA, "code": "root_unavailable"},
    ensure_ascii=True,
    separators=(",", ":"),
).encode("ascii")
_INVALID_PATH_BODY = json.dumps(
    {"schema": ERROR_SCHEMA, "code": "invalid_request"},
    ensure_ascii=True,
    separators=(",", ":"),
).encode("ascii")


def _has_private_prefix(value: object, prefix: str | bytes) -> bool:
    """Recognize only the reserved path-segment boundary, never lookalikes."""

    if isinstance(prefix, bytes):
        return type(value) is bytes and (
            value == prefix or value.startswith(prefix + b"/")
        )
    return isinstance(value, str) and (
        value == prefix or value.startswith(prefix + "/")
    )


async def _send_fixed_error(send: Any, *, status: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        }
    )


def _strict_root_provider() -> InstallationRoot:
    """Open and validate the one installer-owned root on every request."""

    return InstallationRoot.open(default_installation_root_path())


class _UnavailablePrivateDispatcher:
    """Fixed fail-closed response used when this boot has no valid HMAC key."""

    async def __call__(self, _scope: Any, _receive: Any, send: Any) -> None:
        await _send_fixed_error(send, status=503, body=_UNAVAILABLE_BODY)


class InstallationRootGatewayApp:
    """Proxy public app attributes while owning the outer raw-ASGI dispatch."""

    def __init__(self, downstream: Any) -> None:
        self._downstream = downstream
        # Capture exactly once for this process boot.  No argument, config file,
        # bearer credential or request value is accepted as a substitute.
        boot_token = os.environ.get("NACHUAN_ENGINE_BOOT_TOKEN", "")
        if _BOOT_TOKEN_RE.fullmatch(boot_token) is None:
            self._private_dispatcher: Any = _UnavailablePrivateDispatcher()
        else:
            self._private_dispatcher = create_installation_root_dispatcher(
                root=_strict_root_provider,
                boot_token=boot_token,
            )

    def __getattr__(self, name: str) -> Any:
        # TestClient, OpenAPI tooling and existing callers continue to observe
        # the real FastAPI state/router without moving the private routes into it.
        return getattr(self._downstream, name)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        raw_path = scope.get("raw_path") if scope.get("type") == "http" else None
        if type(raw_path) is bytes and raw_path in _RAW_INSTALLATION_ROOT_PATHS:
            await self._private_dispatcher(scope, receive, send)
            return
        if scope.get("type") == "http" and (
            _has_private_prefix(raw_path, _RAW_INSTALLATION_ROOT_PREFIX)
            or _has_private_prefix(scope.get("path"), _INSTALLATION_ROOT_PREFIX)
        ):
            # Decoded aliases are considered only for rejection.  Dispatch is
            # exclusively by one of the seven byte-exact raw paths above.
            await _send_fixed_error(send, status=400, body=_INVALID_PATH_BODY)
            return
        await self._downstream(scope, receive, send)


__all__ = ["InstallationRootGatewayApp"]
