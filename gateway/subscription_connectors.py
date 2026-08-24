"""Public, secret-free discovery surface for user-owned CLI subscriptions."""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Any, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from gateway.auth import require_api_key
from gateway.codex_subscription_worker import CodexSubscriptionWorker
from gateway.subscription_cli_discovery import SubscriptionCliDiscovery


_STATES = frozenset(
    {
        "not_installed",
        "untrusted_binary",
        "version_unsupported",
        "installed_unprobed",
        "logged_out",
        "login_pending",
        "authenticated_unprobed",
        "ready",
        "reauth_required",
        "entitlement_denied",
        "degraded",
        "unavailable",
    }
)
_AUTH = frozenset({"device_code"})
_TRANSPORTS = frozenset({"stdio_jsonl", "acp_stdio"})
_CAPABILITIES = frozenset({"chat", "code"})


class SubscriptionConnectorRegistry(Protocol):
    def list_public(self) -> list[dict[str, object]]: ...


class _DefaultRegistry:
    def list_public(self) -> list[dict[str, object]]:
        # Only explicit path+digest attestations are considered.  Discovery
        # ignores PATH.  Once Codex is attested, the contained worker may ask
        # the official CLI for its public login state; Nachuan still never
        # reads the CLI's auth store.
        environment = dict(os.environ)
        connectors = SubscriptionCliDiscovery(
            environment=environment
        ).list_public()
        if connectors and connectors[0].get("state") == "installed_unprobed":
            connectors[0]["state"] = CodexSubscriptionWorker(
                environment=environment
            ).probe_status()
        return connectors


def _bounded_text(value: object, *, maximum: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ValueError("invalid public connector text")
    return text


def _closed_capabilities(value: object) -> list[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        raise ValueError("invalid connector capabilities")
    capabilities = [str(item).strip() for item in value]
    if (
        not capabilities
        or len(capabilities) > len(_CAPABILITIES)
        or len(set(capabilities)) != len(capabilities)
        or any(item not in _CAPABILITIES for item in capabilities)
    ):
        raise ValueError("invalid connector capabilities")
    return capabilities


def _public_projection(raw: object) -> dict[str, object]:
    if not isinstance(raw, Mapping):
        raise ValueError("invalid connector descriptor")
    connector_id = _bounded_text(raw.get("id"), maximum=64)
    label = _bounded_text(raw.get("label"), maximum=80)
    state = _bounded_text(raw.get("state"), maximum=32)
    auth = _bounded_text(raw.get("auth"), maximum=32)
    transport = _bounded_text(raw.get("transport"), maximum=32)
    if state not in _STATES or auth not in _AUTH or transport not in _TRANSPORTS:
        raise ValueError("unsupported connector descriptor")
    raw_version = raw.get("version")
    version = None if raw_version is None else _bounded_text(raw_version, maximum=64)
    if not isinstance(raw.get("login_supported"), bool) or not isinstance(
        raw.get("logout_supported"), bool
    ):
        raise ValueError("invalid connector capability flags")
    return {
        "id": connector_id,
        "label": label,
        "state": state,
        "auth": auth,
        "transport": transport,
        "version": version,
        "capabilities": _closed_capabilities(raw.get("capabilities")),
        "login_supported": raw["login_supported"],
        "logout_supported": raw["logout_supported"],
    }


router = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)])


@router.get("/subscription-connectors")
async def list_subscription_connectors(request: Request, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    registry = getattr(request.app.state, "subscription_connectors", None)
    if registry is None:
        registry = _DefaultRegistry()
    try:
        connectors = [_public_projection(item) for item in registry.list_public()]
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="订阅连接器状态不可用",
            headers={"Cache-Control": "no-store"},
        ) from exc
    return {"connectors": connectors}


__all__ = ["SubscriptionConnectorRegistry", "router"]
