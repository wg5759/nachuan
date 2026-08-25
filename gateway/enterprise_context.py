"""Fail-closed enterprise identity boundary for the future knowledge_v2 API."""

from __future__ import annotations

import inspect
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from fastapi import HTTPException, Request


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ATTRIBUTE_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_MAX_GROUPS = 128
_MAX_ROLES = 64
_MAX_ATTRIBUTES = 64


class EnterpriseContextError(ValueError):
    pass


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseContextError(f"{field} is invalid")
    return value


def _identifiers(value: object, field: str, limit: int) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, frozenset)) or len(value) > limit:
        raise EnterpriseContextError(f"{field} is invalid")
    normalized = tuple(sorted({_identifier(item, field) for item in value}))
    if len(normalized) != len(value):
        raise EnterpriseContextError(f"{field} contains duplicates")
    return normalized


def _attributes(value: object) -> Mapping[str, str | int | bool]:
    if not isinstance(value, Mapping) or len(value) > _MAX_ATTRIBUTES:
        raise EnterpriseContextError("attributes are invalid")
    normalized: dict[str, str | int | bool] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or _ATTRIBUTE_KEY.fullmatch(raw_key) is None:
            raise EnterpriseContextError("attribute key is invalid")
        if isinstance(raw_value, bool):
            normalized[raw_key] = raw_value
        elif isinstance(raw_value, int) and not isinstance(raw_value, bool):
            if not -(2**31) <= raw_value <= 2**31 - 1:
                raise EnterpriseContextError("attribute integer is out of range")
            normalized[raw_key] = raw_value
        elif isinstance(raw_value, str) and 1 <= len(raw_value) <= 256:
            normalized[raw_key] = raw_value
        else:
            raise EnterpriseContextError("attribute value is invalid")
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class EnterpriseRequestContext:
    tenant_id: str
    subject_id: str
    session_id: str
    groups: tuple[str, ...]
    roles: tuple[str, ...]
    attributes: Mapping[str, str | int | bool]
    purpose: str
    device_trust: str
    region: str
    policy_epoch: int
    session_epoch: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _identifier(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "subject_id", _identifier(self.subject_id, "subject_id"))
        object.__setattr__(self, "session_id", _identifier(self.session_id, "session_id"))
        object.__setattr__(self, "groups", _identifiers(self.groups, "groups", _MAX_GROUPS))
        object.__setattr__(self, "roles", _identifiers(self.roles, "roles", _MAX_ROLES))
        object.__setattr__(self, "attributes", _attributes(self.attributes))
        object.__setattr__(self, "purpose", _identifier(self.purpose, "purpose"))
        object.__setattr__(
            self, "device_trust", _identifier(self.device_trust, "device_trust")
        )
        object.__setattr__(self, "region", _identifier(self.region, "region"))
        for field in ("policy_epoch", "session_epoch"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise EnterpriseContextError(f"{field} is invalid")


EnterpriseContextResolver = Callable[
    [Request], EnterpriseRequestContext | Awaitable[EnterpriseRequestContext]
]


async def require_enterprise_context(request: Request) -> EnterpriseRequestContext:
    """Resolve context only through a trusted app-owned verifier.

    This function intentionally reads no tenant, subject, role, group or epoch
    header itself. A reverse proxy header is still attacker input until an
    application-owned resolver verifies its signature/session and constructs
    :class:`EnterpriseRequestContext`.
    """

    resolver: Any = getattr(request.app.state, "enterprise_context_resolver", None)
    if not callable(resolver):
        raise HTTPException(status_code=503, detail="enterprise_identity_unavailable")
    try:
        context = resolver(request)
        if inspect.isawaitable(context):
            context = await context
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="enterprise_identity_unavailable"
        ) from exc
    if not isinstance(context, EnterpriseRequestContext):
        raise HTTPException(status_code=503, detail="enterprise_identity_unavailable")
    return context


__all__ = [
    "EnterpriseContextError",
    "EnterpriseContextResolver",
    "EnterpriseRequestContext",
    "require_enterprise_context",
]
