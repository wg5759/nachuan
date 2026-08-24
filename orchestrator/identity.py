"""Fail-closed identities for multi-model collaboration.

Display names are user-controlled aliases and therefore cannot prove that two
reviewers are independent.  The router binds every route to both a non-secret,
hashed runtime domain (HTTP target or local CLI login domain) and a closed-set
model family.  A workflow also requires the model identifier returned by the
provider response to match the route's upstream identifier or a provider-owned
alias rule.  Missing evidence never grants a vote.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from gateway.model_identity import canonical_model_id


_DOMAIN_RE = re.compile(r"sha256:[0-9a-f]{64}")
_FAMILY_RE = re.compile(r"[a-z0-9][a-z0-9:._-]{0,127}")


def _clean(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if text and len(text) <= 512 else None


def normalize_independence_domain(value: Any) -> str | None:
    domain = _clean(value)
    if domain is None or not _DOMAIN_RE.fullmatch(domain.casefold()):
        return None
    return domain.casefold()


def normalize_model_family(value: Any) -> str | None:
    family = _clean(value)
    if family is None or not _FAMILY_RE.fullmatch(family.casefold()):
        return None
    return family.casefold()


def observed_model_from_response(response: Any) -> str | None:
    """Read the provider-returned model identifier without trusting aliases."""

    if not isinstance(response, dict):
        return None
    return _clean(response.get("model"))


def independence_domain_from_route(route: Any) -> str | None:
    """Return only a validated opaque domain; never expose a URL or credential."""

    domain = _clean(getattr(route, "independence_domain", None))
    if domain is None:
        domain = _clean(
            getattr(getattr(route, "provider", None), "independence_domain", None)
        )
    return normalize_independence_domain(domain)


@dataclass(frozen=True)
class RouteModelEvidence:
    reported_model: str | None
    observed_model: str | None
    model_family: str | None
    error: str | None


def verified_route_model_evidence(
    route: Any,
    response: Any,
) -> RouteModelEvidence:
    """Verify response.model against the actual route, failing closed on doubt."""

    reported = observed_model_from_response(response)
    if reported is None:
        return RouteModelEvidence(None, None, None, "missing_observed_model")
    upstream = _clean(getattr(route, "upstream_model", None))
    if upstream is None:
        return RouteModelEvidence(reported, None, None, "missing_upstream_model")

    provider = getattr(route, "provider", None)
    verifier = getattr(provider, "verify_model_identity", None)
    if not callable(verifier):
        return RouteModelEvidence(reported, None, None, "missing_model_verifier")
    try:
        verified = verifier(upstream, reported)
    except Exception:  # noqa: BLE001 - identity verification never grants on error
        verified = None
    if verified is None:
        error = (
            "unknown_model_family"
            if canonical_model_id(upstream) == canonical_model_id(reported)
            else "observed_model_mismatch"
        )
        return RouteModelEvidence(reported, None, None, error)

    observed, family_value = verified
    # Provider reports stay available separately as ``reported_model``.  The
    # verified identity is canonical so harmless response casing differences
    # cannot look like a mid-workflow model swap.
    observed = canonical_model_id(observed)
    family = normalize_model_family(family_value)
    expected_family = normalize_model_family(getattr(route, "model_family", None))
    if observed is None or family is None:
        return RouteModelEvidence(reported, None, None, "unknown_model_family")
    if expected_family is not None and expected_family != family:
        return RouteModelEvidence(reported, None, None, "model_family_mismatch")
    return RouteModelEvidence(reported, observed, family, None)


@dataclass(frozen=True)
class WorkflowIdentity:
    actual_model: str | None
    provider: str | None
    upstream_model: str | None
    observed_model: str | None
    model_family: str | None
    independence_domain: str | None

    @property
    def known(self) -> bool:
        return bool(
            self.actual_model
            and self.provider
            and self.upstream_model
            and self.observed_model
            and self.model_family
            and self.independence_domain
        )


def identity_from_call(call: dict[str, Any]) -> WorkflowIdentity:
    domain = normalize_independence_domain(call.get("independence_domain"))
    identity_error = _clean(call.get("model_identity_error"))
    return WorkflowIdentity(
        actual_model=_clean(call.get("actual_model")),
        provider=_clean(call.get("provider")),
        upstream_model=canonical_model_id(call.get("upstream_model")),
        observed_model=(
            None
            if identity_error
            else canonical_model_id(call.get("observed_model"))
        ),
        model_family=(
            None
            if identity_error
            else normalize_model_family(call.get("model_family"))
        ),
        independence_domain=domain,
    )


def identities_collide(left: WorkflowIdentity, right: WorkflowIdentity) -> bool:
    """Unknown identities collide; both runtime domain and family must differ.

    Virtual routes and provider display names are receipt metadata only.  A
    provider-reported model can deny authority, but can grant it only after it
    is bound to the route upstream by a strict provider-owned verifier.
    """

    if not left.known or not right.known:
        return True
    return bool(
        left.independence_domain == right.independence_domain
        or left.model_family == right.model_family
    )


def calls_collide(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return identities_collide(identity_from_call(left), identity_from_call(right))


def call_identity_known(call: dict[str, Any]) -> bool:
    return identity_from_call(call).known
