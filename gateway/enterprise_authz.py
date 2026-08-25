"""Fail-closed relationship plus attribute authorization facade for enterprise RAG."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .enterprise_context import EnterpriseRequestContext


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_RESOURCES = 512
_MAX_REASON_CODES = 32
_MAX_OBLIGATIONS = 32


class EnterpriseAuthorizationError(ValueError):
    pass


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EnterpriseAuthorizationError(f"{field} is invalid")
    return value


def _identifiers(value: object, field: str, limit: int) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list, frozenset)) or len(value) > limit:
        raise EnterpriseAuthorizationError(f"{field} is invalid")
    normalized = tuple(sorted({_identifier(item, field) for item in value}))
    if len(normalized) != len(value):
        raise EnterpriseAuthorizationError(f"{field} contains duplicates")
    return normalized


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EnterpriseAuthorizationResource:
    tenant_id: str
    resource_type: str
    resource_id: str
    policy_id: str
    policy_epoch: int
    classification: int

    def __post_init__(self) -> None:
        for field in ("tenant_id", "resource_type", "resource_id", "policy_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise EnterpriseAuthorizationError("policy_epoch is invalid")
        if (
            isinstance(self.classification, bool)
            or not isinstance(self.classification, int)
            or not 0 <= self.classification <= 10
        ):
            raise EnterpriseAuthorizationError("classification is invalid")

    @property
    def resource_key(self) -> tuple[str, str]:
        return self.resource_type, self.resource_id


@dataclass(frozen=True, slots=True)
class EnterprisePolicyComponentDecision:
    resource_type: str
    resource_id: str
    policy_id: str
    allowed: bool
    policy_epoch: int
    engine_version: str
    reason_codes: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field in ("resource_type", "resource_id", "policy_id", "engine_version"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        if not isinstance(self.allowed, bool):
            raise EnterpriseAuthorizationError("allowed is invalid")
        if (
            isinstance(self.policy_epoch, bool)
            or not isinstance(self.policy_epoch, int)
            or self.policy_epoch < 1
        ):
            raise EnterpriseAuthorizationError("policy_epoch is invalid")
        object.__setattr__(
            self,
            "reason_codes",
            _identifiers(self.reason_codes, "reason_codes", _MAX_REASON_CODES),
        )
        object.__setattr__(
            self,
            "obligations",
            _identifiers(self.obligations, "obligations", _MAX_OBLIGATIONS),
        )
        if self.allowed and self.reason_codes:
            raise EnterpriseAuthorizationError("allowed component has deny reasons")
        if not self.allowed and not self.reason_codes:
            raise EnterpriseAuthorizationError("denied component has no reason")

    @property
    def resource_key(self) -> tuple[str, str]:
        return self.resource_type, self.resource_id


class EnterprisePolicyEvaluator(Protocol):
    def batch_check(
        self,
        *,
        context: EnterpriseRequestContext,
        resources: tuple[EnterpriseAuthorizationResource, ...],
        deadline_monotonic: float,
    ) -> Sequence[EnterprisePolicyComponentDecision]: ...


@dataclass(frozen=True, slots=True)
class EnterpriseAuthorizationDecision:
    resource_type: str
    resource_id: str
    allowed: bool
    policy_epoch: int
    reason_codes: tuple[str, ...]
    obligations: tuple[str, ...]
    component_versions: tuple[str, ...]
    subject_scope_fingerprint: str
    decision_id: str


class EnterpriseAuthorizationFacade:
    """Intersect ReBAC and ABAC decisions and emit pseudonymous receipts."""

    def __init__(
        self,
        *,
        relationship_evaluator: EnterprisePolicyEvaluator,
        attribute_evaluator: EnterprisePolicyEvaluator,
        audit_key: bytes,
        timeout_seconds: float = 1.0,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ):
        if not callable(getattr(relationship_evaluator, "batch_check", None)):
            raise EnterpriseAuthorizationError("relationship evaluator is invalid")
        if not callable(getattr(attribute_evaluator, "batch_check", None)):
            raise EnterpriseAuthorizationError("attribute evaluator is invalid")
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise EnterpriseAuthorizationError("audit_key is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.001 <= float(timeout_seconds) <= 30.0
        ):
            raise EnterpriseAuthorizationError("timeout_seconds is invalid")
        if not callable(monotonic_clock):
            raise EnterpriseAuthorizationError("monotonic_clock is invalid")
        self._relationship = relationship_evaluator
        self._attribute = attribute_evaluator
        self._audit_key = bytes(audit_key)
        self._timeout_seconds = float(timeout_seconds)
        self._clock = monotonic_clock

    def batch_check(
        self,
        context: EnterpriseRequestContext,
        resources: Iterable[EnterpriseAuthorizationResource],
    ) -> tuple[EnterpriseAuthorizationDecision, ...]:
        if not isinstance(context, EnterpriseRequestContext):
            raise EnterpriseAuthorizationError("context is invalid")
        requested = tuple(resources)
        if not requested or len(requested) > _MAX_RESOURCES:
            raise EnterpriseAuthorizationError("resources are invalid")
        keys = [resource.resource_key for resource in requested]
        if len(set(keys)) != len(keys):
            raise EnterpriseAuthorizationError("resources contain duplicates")

        subject_fingerprint = self._subject_fingerprint(context)
        results: dict[tuple[str, str], EnterpriseAuthorizationDecision] = {}
        eligible: list[EnterpriseAuthorizationResource] = []
        for resource in requested:
            if resource.tenant_id != context.tenant_id:
                results[resource.resource_key] = self._deny(
                    context,
                    resource,
                    subject_fingerprint,
                    ("tenant_mismatch",),
                )
            elif resource.policy_epoch != context.policy_epoch:
                results[resource.resource_key] = self._deny(
                    context,
                    resource,
                    subject_fingerprint,
                    ("policy_epoch_mismatch",),
                )
            else:
                eligible.append(resource)

        if eligible:
            deadline = self._clock() + self._timeout_seconds
            try:
                relationship = self._relationship.batch_check(
                    context=context,
                    resources=tuple(eligible),
                    deadline_monotonic=deadline,
                )
                if self._clock() > deadline:
                    raise TimeoutError("relationship authorization timed out")
                attribute = self._attribute.batch_check(
                    context=context,
                    resources=tuple(eligible),
                    deadline_monotonic=deadline,
                )
                if self._clock() > deadline:
                    raise TimeoutError("attribute authorization timed out")
            except Exception:
                self._deny_eligible_batch(
                    results,
                    context,
                    eligible,
                    subject_fingerprint,
                    "authz_dependency_unavailable",
                )
            else:
                try:
                    relationship_by_key = self._component_closure(
                        relationship, eligible, context.policy_epoch
                    )
                    attribute_by_key = self._component_closure(
                        attribute, eligible, context.policy_epoch
                    )
                except EnterpriseAuthorizationError:
                    self._deny_eligible_batch(
                        results,
                        context,
                        eligible,
                        subject_fingerprint,
                        "authz_component_invalid",
                    )
                    relationship_by_key = None
                    attribute_by_key = None
                if relationship_by_key is None or attribute_by_key is None:
                    return tuple(results[resource.resource_key] for resource in requested)
                for resource in eligible:
                    relationship_decision = relationship_by_key[resource.resource_key]
                    attribute_decision = attribute_by_key[resource.resource_key]
                    components = (relationship_decision, attribute_decision)
                    allowed = all(component.allowed for component in components)
                    reasons = tuple(
                        sorted(
                            {
                                reason
                                for component in components
                                for reason in component.reason_codes
                            }
                        )
                    )
                    obligations = (
                        tuple(
                            sorted(
                                {
                                    obligation
                                    for component in components
                                    for obligation in component.obligations
                                }
                            )
                        )
                        if allowed
                        else ()
                    )
                    versions = (
                        "attribute:" + attribute_decision.engine_version,
                        "relationship:" + relationship_decision.engine_version,
                    )
                    results[resource.resource_key] = self._decision(
                        context=context,
                        resource=resource,
                        subject_fingerprint=subject_fingerprint,
                        allowed=allowed,
                        reasons=reasons,
                        obligations=obligations,
                        component_versions=versions,
                    )
        return tuple(results[resource.resource_key] for resource in requested)

    @staticmethod
    def _component_closure(
        decisions: object,
        resources: list[EnterpriseAuthorizationResource],
        expected_policy_epoch: int,
    ) -> dict[tuple[str, str], EnterprisePolicyComponentDecision]:
        if not isinstance(decisions, Sequence) or isinstance(decisions, (str, bytes)):
            raise EnterpriseAuthorizationError("authorization component result is invalid")
        if any(not isinstance(item, EnterprisePolicyComponentDecision) for item in decisions):
            raise EnterpriseAuthorizationError("authorization component result is invalid")
        by_key = {item.resource_key: item for item in decisions}
        expected = {resource.resource_key for resource in resources}
        if len(by_key) != len(decisions) or set(by_key) != expected:
            raise EnterpriseAuthorizationError("authorization component closure differs")
        resource_by_key = {resource.resource_key: resource for resource in resources}
        if any(
            item.policy_epoch != expected_policy_epoch
            or item.policy_id != resource_by_key[item.resource_key].policy_id
            for item in decisions
        ):
            raise EnterpriseAuthorizationError("authorization component policy is stale")
        return by_key

    def _deny_eligible_batch(
        self,
        results: dict[tuple[str, str], EnterpriseAuthorizationDecision],
        context: EnterpriseRequestContext,
        resources: list[EnterpriseAuthorizationResource],
        subject_fingerprint: str,
        reason: str,
    ) -> None:
        for resource in resources:
            results[resource.resource_key] = self._deny(
                context,
                resource,
                subject_fingerprint,
                (reason,),
            )

    def _subject_fingerprint(self, context: EnterpriseRequestContext) -> str:
        payload = {
            "tenant": context.tenant_id,
            "subject": context.subject_id,
            "session": context.session_id,
            "groups": context.groups,
            "roles": context.roles,
            "attributes": dict(context.attributes),
            "purpose": context.purpose,
            "device_trust": context.device_trust,
            "region": context.region,
            "policy_epoch": context.policy_epoch,
            "session_epoch": context.session_epoch,
        }
        return hmac.new(self._audit_key, _canonical_json(payload), hashlib.sha256).hexdigest()

    def _deny(
        self,
        context: EnterpriseRequestContext,
        resource: EnterpriseAuthorizationResource,
        subject_fingerprint: str,
        reasons: tuple[str, ...],
    ) -> EnterpriseAuthorizationDecision:
        return self._decision(
            context=context,
            resource=resource,
            subject_fingerprint=subject_fingerprint,
            allowed=False,
            reasons=reasons,
            obligations=(),
            component_versions=(),
        )

    def _decision(
        self,
        *,
        context: EnterpriseRequestContext,
        resource: EnterpriseAuthorizationResource,
        subject_fingerprint: str,
        allowed: bool,
        reasons: tuple[str, ...],
        obligations: tuple[str, ...],
        component_versions: tuple[str, ...],
    ) -> EnterpriseAuthorizationDecision:
        if not allowed and not reasons:
            reasons = ("explicit_deny",)
        receipt = {
            "tenant": context.tenant_id,
            "subject_scope_fingerprint": subject_fingerprint,
            "resource_type": resource.resource_type,
            "resource_id": resource.resource_id,
            "policy_id": resource.policy_id,
            "policy_epoch": context.policy_epoch,
            "allowed": allowed,
            "reasons": reasons,
            "obligations": obligations,
            "component_versions": component_versions,
        }
        decision_id = hmac.new(
            self._audit_key, _canonical_json(receipt), hashlib.sha256
        ).hexdigest()
        return EnterpriseAuthorizationDecision(
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            allowed=allowed,
            policy_epoch=context.policy_epoch,
            reason_codes=reasons,
            obligations=obligations,
            component_versions=component_versions,
            subject_scope_fingerprint=subject_fingerprint,
            decision_id=decision_id,
        )


__all__ = [
    "EnterpriseAuthorizationDecision",
    "EnterpriseAuthorizationError",
    "EnterpriseAuthorizationFacade",
    "EnterpriseAuthorizationResource",
    "EnterprisePolicyComponentDecision",
    "EnterprisePolicyEvaluator",
]
