from __future__ import annotations

import pytest

from gateway.enterprise_authz import (
    EnterpriseAuthorizationError,
    EnterpriseAuthorizationFacade,
    EnterpriseAuthorizationResource,
    EnterprisePolicyComponentDecision,
)
from gateway.enterprise_context import EnterpriseRequestContext


def _context(**changes) -> EnterpriseRequestContext:
    values = {
        "tenant_id": "tenant-a",
        "subject_id": "user-a",
        "session_id": "session-a",
        "groups": ("project-red",),
        "roles": ("employee",),
        "attributes": {"clearance": 4},
        "purpose": "support",
        "device_trust": "managed",
        "region": "cn-east",
        "policy_epoch": 7,
        "session_epoch": 3,
    }
    values.update(changes)
    return EnterpriseRequestContext(**values)


def _resource(
    resource_id: str = "chunk-a", *, tenant: str = "tenant-a", epoch: int = 7
) -> EnterpriseAuthorizationResource:
    return EnterpriseAuthorizationResource(
        tenant_id=tenant,
        resource_type="chunk",
        resource_id=resource_id,
        policy_id="policy-a",
        policy_epoch=epoch,
        classification=3,
    )


class _Evaluator:
    def __init__(
        self,
        *,
        allowed: bool = True,
        reason: str = "component_denied",
        obligations: tuple[str, ...] = (),
        version: str = "engine-v1",
        response=None,
        error: Exception | None = None,
        clock=None,
        advance: float = 0.0,
    ):
        self.allowed = allowed
        self.reason = reason
        self.obligations = obligations
        self.version = version
        self.response = response
        self.error = error
        self.clock = clock
        self.advance = advance
        self.calls = []

    def batch_check(self, *, context, resources, deadline_monotonic):
        self.calls.append((context, resources, deadline_monotonic))
        if self.error is not None:
            raise self.error
        if self.clock is not None:
            self.clock.value += self.advance
        if self.response is not None:
            return self.response
        return tuple(
            EnterprisePolicyComponentDecision(
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
                policy_id=resource.policy_id,
                allowed=self.allowed,
                policy_epoch=resource.policy_epoch,
                engine_version=self.version,
                reason_codes=() if self.allowed else (self.reason,),
                obligations=self.obligations,
            )
            for resource in resources
        )


class _Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


def _facade(relationship=None, attribute=None, **kwargs):
    return EnterpriseAuthorizationFacade(
        relationship_evaluator=relationship or _Evaluator(version="rebac-v1"),
        attribute_evaluator=attribute or _Evaluator(version="abac-v1"),
        audit_key=b"audit-key-for-tests-is-at-least-32-bytes-long",
        **kwargs,
    )


def test_relationship_and_attribute_must_both_allow_and_obligations_are_merged() -> None:
    relationship = _Evaluator(obligations=("no_export",), version="rebac-v3")
    attribute = _Evaluator(obligations=("mask_pii", "no_export"), version="abac-v8")

    decision = _facade(relationship, attribute).batch_check(
        _context(), (_resource(),)
    )[0]

    assert decision.allowed is True
    assert decision.reason_codes == ()
    assert decision.obligations == ("mask_pii", "no_export")
    assert decision.component_versions == (
        "attribute:abac-v8",
        "relationship:rebac-v3",
    )


def test_any_explicit_deny_wins_and_allow_obligations_are_discarded() -> None:
    relationship = _Evaluator(allowed=False, reason="relationship_denied")
    attribute = _Evaluator(allowed=True, obligations=("mask_pii",))

    decision = _facade(relationship, attribute).batch_check(
        _context(), (_resource(),)
    )[0]

    assert decision.allowed is False
    assert decision.reason_codes == ("relationship_denied",)
    assert decision.obligations == ()


@pytest.mark.parametrize(
    "failure", ["exception", "missing", "extra", "stale", "wrong_policy"]
)
def test_component_error_missing_extra_or_stale_result_fails_closed(failure: str) -> None:
    resource = _resource()
    if failure == "exception":
        relationship = _Evaluator(error=RuntimeError("provider down"))
    elif failure == "missing":
        relationship = _Evaluator(response=())
    elif failure == "extra":
        relationship = _Evaluator(
            response=(
                EnterprisePolicyComponentDecision(
                    resource_type="chunk",
                    resource_id="other",
                    policy_id="policy-a",
                    allowed=True,
                    policy_epoch=7,
                    engine_version="rebac-v1",
                ),
            )
        )
    else:
        relationship = _Evaluator(
            response=(
                EnterprisePolicyComponentDecision(
                    resource_type="chunk",
                    resource_id="chunk-a",
                    policy_id="policy-b" if failure == "wrong_policy" else "policy-a",
                    allowed=True,
                    policy_epoch=7 if failure == "wrong_policy" else 6,
                    engine_version="rebac-v1",
                ),
            )
        )

    decision = _facade(relationship=relationship).batch_check(
        _context(), (resource,)
    )[0]

    assert decision.allowed is False
    expected = (
        "authz_dependency_unavailable"
        if failure == "exception"
        else "authz_component_invalid"
    )
    assert decision.reason_codes == (expected,)


def test_tenant_and_epoch_mismatches_are_denied_before_calling_policy_engines() -> None:
    relationship = _Evaluator()
    attribute = _Evaluator()
    decisions = _facade(relationship, attribute).batch_check(
        _context(),
        (
            _resource("cross-tenant", tenant="tenant-b"),
            _resource("stale", epoch=6),
        ),
    )

    assert [decision.reason_codes for decision in decisions] == [
        ("tenant_mismatch",),
        ("policy_epoch_mismatch",),
    ]
    assert relationship.calls == [] and attribute.calls == []


def test_shared_deadline_expiry_denies_the_whole_eligible_batch() -> None:
    clock = _Clock()
    relationship = _Evaluator(clock=clock, advance=1.1)
    attribute = _Evaluator(clock=clock)

    decision = _facade(
        relationship,
        attribute,
        timeout_seconds=1.0,
        monotonic_clock=clock,
    ).batch_check(_context(), (_resource(),))[0]

    assert decision.allowed is False
    assert decision.reason_codes == ("authz_dependency_unavailable",)
    assert attribute.calls == []


def test_receipt_is_hmac_pseudonymous_deterministic_and_scope_sensitive() -> None:
    facade = _facade()
    first = facade.batch_check(_context(), (_resource(),))[0]
    repeat = facade.batch_check(_context(), (_resource(),))[0]
    changed = facade.batch_check(
        _context(groups=("project-blue",)), (_resource(),)
    )[0]

    assert first.decision_id == repeat.decision_id
    assert first.subject_scope_fingerprint == repeat.subject_scope_fingerprint
    assert first.subject_scope_fingerprint != changed.subject_scope_fingerprint
    assert "user-a" not in first.subject_scope_fingerprint
    assert len(first.subject_scope_fingerprint) == 64


def test_duplicate_resources_and_invalid_component_decisions_are_rejected() -> None:
    with pytest.raises(EnterpriseAuthorizationError, match="duplicates"):
        _facade().batch_check(_context(), (_resource(), _resource()))
    with pytest.raises(EnterpriseAuthorizationError, match="allowed component"):
        EnterprisePolicyComponentDecision(
            resource_type="chunk",
            resource_id="chunk-a",
            policy_id="policy-a",
            allowed=True,
            policy_epoch=7,
            engine_version="rebac-v1",
            reason_codes=("contradiction",),
        )
