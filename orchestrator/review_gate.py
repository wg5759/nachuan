"""Fail-closed review/outcome gate shared by every multi-model workflow.

Review authority is attached to the *actual served* model, verified response
identity, closed-set model family and runtime domain, never to the requested
route or user-editable connection name.  A model verdict is advisory evidence
only: even a qualified PASS sets ``reviewed`` but cannot set
``machine_verified``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Iterable

from gateway.catalog import rank_sort_key
from gateway.model_identity import (
    REVIEW_STRENGTH_REGISTRY_VERSION,
    review_strength_from_identifier,
)
from gateway.route_attestation import (
    ATTESTATION_FIELD,
    bind_model_review_receipt,
    claim_receipt_for_review_gate,
    verify_model_review_receipt,
    verify_provider_call_receipt,
)
from orchestrator.identity import (
    identity_from_call,
    independence_domain_from_route,
    normalize_independence_domain,
    normalize_model_family,
    verified_route_model_evidence,
)
from orchestrator.workflows.common import ROUTE_RECEIPT_VERSION, route_receipt


REVIEWED_OUTPUT_BINDING_VERSION = 1
_REVIEWED_OUTPUT_NOT_SUPPLIED = object()


def _canonical_json_value(value: Any) -> Any:
    """Return a closed JSON value whose encoding is deterministic.

    Mapping keys must be strings and unordered containers are deliberately
    rejected.  Falling back to ``str(value)`` would make a process-specific
    representation look like durable review evidence.
    """

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not canonical JSON")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("reviewed output object keys must be strings")
            normalized[key] = _canonical_json_value(child)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(child) for child in value]
    raise TypeError(
        f"unsupported reviewed output type: {type(value).__name__}"
    )


def canonical_reviewed_output(value: Any) -> bytes:
    """Canonicalize the exact reviewed text/bytes/JSON-like object.

    Type/domain prefixes prevent an object from sharing a digest with text
    that merely looks like its JSON serialization.  Text and bytes are not
    stripped, Unicode-normalized, or otherwise rewritten: a changed byte must
    produce a changed binding.
    """

    prefix = f"nachuan-reviewed-output-v{REVIEWED_OUTPUT_BINDING_VERSION}\0"
    if isinstance(value, str):
        return prefix.encode("ascii") + b"text\0" + value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return prefix.encode("ascii") + b"bytes\0" + bytes(value)
    normalized = _canonical_json_value(value)
    payload = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return prefix.encode("ascii") + b"json\0" + payload


def reviewed_output_sha256(value: Any) -> str:
    """Return the lowercase SHA-256 binding for one canonical reviewed output."""

    return hashlib.sha256(canonical_reviewed_output(value)).hexdigest()


def _output_binding(value: Any) -> tuple[str | None, bool, str | None]:
    if value is _REVIEWED_OUTPUT_NOT_SUPPLIED:
        return None, False, "reviewed_output_not_supplied"
    try:
        return reviewed_output_sha256(value), True, None
    except (TypeError, ValueError, OverflowError, RecursionError):
        return None, False, "reviewed_output_not_canonicalizable"


def verdict_pass(text: str) -> bool:
    """Accept only the final line's exact verdict token; ambiguity fails closed."""
    if not (text or "").strip():
        return False
    last = next(
        (line.strip().upper() for line in reversed(text.strip().splitlines()) if line.strip()),
        "",
    )
    return bool(re.fullmatch(r"(?:PASS|OK|YES|达标|通过|合格)", last))


@dataclass(frozen=True)
class ModelIdentity:
    model: str
    provider: str
    model_family: str
    independence_domain: str


@dataclass(frozen=True)
class ReviewObservation:
    requested_model: str
    served_model: str
    provider: str | None
    upstream_model: str | None
    reported_model: str | None
    observed_model: str | None
    model_family: str | None
    model_identity_error: str | None
    independence_domain: str | None
    tier: str | None
    flagship: bool | None
    review_strength: str | None
    strength_registry_version: str
    route_receipt_version: int | None
    call_receipt: dict[str, Any] | None
    review_receipt: dict[str, Any] | None
    review_receipt_error: str | None
    reviewed_output_sha256: str | None
    provider_request_sha256: str | None
    verdict: str
    passed: bool

    def __iter__(self):  # noqa: ANN204 - legacy ``ok, verdict = await _verify(...)`` support
        yield self.passed
        yield self.verdict


@dataclass(frozen=True)
class ReviewDecision:
    observation: ReviewObservation
    identity_qualified: bool
    qualified: bool
    reviewed: bool
    machine_verified: bool
    vote_weight: int
    reason: str
    reviewed_output_sha256: str | None
    reviewed_output_bound: bool
    reviewed_output_binding_version: int
    reviewed_output_binding_error: str | None

    @property
    def verified(self) -> bool:
        """Compatibility alias; verification means machine verification only."""
        return self.machine_verified

    def matches_reviewed_output(self, value: Any) -> bool:
        """Return whether ``value`` is exactly the output bound to this decision."""

        if not self.reviewed_output_bound or not self.reviewed_output_sha256:
            return False
        try:
            digest = reviewed_output_sha256(value)
        except (TypeError, ValueError, OverflowError, RecursionError):
            return False
        return hmac.compare_digest(self.reviewed_output_sha256, digest)

    def reviewed_for(self, value: Any) -> bool:
        """Safely apply this review decision to one candidate final output."""

        return bool(self.reviewed and self.matches_reviewed_output(value))


def review_observation(
    router: Any,
    *,
    requested_model: str,
    served_model: str,
    route: Any = None,
    response: dict[str, Any] | None = None,
    observed_model: str | None = None,
    verdict: str,
    passed: bool | None = None,
    reviewed_output: Any = _REVIEWED_OUTPUT_NOT_SUPPLIED,
    provider_provenance: dict[str, Any] | None = None,
    expected_provider_request_sha256: str | None = None,
) -> ReviewObservation:
    """Build review evidence only from the invocation-time route snapshot."""
    del router  # mutable router state is never review identity evidence
    actual = str(served_model or "").strip()
    text = str(verdict or "").strip()
    parsed_pass = verdict_pass(text)
    evidence_response = response if isinstance(response, dict) else {"model": observed_model}
    model_evidence = verified_route_model_evidence(route, evidence_response)
    route_virtual = str(getattr(route, "virtual_model", "") or "").strip()
    identity_error = model_evidence.error
    if route is None:
        identity_error = "missing_route_snapshot"
    elif not route_virtual:
        identity_error = "missing_route_virtual"
    elif route_virtual != actual:
        identity_error = "actual_route_mismatch"
    provider = (
        str(getattr(getattr(route, "provider", None), "name", "") or "")
        .strip()
        .casefold()
        or None
    )
    upstream_model = str(getattr(route, "upstream_model", "") or "").strip() or None
    independence_domain = independence_domain_from_route(route)
    tier = str(getattr(route, "tier", "") or "").strip().casefold() or None
    observed = None if identity_error else model_evidence.observed_model
    family = None if identity_error else model_evidence.model_family
    strength = review_strength_from_identifier(observed) if observed else None
    call_receipt = route_receipt(
        requested_model=str(requested_model or "").strip(),
        actual_model=actual or None,
        route=route,
        response=evidence_response,
    )
    reviewed_digest, reviewed_bound, _reviewed_error = _output_binding(
        reviewed_output
    )
    request_digest = str(expected_provider_request_sha256 or "").strip().casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", request_digest):
        request_digest = ""
    review_receipt: dict[str, Any] | None = None
    review_receipt_error: str | None = None
    if reviewed_bound and reviewed_digest and request_digest:
        try:
            review_receipt = bind_model_review_receipt(
                call_receipt,
                provenance=provider_provenance or {},
                verdict=text,
                reviewed_output_sha256=reviewed_digest,
                expected_provider_request_sha256=request_digest,
            )
        except ValueError as exc:
            review_receipt = None
            review_receipt_error = (
                "provider_call_ledger_uncommitted"
                if str(exc) == "provider_call_ledger_uncommitted"
                else "provider_review_attestation_invalid"
            )
    return ReviewObservation(
        requested_model=str(requested_model or "").strip(),
        served_model=actual,
        provider=provider,
        upstream_model=upstream_model,
        reported_model=model_evidence.reported_model,
        observed_model=observed,
        model_family=family,
        model_identity_error=identity_error,
        independence_domain=independence_domain,
        tier=tier,
        flagship=bool(getattr(route, "flagship", False)) if route is not None else None,
        review_strength=strength,
        strength_registry_version=REVIEW_STRENGTH_REGISTRY_VERSION,
        route_receipt_version=ROUTE_RECEIPT_VERSION if route is not None else None,
        call_receipt=call_receipt,
        review_receipt=review_receipt,
        review_receipt_error=review_receipt_error,
        reviewed_output_sha256=reviewed_digest,
        provider_request_sha256=request_digest or None,
        verdict=text,
        # Callers may force a rejection (timeout/policy), never force an ambiguous
        # natural-language verdict to PASS and bypass the centralized parser.
        passed=parsed_pass and passed is not False,
    )


class ReviewGate:
    """Own actual-author lineage and adjudicate independent model reviews."""

    def __init__(self, router: Any) -> None:
        self.router = router
        self._contributors: dict[str, dict[str, Any]] = {}
        self._unknown_contributors: list[dict[str, Any]] = []
        self._initiator: ModelIdentity | None = None
        self._qualified_reviews: list[ReviewDecision] = []
        self._author_receipt_uses: dict[str, tuple[str, str, bool]] = {}
        self._gate_id = secrets.token_hex(32)

    @property
    def lineage_complete(self) -> bool:
        return bool(self._contributors) and self._initiator is not None and not self._unknown_contributors

    @property
    def contributor_models(self) -> set[str]:
        return set(self._contributors)

    @property
    def contributor_providers(self) -> set[str]:
        return {str(row["provider"]) for row in self._contributors.values()}

    @property
    def contributor_families(self) -> set[str]:
        return {str(row["model_family"]) for row in self._contributors.values()}

    @property
    def contributor_domains(self) -> set[str]:
        return {
            str(row["independence_domain"])
            for row in self._contributors.values()
        }

    @property
    def initiator(self) -> ModelIdentity | None:
        return self._initiator

    def review_capability(self) -> dict[str, Any]:
        """Describe the default review pool; never use this as vote evidence.

        Strength comes only from the versioned registry.  ``tier`` remains a
        mutable scheduling hint, so we expose both the complete trusted set and
        the subset the default premium scheduler can actually select.
        """

        try:
            all_rows = [
                dict(row)
                for row in self.router.routes_info()
                if normalize_model_family(row.get("model_family"))
                and normalize_independence_domain(row.get("independence_domain"))
                and review_strength_from_identifier(row.get("upstream_model")) == "strong"
            ]
        except Exception:  # noqa: BLE001
            all_rows = []
        rows = [
            row
            for row in all_rows
            if str(row.get("tier") or "").strip().casefold() == "premium"
        ]
        pair_available = any(
            normalize_model_family(left.get("model_family"))
            != normalize_model_family(right.get("model_family"))
            and normalize_independence_domain(left.get("independence_domain"))
            != normalize_independence_domain(right.get("independence_domain"))
            for index, left in enumerate(rows)
            for right in rows[index + 1 :]
        )
        if not all_rows:
            reason = "no_strong_verified_routes"
        elif not rows:
            reason = "no_schedulable_strong_routes"
        elif not pair_available:
            reason = "no_independent_strong_route_pair"
        else:
            reason = None
        return {
            "registry_version": REVIEW_STRENGTH_REGISTRY_VERSION,
            "all_strong_route_count": len(all_rows),
            "schedulable_strong_route_count": len(rows),
            "strong_route_count": len(rows),
            "independent_pair_available": pair_available,
            "reason": reason,
        }

    def _poison(self, model: str, role: str, reason: str) -> bool:
        marker = {
            "model": model,
            "role": str(role or "unknown"),
            "reason": reason,
        }
        if marker not in self._unknown_contributors:
            self._unknown_contributors.append(marker)
        return False

    @staticmethod
    def _verified_observation_receipt(
        observation: ReviewObservation,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Authenticate and cross-check every identity field used for a vote."""

        receipt = observation.call_receipt
        if not verify_provider_call_receipt(
            receipt,
            authored_output=observation.verdict,
        ) or not isinstance(receipt, dict):
            return None, "reviewer_call_attestation_invalid"
        call = dict(receipt)
        reported_model = str(call.get("reported_model") or "").strip() or None
        identity_error = (
            str(call.get("model_identity_error") or "").strip() or None
        )
        tier = str(call.get("tier") or "").strip().casefold() or None
        flagship = (
            bool(call.get("flagship"))
            if call.get("flagship") is not None
            else None
        )
        if (
            call.get("route_receipt_version") != ROUTE_RECEIPT_VERSION
            or str(call.get("actual_model") or "").strip()
            != observation.served_model
            or str(call.get("requested_model") or "").strip()
            != observation.requested_model
            or reported_model != observation.reported_model
            or identity_error != observation.model_identity_error
            or tier != observation.tier
            or flagship != observation.flagship
            or observation.strength_registry_version
            != REVIEW_STRENGTH_REGISTRY_VERSION
            or observation.route_receipt_version
            != (ROUTE_RECEIPT_VERSION if call.get("route_receipt_version") else None)
            or (observation.passed and not verdict_pass(observation.verdict))
        ):
            return None, "reviewer_observation_receipt_mismatch"
        identity = identity_from_call(call)
        if identity.known:
            expected = (
                str(identity.provider).casefold(),
                str(identity.upstream_model),
                str(identity.observed_model),
                str(identity.model_family),
                str(identity.independence_domain),
                review_strength_from_identifier(identity.observed_model),
            )
            observed = (
                observation.provider,
                observation.upstream_model,
                observation.observed_model,
                observation.model_family,
                observation.independence_domain,
                observation.review_strength,
            )
            if observed != expected or observation.model_identity_error is not None:
                return None, "reviewer_observation_receipt_mismatch"
        elif any(
            value is not None
            for value in (
                observation.observed_model,
                observation.model_family,
                observation.review_strength,
            )
        ):
            return None, "reviewer_observation_receipt_mismatch"
        return call, None

    def add_author(
        self,
        served_model: str | None,
        *,
        role: str,
        initiator: bool = False,
        requested_model: str | None = None,
        route: Any = None,
        response: dict[str, Any] | None = None,
        receipt: Mapping[str, Any] | ReviewObservation | None = None,
    ) -> bool:
        """Add an author only from immutable call evidence; drift poisons lineage."""
        model = str(served_model or "").strip()
        verified_observation = False
        if isinstance(receipt, ReviewObservation):
            observation = receipt
            verified, error = self._verified_observation_receipt(observation)
            if verified is None:
                return self._poison(model, role, str(error))
            receipt = verified
            verified_observation = True
        elif receipt is None and route is not None:
            receipt = route_receipt(
                requested_model=str(requested_model or model),
                actual_model=model or None,
                route=route,
                response=response,
            )
        if not model or not isinstance(receipt, dict):
            return self._poison(model, role, "missing_call_receipt")
        if not verified_observation and not verify_provider_call_receipt(receipt):
            return self._poison(model, role, "invalid_call_attestation")
        call = dict(receipt)
        if not claim_receipt_for_review_gate(call, gate_id=self._gate_id):
            return self._poison(model, role, "call_receipt_replayed")
        if call.get("route_receipt_version") != ROUTE_RECEIPT_VERSION:
            return self._poison(model, role, "unsupported_call_receipt")
        if str(call.get("actual_model") or "").strip() != model:
            return self._poison(model, role, "actual_model_mismatch")
        role_name = str(role or "author")
        attestation = str(call.get(ATTESTATION_FIELD) or "")
        prior_use = self._author_receipt_uses.get(attestation)
        current_use = (model, role_name, bool(initiator))
        if prior_use is not None:
            if prior_use == current_use:
                return True
            return self._poison(model, role_name, "call_receipt_reused")
        identity = identity_from_call(call)
        if not identity.known:
            error = str(call.get("model_identity_error") or "identity_unknown")
            return self._poison(model, role, error)
        provider = str(identity.provider)
        model_family = str(identity.model_family)
        independence_domain = str(identity.independence_domain)
        identity_fields = {
            "provider": provider,
            "upstream_model": str(identity.upstream_model),
            "observed_model": str(identity.observed_model),
            "model_family": model_family,
            "independence_domain": independence_domain,
            "route_receipt_version": ROUTE_RECEIPT_VERSION,
        }
        existing = self._contributors.get(model)
        if existing is not None and any(
            existing.get(key) != value for key, value in identity_fields.items()
        ):
            return self._poison(model, role, "author_identity_changed")
        if existing is None:
            row = {
                "model": model,
                **identity_fields,
                "roles": [],
                "call_receipts": [],
            }
            self._contributors[model] = row
        else:
            row = existing
        if role_name not in row["roles"]:
            row["roles"].append(role_name)
        row["call_receipts"].append(
            {
                "role": role_name,
                "route_receipt_version": ROUTE_RECEIPT_VERSION,
                "requested_model": str(call.get("requested_model") or "").strip(),
                "actual_model": model,
                "provider": provider,
                "upstream_model": str(call.get("upstream_model") or "").strip(),
                "reported_model": str(call.get("reported_model") or "").strip() or None,
                "observed_model": str(identity.observed_model),
                "model_family": model_family,
                "independence_domain": independence_domain,
                "model_identity_error": None,
                "attested": True,
                "attestation_sha256": hashlib.sha256(
                    str(call.get(ATTESTATION_FIELD) or "").encode("ascii")
                ).hexdigest(),
            }
        )
        self._author_receipt_uses[attestation] = current_use
        if initiator:
            identity = ModelIdentity(
                model=model,
                provider=provider,
                model_family=model_family,
                independence_domain=independence_domain,
            )
            if self._initiator is None:
                self._initiator = identity
            elif self._initiator != identity:
                return self._poison(model, "initiator_conflict", "initiator_conflict")
        return True

    def add_contributor(
        self,
        contributor: ReviewObservation | str | None,
        *,
        role: str,
        receipt: Mapping[str, Any] | None = None,
    ) -> bool:
        """Absorb a verified observation directly; never re-query the router."""
        if isinstance(contributor, ReviewObservation):
            return self.add_author(
                contributor.served_model,
                role=role,
                receipt=contributor,
                initiator=False,
            )
        return self.add_author(
            contributor,
            role=role,
            receipt=receipt,
            initiator=False,
        )

    def add_initiator_summary(
        self,
        served_model: str | None,
        *,
        role: str,
        requested_model: str | None = None,
        route: Any = None,
        response: dict[str, Any] | None = None,
        receipt: Mapping[str, Any] | None = None,
    ) -> bool:
        """Accept a summary only when the original initiator actually served it.

        Requesting the initiator is not sufficient because provider failover may
        return a different model.  Such output is useful only as untrusted progress;
        it cannot impersonate the initiator's zero-vote synthesis stage.
        """

        initiator = self._initiator
        actual = str(served_model or "").strip()
        requested = str(requested_model or "").strip()
        if initiator is None:
            return self._poison(actual, role, "initiator_identity_unknown")
        if requested != initiator.model or actual != initiator.model:
            return self._poison(
                actual,
                role,
                "initiator_summary_actual_mismatch",
            )
        return self.add_author(
            actual,
            role=role,
            requested_model=requested,
            route=route,
            response=response,
            receipt=receipt,
            initiator=False,
        )

    def select_reviewer(self, *, tier: str = "premium") -> str | None:
        """Select a reviewer independent from every actual lineage contributor."""
        if not self.lineage_complete:
            return None
        required_tier = str(tier or "").strip().casefold()
        try:
            rows: Iterable[dict[str, Any]] = self.router.routes_info()
        except Exception:  # noqa: BLE001
            return None
        independent = [
            row
            for row in rows
            if str(row.get("tier") or "").strip().casefold() == required_tier
            and str(row.get("model") or "") not in self.contributor_models
            and bool(normalize_model_family(row.get("model_family")))
            and review_strength_from_identifier(row.get("upstream_model")) == "strong"
            and normalize_model_family(row.get("model_family"))
            not in self.contributor_families
            and bool(normalize_independence_domain(row.get("independence_domain")))
            and normalize_independence_domain(row.get("independence_domain"))
            not in self.contributor_domains
        ]
        # Cost preference must not disable review: prefer ordinary premium, then use an
        # independent flagship when it is the only qualified route.
        candidates = [row for row in independent if not row.get("flagship")] or independent
        candidates.sort(
            key=lambda row: (
                rank_sort_key(row.get("rank")),
                str(row.get("model") or ""),
            )
        )
        return str(candidates[0].get("model") or "") if candidates else None

    def evaluate(
        self,
        observation: ReviewObservation,
        *,
        required_tier: str = "premium",
        reviewed_output: Any = _REVIEWED_OUTPUT_NOT_SUPPLIED,
    ) -> ReviewDecision:
        """Vote only on a strongly identified reviewer and one exact output.

        ``reviewed_output`` is mandatory for a counted vote.  Keeping a default
        makes rollout fail closed instead of crashing old callers: an unbound
        PASS has zero weight and cannot set ``reviewed``.
        """
        del required_tier  # user-editable tier is scheduling/display metadata only
        _receipt, receipt_error = self._verified_observation_receipt(observation)
        output_digest, output_bound, output_binding_error = _output_binding(
            reviewed_output
        )
        review_receipt_valid = bool(
            observation.reviewed_output_sha256
            and verify_model_review_receipt(
                observation.review_receipt,
                verdict=observation.verdict,
                reviewed_output_sha256=observation.reviewed_output_sha256,
                expected_provider_request_sha256=(
                    observation.provider_request_sha256 or ""
                ),
            )
        )
        review_receipt_claimed = bool(
            review_receipt_valid
            and claim_receipt_for_review_gate(
                observation.review_receipt,
                gate_id=self._gate_id,
            )
        )
        signed_output_matches = bool(
            review_receipt_valid
            and output_digest
            and observation.reviewed_output_sha256
            and hmac.compare_digest(
                output_digest,
                observation.reviewed_output_sha256,
            )
        )
        independent = bool(
            receipt_error is None
            and self.lineage_complete
            and observation.served_model
            and observation.observed_model
            and observation.model_family
            and not observation.model_identity_error
            and observation.independence_domain
            and observation.review_strength == "strong"
            and observation.served_model not in self.contributor_models
            and observation.model_family not in self.contributor_families
            and observation.independence_domain not in self.contributor_domains
        )
        if receipt_error is not None:
            reason = receipt_error
        elif not self.lineage_complete:
            reason = "author_lineage_unknown"
        elif (
            not observation.served_model
            or not observation.independence_domain
            or not observation.tier
        ):
            reason = "reviewer_identity_unknown"
        elif (
            not observation.observed_model
            or not observation.model_family
            or observation.model_identity_error
        ):
            reason = "reviewer_model_identity_unknown"
        elif observation.review_strength != "strong":
            reason = "reviewer_strength_not_qualified"
        elif observation.served_model in self.contributor_models:
            reason = "reviewer_is_lineage_contributor"
        elif observation.model_family in self.contributor_families:
            reason = "reviewer_model_family_is_lineage_family"
        elif observation.independence_domain in self.contributor_domains:
            reason = "reviewer_domain_is_lineage_domain"
        elif not output_bound:
            reason = str(output_binding_error or "reviewed_output_unbound")
        elif observation.review_receipt_error == "provider_call_ledger_uncommitted":
            reason = "provider_call_ledger_uncommitted"
        elif not review_receipt_valid:
            reason = "reviewer_output_attestation_invalid"
        elif not review_receipt_claimed:
            reason = "review_receipt_replayed"
        elif not signed_output_matches:
            reason = "reviewed_output_mismatch"
        else:
            reason = "qualified_pass" if observation.passed else "qualified_reject"

        qualified = bool(
            independent
            and output_bound
            and review_receipt_valid
            and review_receipt_claimed
            and signed_output_matches
        )
        reviewed = bool(qualified and observation.passed)
        decision = ReviewDecision(
            observation=observation,
            identity_qualified=independent,
            qualified=qualified,
            reviewed=reviewed,
            # No production caller currently owns an isolated verifier whose evidence is
            # cryptographically bound to this exact output.  LLM review can never elevate it.
            machine_verified=False,
            vote_weight=1 if qualified else 0,
            reason=reason,
            reviewed_output_sha256=output_digest,
            reviewed_output_bound=output_bound,
            reviewed_output_binding_version=REVIEWED_OUTPUT_BINDING_VERSION,
            reviewed_output_binding_error=output_binding_error,
        )
        if qualified and decision not in self._qualified_reviews:
            self._qualified_reviews.append(decision)
        return decision

    def summary_for_initiator(self) -> dict[str, Any]:
        """Return only qualified reviews; the initiator itself always has zero review vote."""
        return {
            "initiator": self._initiator.model if self._initiator else None,
            "initiator_provider": self._initiator.provider if self._initiator else None,
            "initiator_model_family": (
                self._initiator.model_family if self._initiator else None
            ),
            "initiator_independence_domain": (
                self._initiator.independence_domain if self._initiator else None
            ),
            "initiator_vote_weight": 0,
            "qualified_reviews": [
                {
                    "requested_model": review.requested_model,
                    "served_model": review.served_model,
                    "provider": review.provider,
                    "upstream_model": review.upstream_model,
                    "reported_model": review.reported_model,
                    "observed_model": review.observed_model,
                    "model_family": review.model_family,
                    "model_identity_error": review.model_identity_error,
                    "independence_domain": review.independence_domain,
                    "tier": review.tier,
                    "flagship": review.flagship,
                    "review_strength": review.review_strength,
                    "strength_registry_version": review.strength_registry_version,
                    "route_receipt_version": review.route_receipt_version,
                    "passed": review.passed,
                    "verdict": review.verdict,
                    "vote_weight": decision.vote_weight,
                    "reviewed_output_sha256": decision.reviewed_output_sha256,
                    "provider_request_sha256": review.provider_request_sha256,
                    "review_receipt_error": review.review_receipt_error,
                    "reviewed_output_bound": decision.reviewed_output_bound,
                    "reviewed_output_binding_version": (
                        decision.reviewed_output_binding_version
                    ),
                }
                for decision in self._qualified_reviews
                for review in (decision.observation,)
            ],
        }

    def route_metadata(
        self,
        decision: ReviewDecision | None,
        *,
        reviewed_output: Any = _REVIEWED_OUTPUT_NOT_SUPPLIED,
    ) -> dict[str, Any]:
        """Return route evidence after re-binding it to the current final output.

        A stored decision is not enough: callers must provide the output they
        are about to return.  This second comparison prevents a PASS decision
        for an older draft from being attached to a modified final response.
        """

        observation = decision.observation if decision else None
        current_digest, current_bound, current_binding_error = _output_binding(
            reviewed_output
        )
        output_matches = (
            hmac.compare_digest(decision.reviewed_output_sha256, current_digest)
            if decision is not None
            and decision.reviewed_output_sha256 is not None
            and current_digest is not None
            else None
        )
        effective_reviewed = bool(
            decision and decision.reviewed and output_matches is True
        )
        effective_machine_verified = bool(
            decision and decision.machine_verified and output_matches is True
        )
        if decision is not None and not decision.qualified:
            review_unavailable_reason = decision.reason
        elif decision is not None and not current_bound:
            review_unavailable_reason = str(
                current_binding_error or "reviewed_output_not_supplied"
            )
        elif decision is not None and output_matches is not True:
            review_unavailable_reason = "reviewed_output_mismatch"
        elif decision is None and not self.lineage_complete:
            review_unavailable_reason = "author_lineage_unknown"
        elif decision is None and self.select_reviewer() is None:
            review_unavailable_reason = "no_strong_independent_reviewer"
        else:
            review_unavailable_reason = None
        if decision is None:
            review_reason = "review_not_run"
        elif not decision.qualified:
            review_reason = decision.reason
        elif not current_bound:
            review_reason = str(
                current_binding_error or "reviewed_output_not_supplied"
            )
        elif output_matches is not True:
            review_reason = "reviewed_output_mismatch"
        else:
            review_reason = decision.reason
        return {
            "author_lineage": [
                {
                    "model": row["model"],
                    "provider": row["provider"],
                    "upstream_model": row["upstream_model"],
                    "observed_model": row["observed_model"],
                    "model_family": row["model_family"],
                    "independence_domain": row["independence_domain"],
                    "route_receipt_version": row["route_receipt_version"],
                    "roles": list(row["roles"]),
                    "call_receipts": [dict(call) for call in row["call_receipts"]],
                }
                for row in self._contributors.values()
            ],
            "lineage_complete": self.lineage_complete,
            "unknown_lineage": list(self._unknown_contributors),
            "initiator": self._initiator.model if self._initiator else None,
            "initiator_vote_weight": 0,
            "reviewer_requested": observation.requested_model if observation else None,
            "reviewer": observation.served_model if observation else None,
            "reviewer_provider": observation.provider if observation else None,
            "reviewer_upstream_model": observation.upstream_model if observation else None,
            "reviewer_reported_model": (
                observation.reported_model if observation else None
            ),
            "reviewer_observed_model": (
                observation.observed_model if observation else None
            ),
            "reviewer_model_family": (
                observation.model_family if observation else None
            ),
            "reviewer_model_identity_error": (
                observation.model_identity_error if observation else None
            ),
            "reviewer_independence_domain": (
                observation.independence_domain if observation else None
            ),
            "reviewer_tier": observation.tier if observation else None,
            "reviewer_flagship": observation.flagship if observation else None,
            "reviewer_strength": observation.review_strength if observation else None,
            "review_strength_registry_version": (
                observation.strength_registry_version if observation else REVIEW_STRENGTH_REGISTRY_VERSION
            ),
            "reviewer_route_receipt_version": (
                observation.route_receipt_version if observation else None
            ),
            "reviewer_independent": bool(decision and decision.identity_qualified),
            "reviewer_qualified": bool(decision and decision.qualified),
            "reviewer_decision_vote_weight": decision.vote_weight if decision else 0,
            "reviewer_vote_weight": (
                decision.vote_weight
                if decision and output_matches is True
                else 0
            ),
            "review_reason": review_reason,
            "review_unavailable_reason": review_unavailable_reason,
            "review_capability": self.review_capability(),
            "reviewed_output_sha256": (
                decision.reviewed_output_sha256 if decision else None
            ),
            "reviewer_provider_request_sha256": (
                observation.provider_request_sha256 if observation else None
            ),
            "reviewer_receipt_error": (
                observation.review_receipt_error if observation else None
            ),
            "reviewed_output_current_sha256": current_digest,
            "reviewed_output_bound": bool(
                decision and decision.reviewed_output_bound
            ),
            "reviewed_output_current_bound": current_bound,
            "reviewed_output_matches_current": output_matches,
            "reviewed_output_binding_version": (
                decision.reviewed_output_binding_version
                if decision
                else REVIEWED_OUTPUT_BINDING_VERSION
            ),
            "reviewed_output_binding_error": (
                decision.reviewed_output_binding_error if decision else None
            ),
            "reviewed_output_current_binding_error": current_binding_error,
            "reviewed": effective_reviewed,
            "machine_verified": effective_machine_verified,
            "verified": effective_machine_verified,
            "verification_level": (
                "model_review_only" if effective_reviewed else "none"
            ),
        }
