"""Process-local authenticity for route receipts crossing public boundaries.

The receipt remains JSON-serializable, but a model result cannot gain public
authorship merely by returning a structurally plausible dictionary.  Only the
trusted route-receipt constructor in this process can mint the HMAC.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar, Token
from collections.abc import Iterator
from typing import Any


ATTESTATION_FIELD = "_nachuan_route_attestation"
_ATTESTATION_VERSION = 1
_PROCESS_KEY = secrets.token_bytes(32)
_AUTHOR_CONTEXT: ContextVar[str] = ContextVar(
    "nachuan_agent_author_context",
    default="",
)
_KIND_FIELD = "_nachuan_attestation_kind"
_NONCE_FIELD = "_nachuan_attestation_nonce"
_CONTEXT_FIELD = "_nachuan_attestation_context_sha256"
_ROLE_FIELD = "_nachuan_attestation_role"
_SOURCE_FIELD = "_nachuan_source_route_attestation"
_OUTPUT_FIELD = "_nachuan_authored_output_sha256"
_CANONICAL_OUTPUT_FIELD = "_nachuan_canonical_output_sha256"
_REVIEWED_OUTPUT_FIELD = "_nachuan_reviewed_output_sha256"
_PROVENANCE_SOURCE_FIELD = "_nachuan_provider_provenance_attestation"
_REQUEST_FIELD = "_nachuan_provider_request_sha256"
_CALL_ID_FIELD = "_nachuan_provider_call_id"
_ATTEMPT_FIELD = "_nachuan_provider_attempt"
_TRACE_FIELD = "_nachuan_provider_trace_sha256"
_TURN_FIELD = "_nachuan_provider_turn_sha256"
_WORKFLOW_FIELD = "_nachuan_provider_workflow_sha256"
_BUSINESS_ROLE_FIELD = "_nachuan_provider_business_role"
_REVIEW_CALL_NONCE_FIELD = "_nachuan_review_call_nonce"
_LEDGER_COMMITTED_FIELD = "_nachuan_provider_ledger_terminal_committed"
_PROVENANCE_ATTESTATION_FIELD = "_nachuan_provider_call_attestation"
_PROVENANCE_VERSION = 1
_REVIEW_BINDING: ContextVar[dict[str, str] | None] = ContextVar(
    "nachuan_model_review_binding",
    default=None,
)
_LAST_PROVIDER_PROVENANCE: ContextVar[dict[str, Any] | None] = ContextVar(
    "nachuan_provider_call_provenance",
    default=None,
)
_CLAIM_LOCK = threading.Lock()
_MAX_PROCESS_CLAIMS = 100_000
_BOUND_PROVENANCE: OrderedDict[str, None] = OrderedDict()
_GATE_CLAIMS: OrderedDict[str, str] = OrderedDict()
_THINK_RE = re.compile(
    r"<think>.*?</think>|<thinking>.*?</thinking>|◁think▷.*?◁/think▷|"
    r"<reasoning>.*?</reasoning>",
    re.I | re.S,
)
_SIGNED_FIELDS = (
    "route_receipt_version",
    "model",
    "requested_model",
    "actual_model",
    "provider",
    "upstream_model",
    "reported_model",
    "observed_model",
    "model_family",
    "model_identity_error",
    "independence_domain",
    "tier",
    "flagship",
    _KIND_FIELD,
    _NONCE_FIELD,
    _CONTEXT_FIELD,
    _ROLE_FIELD,
    _SOURCE_FIELD,
    _OUTPUT_FIELD,
    _CANONICAL_OUTPUT_FIELD,
    _REVIEWED_OUTPUT_FIELD,
    _PROVENANCE_SOURCE_FIELD,
    _REQUEST_FIELD,
    _CALL_ID_FIELD,
    _ATTEMPT_FIELD,
    _TRACE_FIELD,
    _TURN_FIELD,
    _WORKFLOW_FIELD,
    _BUSINESS_ROLE_FIELD,
    _REVIEW_CALL_NONCE_FIELD,
    _LEDGER_COMMITTED_FIELD,
)

_PROVENANCE_FIELDS = (
    "requested_model",
    "actual_model",
    "provider",
    "upstream_model",
    "reported_model",
    "observed_model",
    "model_family",
    "model_identity_error",
    "independence_domain",
    "tier",
    "flagship",
    _NONCE_FIELD,
    _CONTEXT_FIELD,
    _REQUEST_FIELD,
    _OUTPUT_FIELD,
    _CANONICAL_OUTPUT_FIELD,
    _REVIEWED_OUTPUT_FIELD,
    _CALL_ID_FIELD,
    _ATTEMPT_FIELD,
    _TRACE_FIELD,
    _TURN_FIELD,
    _WORKFLOW_FIELD,
    _BUSINESS_ROLE_FIELD,
    _REVIEW_CALL_NONCE_FIELD,
    _LEDGER_COMMITTED_FIELD,
)


def _payload(receipt: dict[str, Any]) -> bytes:
    values = {field: receipt.get(field) for field in _SIGNED_FIELDS}
    return json.dumps(
        {"v": _ATTESTATION_VERSION, "receipt": values},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _provenance_payload(value: dict[str, Any]) -> bytes:
    fields = {field: value.get(field) for field in _PROVENANCE_FIELDS}
    return json.dumps(
        {"v": _PROVENANCE_VERSION, "provider_call": fields},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _remember_once(store: OrderedDict[str, None], key: str) -> bool:
    with _CLAIM_LOCK:
        if key in store:
            return False
        store[key] = None
        while len(store) > _MAX_PROCESS_CLAIMS:
            store.popitem(last=False)
    return True


def _claim_for_gate(attestation: str, gate_id: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{64}", attestation) or not gate_id:
        return False
    with _CLAIM_LOCK:
        owner = _GATE_CLAIMS.get(attestation)
        if owner is not None:
            return hmac.compare_digest(owner, gate_id)
        _GATE_CLAIMS[attestation] = gate_id
        while len(_GATE_CLAIMS) > _MAX_PROCESS_CLAIMS:
            _GATE_CLAIMS.popitem(last=False)
    return True


def claim_receipt_for_review_gate(value: object, *, gate_id: str) -> bool:
    """Allow one attested call/review receipt to belong to one ReviewGate."""

    if not verify_route_receipt_attestation(value) or not isinstance(value, dict):
        return False
    return _claim_for_gate(str(value.get(ATTESTATION_FIELD) or ""), gate_id)


@contextmanager
def bind_model_review_call(
    *,
    reviewed_output_sha256: str,
    business_role: str,
) -> Iterator[None]:
    """Declare the exact candidate before the provider review call starts."""

    digest = str(reviewed_output_sha256 or "")
    role = str(business_role or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("reviewed output digest is invalid")
    if not role or len(role) > 256:
        raise ValueError("model review business role is invalid")
    token = _REVIEW_BINDING.set(
        {
            "reviewed_output_sha256": digest,
            "business_role": role,
            "review_call_nonce": secrets.token_hex(16),
        }
    )
    _LAST_PROVIDER_PROVENANCE.set(None)
    try:
        yield
    finally:
        _REVIEW_BINDING.reset(token)


def canonical_provider_request_sha256(value: object) -> str:
    """Hash the exact JSON-like provider request without retaining prompt text."""

    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"nachuan-provider-request-v1\0" + payload).hexdigest()


def capture_provider_call_provenance(
    *,
    request_payload: object,
    response: dict[str, Any],
    requested_model: str,
    actual_model: str,
    provider: str,
    upstream_model: str,
    route: Any,
    call_id: str,
    attempt: int,
    call_context: object,
    ledger_terminal_committed: bool,
) -> dict[str, Any] | None:
    """Mint task-local provenance at the successful provider boundary."""

    binding = _REVIEW_BINDING.get()
    _LAST_PROVIDER_PROVENANCE.set(None)
    if binding is None:
        return None
    content = (
        (response.get("choices") or [{}])[0]
        .get("message", {})
        .get("content")
    )
    if not isinstance(content, str):
        return None

    def context_digest(name: str) -> str | None:
        raw = str(getattr(call_context, name, "") or "")
        return _digest_text(raw) if raw else None

    # Freeze the same invocation-time identity snapshot later used by the
    # ReviewGate.  A caller must not be able to pair one genuine verdict with a
    # different mutable route/response object and thereby upgrade its vote.
    from orchestrator.identity import (  # local import avoids a module cycle
        independence_domain_from_route,
        verified_route_model_evidence,
    )

    model_evidence = verified_route_model_evidence(route, response)
    route_virtual = str(getattr(route, "virtual_model", "") or "").strip()
    actual = str(actual_model or "").strip()
    identity_error = model_evidence.error
    if route is None:
        identity_error = "missing_route_snapshot"
    elif not route_virtual:
        identity_error = "missing_route_virtual"
    elif route_virtual != actual:
        identity_error = "actual_route_mismatch"

    provenance: dict[str, Any] = {
        "requested_model": str(requested_model or ""),
        "actual_model": actual,
        "provider": str(provider or ""),
        "upstream_model": str(upstream_model or ""),
        "reported_model": model_evidence.reported_model,
        "observed_model": None if identity_error else model_evidence.observed_model,
        "model_family": None if identity_error else model_evidence.model_family,
        "model_identity_error": identity_error,
        "independence_domain": independence_domain_from_route(route),
        "tier": getattr(route, "tier", None),
        "flagship": getattr(route, "flagship", None),
        _NONCE_FIELD: secrets.token_hex(16),
        _CONTEXT_FIELD: _context_digest(),
        _REQUEST_FIELD: canonical_provider_request_sha256(request_payload),
        _OUTPUT_FIELD: _digest_text(content),
        _CANONICAL_OUTPUT_FIELD: _digest_text(canonical_agent_output(content)),
        _REVIEWED_OUTPUT_FIELD: binding["reviewed_output_sha256"],
        _CALL_ID_FIELD: str(call_id or ""),
        _ATTEMPT_FIELD: int(attempt),
        _TRACE_FIELD: context_digest("trace_id"),
        _TURN_FIELD: context_digest("turn_id"),
        _WORKFLOW_FIELD: context_digest("workflow_id"),
        _BUSINESS_ROLE_FIELD: binding["business_role"],
        _REVIEW_CALL_NONCE_FIELD: binding["review_call_nonce"],
        _LEDGER_COMMITTED_FIELD: bool(ledger_terminal_committed),
    }
    provenance[_PROVENANCE_ATTESTATION_FIELD] = hmac.new(
        _PROCESS_KEY,
        _provenance_payload(provenance),
        hashlib.sha256,
    ).hexdigest()
    _LAST_PROVIDER_PROVENANCE.set(provenance)
    return dict(provenance)


def take_provider_call_provenance() -> dict[str, Any] | None:
    """Consume the current task's provider-bound review provenance once."""

    value = _LAST_PROVIDER_PROVENANCE.get()
    _LAST_PROVIDER_PROVENANCE.set(None)
    if not _verify_provider_call_provenance(value):
        return None
    return dict(value) if isinstance(value, dict) else None


def _verify_provider_call_provenance(
    value: object,
    *,
    require_ledger_commit: bool = True,
) -> bool:
    if not isinstance(value, dict):
        return False
    supplied = value.get(_PROVENANCE_ATTESTATION_FIELD)
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    expected = hmac.new(
        _PROCESS_KEY,
        _provenance_payload(value),
        hashlib.sha256,
    ).hexdigest()
    return bool(
        hmac.compare_digest(supplied, expected)
        and value.get(_CONTEXT_FIELD) == _context_digest()
        and re.fullmatch(r"[0-9a-f]{64}", str(value.get(_REQUEST_FIELD) or ""))
        and re.fullmatch(
            r"[0-9a-f]{64}", str(value.get(_REVIEWED_OUTPUT_FIELD) or "")
        )
        and re.fullmatch(r"[0-9a-f]{32}", str(value.get(_NONCE_FIELD) or ""))
        and re.fullmatch(
            r"[0-9a-f]{32}", str(value.get(_REVIEW_CALL_NONCE_FIELD) or "")
        )
        and str(value.get(_CALL_ID_FIELD) or "")
        and isinstance(value.get(_ATTEMPT_FIELD), int)
        and int(value.get(_ATTEMPT_FIELD)) >= 1
        and re.search(
            r"(?:^|[._-])review(?:[._-]|$)",
            str(value.get(_BUSINESS_ROLE_FIELD) or "").strip().casefold(),
        )
        and (
            not require_ledger_commit
            or value.get(_LEDGER_COMMITTED_FIELD) is True
        )
    )


def canonical_agent_output(value: str) -> str:
    return _THINK_RE.sub("", str(value or "")).strip()


def seal_route_receipt(
    receipt: dict[str, Any],
    *,
    authored_output: str | None = None,
) -> dict[str, Any]:
    """Mint or refresh the process-local authenticity tag in place."""

    receipt.setdefault(_KIND_FIELD, "route_call_v1")
    receipt.setdefault(_NONCE_FIELD, secrets.token_hex(16))
    receipt.setdefault(_CONTEXT_FIELD, _context_digest())
    receipt.setdefault(_ROLE_FIELD, "provider_call")
    receipt.setdefault(_SOURCE_FIELD, None)
    if authored_output is not None:
        receipt[_OUTPUT_FIELD] = _digest_text(authored_output)
        receipt[_CANONICAL_OUTPUT_FIELD] = _digest_text(
            canonical_agent_output(authored_output)
        )
    else:
        receipt.setdefault(_OUTPUT_FIELD, None)
        receipt.setdefault(_CANONICAL_OUTPUT_FIELD, None)
    receipt.setdefault(_REVIEWED_OUTPUT_FIELD, None)
    receipt.pop(ATTESTATION_FIELD, None)
    receipt[ATTESTATION_FIELD] = hmac.new(
        _PROCESS_KEY,
        _payload(receipt),
        hashlib.sha256,
    ).hexdigest()
    return receipt


def verify_route_receipt_attestation(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    supplied = value.get(ATTESTATION_FIELD)
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    expected = hmac.new(_PROCESS_KEY, _payload(value), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)


def verify_provider_call_receipt(
    value: object,
    *,
    authored_output: str | None = None,
) -> bool:
    """Verify one base provider-call receipt in the current request context.

    Review and lineage consumers must use the original attested receipt.  A
    structurally identical dictionary, a final-answer derivative, or a receipt
    replayed from another public Agent turn has no call authority.
    """

    if not verify_route_receipt_attestation(value) or not isinstance(value, dict):
        return False
    if not (
        value.get(_KIND_FIELD) == "route_call_v1"
        and value.get(_ROLE_FIELD) == "provider_call"
        and value.get(_CONTEXT_FIELD) == _context_digest()
        and value.get(_SOURCE_FIELD) is None
    ):
        return False
    if authored_output is None:
        return True
    return _digest_text(authored_output) in {
        value.get(_OUTPUT_FIELD),
        value.get(_CANONICAL_OUTPUT_FIELD),
    }


def bind_model_review_receipt(
    receipt: dict[str, Any],
    *,
    provenance: dict[str, Any],
    verdict: str,
    reviewed_output_sha256: str,
    expected_provider_request_sha256: str,
) -> dict[str, Any]:
    """Derive a review proof only from the one provider-bound call envelope."""

    if not verify_provider_call_receipt(receipt, authored_output=verdict):
        raise ValueError("review source receipt is not an authentic provider verdict")
    if not _verify_provider_call_provenance(
        provenance,
        require_ledger_commit=False,
    ):
        raise ValueError("provider review provenance is invalid")
    if provenance.get(_LEDGER_COMMITTED_FIELD) is not True:
        raise ValueError("provider_call_ledger_uncommitted")
    digest = str(reviewed_output_sha256 or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("reviewed output digest is invalid")
    request_digest = str(expected_provider_request_sha256 or "")
    if not re.fullmatch(r"[0-9a-f]{64}", request_digest):
        raise ValueError("provider request digest is invalid")
    if not (
        provenance.get(_REVIEWED_OUTPUT_FIELD) == digest
        and provenance.get(_REQUEST_FIELD) == request_digest
        and provenance.get(_CONTEXT_FIELD) == receipt.get(_CONTEXT_FIELD)
        and str(provenance.get("requested_model") or "")
        == str(receipt.get("requested_model") or "")
        and str(provenance.get("actual_model") or "")
        == str(receipt.get("actual_model") or "")
        and str(provenance.get("provider") or "").strip().casefold()
        == str(receipt.get("provider") or "").strip().casefold()
        and str(provenance.get("upstream_model") or "")
        == str(receipt.get("upstream_model") or "")
        and (str(provenance.get("reported_model") or "").strip() or None)
        == (str(receipt.get("reported_model") or "").strip() or None)
        and (str(provenance.get("observed_model") or "").strip() or None)
        == (str(receipt.get("observed_model") or "").strip() or None)
        and (str(provenance.get("model_family") or "").strip() or None)
        == (str(receipt.get("model_family") or "").strip() or None)
        and (str(provenance.get("model_identity_error") or "").strip() or None)
        == (str(receipt.get("model_identity_error") or "").strip() or None)
        and (str(provenance.get("independence_domain") or "").strip() or None)
        == (str(receipt.get("independence_domain") or "").strip() or None)
        and (str(provenance.get("tier") or "").strip().casefold() or None)
        == (str(receipt.get("tier") or "").strip().casefold() or None)
        and provenance.get("flagship") == receipt.get("flagship")
        and _digest_text(verdict)
        in {
            provenance.get(_OUTPUT_FIELD),
            provenance.get(_CANONICAL_OUTPUT_FIELD),
        }
    ):
        raise ValueError("provider review provenance does not match the route call")
    provenance_attestation = str(
        provenance.get(_PROVENANCE_ATTESTATION_FIELD) or ""
    )
    if not _remember_once(_BOUND_PROVENANCE, provenance_attestation):
        raise ValueError("provider review provenance was already bound")
    bound = dict(receipt)
    bound[_KIND_FIELD] = "model_review_v1"
    bound[_NONCE_FIELD] = secrets.token_hex(16)
    bound[_CONTEXT_FIELD] = _context_digest()
    bound[_ROLE_FIELD] = "model_review"
    bound[_SOURCE_FIELD] = str(receipt.get(ATTESTATION_FIELD) or "")
    bound[_OUTPUT_FIELD] = _digest_text(verdict)
    bound[_CANONICAL_OUTPUT_FIELD] = _digest_text(canonical_agent_output(verdict))
    bound[_REVIEWED_OUTPUT_FIELD] = digest
    bound[_PROVENANCE_SOURCE_FIELD] = provenance_attestation
    for field in (
        _REQUEST_FIELD,
        _CALL_ID_FIELD,
        _ATTEMPT_FIELD,
        _TRACE_FIELD,
        _TURN_FIELD,
        _WORKFLOW_FIELD,
        _BUSINESS_ROLE_FIELD,
        _REVIEW_CALL_NONCE_FIELD,
        _LEDGER_COMMITTED_FIELD,
    ):
        bound[field] = provenance.get(field)
    return seal_route_receipt(bound)


def verify_model_review_receipt(
    value: object,
    *,
    verdict: str,
    reviewed_output_sha256: str,
    expected_provider_request_sha256: str,
) -> bool:
    """Verify a model-review proof for one exact verdict/candidate pair."""

    if not verify_route_receipt_attestation(value) or not isinstance(value, dict):
        return False
    digest = str(reviewed_output_sha256 or "")
    request_digest = str(expected_provider_request_sha256 or "")
    return bool(
        re.fullmatch(r"[0-9a-f]{64}", digest)
        and re.fullmatch(r"[0-9a-f]{64}", request_digest)
        and value.get(_KIND_FIELD) == "model_review_v1"
        and value.get(_ROLE_FIELD) == "model_review"
        and value.get(_CONTEXT_FIELD) == _context_digest()
        and isinstance(value.get(_SOURCE_FIELD), str)
        and len(str(value.get(_SOURCE_FIELD))) == 64
        and isinstance(value.get(_PROVENANCE_SOURCE_FIELD), str)
        and len(str(value.get(_PROVENANCE_SOURCE_FIELD))) == 64
        and value.get(_REQUEST_FIELD) == request_digest
        and str(value.get(_CALL_ID_FIELD) or "")
        and isinstance(value.get(_ATTEMPT_FIELD), int)
        and int(value.get(_ATTEMPT_FIELD)) >= 1
        and re.search(
            r"(?:^|[._-])review(?:[._-]|$)",
            str(value.get(_BUSINESS_ROLE_FIELD) or "").strip().casefold(),
        )
        and re.fullmatch(
            r"[0-9a-f]{32}", str(value.get(_REVIEW_CALL_NONCE_FIELD) or "")
        )
        and value.get(_OUTPUT_FIELD) == _digest_text(verdict)
        and value.get(_REVIEWED_OUTPUT_FIELD) == digest
        and value.get(_LEDGER_COMMITTED_FIELD) is True
    )


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _context_digest() -> str:
    return _digest_text(_AUTHOR_CONTEXT.get())


def set_agent_author_context(value: str) -> Token[str]:
    """Bind final-author evidence to one public Agent request/task context."""

    return _AUTHOR_CONTEXT.set(str(value))


def reset_agent_author_context(token: Token[str]) -> None:
    _AUTHOR_CONTEXT.reset(token)


def bind_agent_author_receipt(
    receipt: dict[str, Any],
    *,
    reply: str,
) -> dict[str, Any]:
    """Derive a final-answer proof from an authentic provider-call receipt."""

    if verify_agent_author_receipt(receipt, reply=reply):
        return dict(receipt)
    if not verify_route_receipt_attestation(receipt):
        raise ValueError("route receipt attestation is invalid")
    if (
        receipt.get(_KIND_FIELD) != "route_call_v1"
        or receipt.get(_ROLE_FIELD) != "provider_call"
        or receipt.get(_CONTEXT_FIELD) != _context_digest()
        or _digest_text(reply)
        not in {
            receipt.get(_OUTPUT_FIELD),
            receipt.get(_CANONICAL_OUTPUT_FIELD),
        }
    ):
        raise ValueError("route receipt is not the current final-answer source")
    bound = dict(receipt)
    bound[_KIND_FIELD] = "agent_final_answer_v1"
    bound[_NONCE_FIELD] = secrets.token_hex(16)
    bound[_CONTEXT_FIELD] = _context_digest()
    bound[_ROLE_FIELD] = "final_answer"
    bound[_SOURCE_FIELD] = str(receipt.get(ATTESTATION_FIELD) or "")
    # The base call may be canonically stripped by the trusted producer, but
    # the final public answer is bound byte-for-byte.  Verification must never
    # erase an injected region and accidentally authenticate a different text.
    bound[_OUTPUT_FIELD] = _digest_text(reply)
    bound[_CANONICAL_OUTPUT_FIELD] = _digest_text(canonical_agent_output(reply))
    return seal_route_receipt(bound)


def verify_agent_author_receipt(value: object, *, reply: str) -> bool:
    if not verify_route_receipt_attestation(value) or not isinstance(value, dict):
        return False
    return bool(
        value.get(_KIND_FIELD) == "agent_final_answer_v1"
        and value.get(_ROLE_FIELD) == "final_answer"
        and value.get(_CONTEXT_FIELD) == _context_digest()
        and isinstance(value.get(_SOURCE_FIELD), str)
        and len(str(value.get(_SOURCE_FIELD))) == 64
        and value.get(_OUTPUT_FIELD) == _digest_text(reply)
    )
