"""Dual-authority, bounded control plane for privacy rights orchestration.

These endpoints accept digests and closed step metadata only.  They do not
accept customer content, perform deletion themselves, or treat an enqueued job
as completion; store adapters must return receipts to the durable ledger.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from functools import partial
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key, require_approval_admin_key
from gateway.config import get_settings
from gateway.privacy_execution import (
    PrivacyExecutionEngine,
    PrivacyExecutionError,
)
from gateway.privacy_rights import (
    PrivacyRightsCapacity,
    PrivacyRightsConflict,
    PrivacyRightsIncomplete,
    PrivacyRightsLedger,
    PrivacyRightsNotFound,
    PrivacyRightsUnavailable,
    PrivacyRightsValidationError,
    RightsRequestSnapshot,
    RightsScopeStep,
)


MAX_BODY_BYTES = 64 * 1024
router = APIRouter(
    prefix="/admin/privacy-rights",
    dependencies=[
        Depends(require_api_key),
        Depends(require_approval_admin_key),
    ],
)


def initialize_privacy_rights(data_dir: str | Path) -> PrivacyRightsLedger | None:
    """Open the dedicated ledger without making ordinary chat startup brittle."""

    try:
        return PrivacyRightsLedger(Path(data_dir) / "privacy_rights.db")
    except PrivacyRightsUnavailable:
        return None


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
        headers={"Cache-Control": "no-store"},
    )


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _reject_isolated_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("isolated Unicode surrogate")
        return
    if type(value) is list:
        for item in value:
            _reject_isolated_surrogates(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            _reject_isolated_surrogates(key)
            _reject_isolated_surrogates(item)


async def _bounded_json_object(request: Request) -> dict[str, Any]:
    content_type = str(request.headers.get("content-type") or "")
    if content_type.split(";", 1)[0].strip().casefold() != "application/json":
        raise _error(415, "privacy_rights_media_type", "application/json is required")
    content_lengths = request.headers.getlist("content-length")
    if len(content_lengths) > 1:
        raise _error(400, "privacy_rights_invalid_body", "ambiguous content length")
    if content_lengths:
        try:
            declared = int(content_lengths[0], 10)
        except (TypeError, ValueError, OverflowError) as exc:
            raise _error(
                400, "privacy_rights_invalid_body", "invalid content length"
            ) from exc
        if declared < 0:
            raise _error(400, "privacy_rights_invalid_body", "invalid content length")
        if declared > MAX_BODY_BYTES:
            raise _error(413, "privacy_rights_body_too_large", "request body is too large")

    chunks: list[bytes] = []
    total = 0
    try:
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                raise _error(
                    413,
                    "privacy_rights_body_too_large",
                    "request body is too large",
                )
            chunks.append(bytes(chunk))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - transport errors are a closed 400
        raise _error(400, "privacy_rights_invalid_body", "request body is unavailable") from exc
    try:
        decoded = b"".join(chunks).decode("utf-8", errors="strict")
        document = json.loads(
            decoded,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_json_constant,
        )
        _reject_isolated_surrogates(document)
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _error(422, "privacy_rights_invalid_body", "body must be strict JSON") from exc
    if type(document) is not dict:
        raise _error(422, "privacy_rights_invalid_body", "body must be a JSON object")
    return document


def _closed(
    body: dict[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    keys = set(body)
    if not required.issubset(keys) or bool(keys - required - optional):
        raise _error(422, "privacy_rights_invalid_body", "body fields are not allowed")
    return body


def _ledger(request: Request) -> PrivacyRightsLedger:
    ledger = getattr(request.app.state, "privacy_rights", None)
    if not isinstance(ledger, PrivacyRightsLedger):
        raise _error(
            503,
            "privacy_rights_unavailable",
            "privacy rights storage is unavailable",
        )
    return ledger


async def _call(method: Callable[..., RightsRequestSnapshot], **kwargs: Any) -> dict:
    try:
        snapshot = await run_in_threadpool(partial(method, **kwargs))
    except PrivacyRightsValidationError as exc:
        raise _error(422, "privacy_rights_invalid", str(exc)) from exc
    except PrivacyRightsNotFound as exc:
        raise _error(404, "privacy_rights_not_found", "rights request was not found") from exc
    except PrivacyRightsIncomplete as exc:
        raise _error(409, "privacy_rights_incomplete", str(exc)) from exc
    except PrivacyRightsCapacity as exc:
        raise _error(409, "privacy_rights_capacity", str(exc)) from exc
    except PrivacyRightsConflict as exc:
        raise _error(409, "privacy_rights_conflict", str(exc)) from exc
    except PrivacyRightsUnavailable as exc:
        raise _error(
            503,
            "privacy_rights_unavailable",
            "privacy rights storage is unavailable",
        ) from exc
    return asdict(snapshot)


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


@router.post("/requests")
async def submit_request(request: Request, response: Response) -> dict:
    ledger = _ledger(request)
    body = _closed(
        await _bounded_json_object(request),
        required=frozenset({"request_id", "action", "subject_digest"}),
    )
    result = await _call(
        ledger.submit,
        request_id=body["request_id"],
        action=body["action"],
        subject_digest=body["subject_digest"],
    )
    _no_store(response)
    return result


@router.get("/requests/{request_id}")
async def request_snapshot(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    result = await _call(_ledger(request).snapshot, request_id=request_id)
    _no_store(response)
    return result


@router.post("/requests/{request_id}/identity")
async def verify_identity(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    ledger = _ledger(request)
    body = _closed(
        await _bounded_json_object(request),
        required=frozenset({"evidence_sha256"}),
    )
    result = await _call(
        ledger.verify_identity,
        request_id=request_id,
        evidence_sha256=body["evidence_sha256"],
    )
    _no_store(response)
    return result


@router.post("/requests/{request_id}/scope")
async def freeze_scope(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    ledger = _ledger(request)
    body = _closed(
        await _bounded_json_object(request),
        required=frozenset({"steps"}),
    )
    raw_steps = body["steps"]
    if type(raw_steps) is not list or not 1 <= len(raw_steps) <= 256:
        raise _error(422, "privacy_rights_invalid_body", "steps must contain 1 to 256 items")
    steps: list[RightsScopeStep] = []
    for raw in raw_steps:
        if type(raw) is not dict:
            raise _error(422, "privacy_rights_invalid_body", "scope step must be an object")
        item = _closed(
            raw,
            required=frozenset({"step_id", "store_id", "operation"}),
            optional=frozenset({"depends_on"}),
        )
        dependencies = item.get("depends_on", [])
        if type(dependencies) is not list or not all(
            isinstance(value, str) for value in dependencies
        ):
            raise _error(
                422,
                "privacy_rights_invalid_body",
                "depends_on must be an array of strings",
            )
        steps.append(
            RightsScopeStep(
                step_id=item["step_id"],
                store_id=item["store_id"],
                operation=item["operation"],
                depends_on=tuple(dependencies),
            )
        )
    result = await _call(
        ledger.freeze_scope,
        request_id=request_id,
        steps=tuple(steps),
    )
    _no_store(response)
    return result


async def _empty_action(
    request_id: str,
    request: Request,
    response: Response,
    method_name: str,
) -> dict:
    ledger = _ledger(request)
    _closed(await _bounded_json_object(request), required=frozenset())
    result = await _call(getattr(ledger, method_name), request_id=request_id)
    _no_store(response)
    return result


@router.post("/requests/{request_id}/start")
async def start_request(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    return await _empty_action(request_id, request, response, "start")


@router.post("/requests/{request_id}/receipts")
async def record_receipt(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    ledger = _ledger(request)
    body = _closed(
        await _bounded_json_object(request),
        required=frozenset(
            {"step_id", "receipt_id", "outcome", "evidence_sha256"}
        ),
        optional=frozenset({"affected_count", "error_code"}),
    )
    result = await _call(
        ledger.record_receipt,
        request_id=request_id,
        step_id=body["step_id"],
        receipt_id=body["receipt_id"],
        outcome=body["outcome"],
        evidence_sha256=body["evidence_sha256"],
        affected_count=body.get("affected_count"),
        error_code=body.get("error_code"),
    )
    _no_store(response)
    return result


@router.post("/requests/{request_id}/finalize")
async def finalize_request(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    return await _empty_action(request_id, request, response, "finalize")


@router.post("/requests/{request_id}/reject")
async def reject_request(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    ledger = _ledger(request)
    body = _closed(
        await _bounded_json_object(request),
        required=frozenset({"reason_code", "evidence_sha256"}),
    )
    result = await _call(
        ledger.reject,
        request_id=request_id,
        reason_code=body["reason_code"],
        evidence_sha256=body["evidence_sha256"],
    )
    _no_store(response)
    return result


def _execution_engine(request: Request) -> PrivacyExecutionEngine:
    engine = getattr(request.app.state, "privacy_execution", None)
    if isinstance(engine, PrivacyExecutionEngine):
        return engine
    # The gateway owns the data root; tests inject a tmp-rooted engine.
    data_dir = Path(get_settings().usage_db_path).parent
    engine = PrivacyExecutionEngine(data_dir)
    request.app.state.privacy_execution = engine
    return engine


def _drop_conversation_runtime_cache(request: Request, keys: list[str]) -> int:
    """Best-effort drop of process-local conversation caches after erasure.

    Durable deletion already happened at the store layer; the live
    ConversationStore also self-invalidates on its next access through the
    data_version check.  This call only shrinks the stale-read window and is
    deliberately not part of any durable receipt.
    """

    conversations = getattr(request.app.state, "conversations", None)
    clear = getattr(conversations, "clear", None)
    if not callable(clear):
        return 0
    dropped = 0
    for key in keys:
        try:
            clear(key)
            dropped += 1
        except Exception:  # noqa: BLE001 -- cache drop never masks the receipt
            continue
    return dropped


@router.post("/requests/{request_id}/execute")
async def execute_request(
    request_id: str,
    request: Request,
    response: Response,
) -> dict:
    """Run the frozen scope through the four-store adapters, honestly.

    Every executed step writes an NCPR receipt; steps without an adapter or
    with pending dependencies are reported as skipped and never receive a
    fabricated receipt.  The request is never finalized here.
    """

    ledger = _ledger(request)
    _closed(await _bounded_json_object(request), required=frozenset())
    engine = _execution_engine(request)
    try:
        report = await run_in_threadpool(
            engine.execute_request, ledger, request_id=request_id
        )
    except PrivacyRightsValidationError as exc:
        raise _error(422, "privacy_rights_invalid", str(exc)) from exc
    except PrivacyRightsNotFound as exc:
        raise _error(404, "privacy_rights_not_found", "rights request was not found") from exc
    except PrivacyRightsIncomplete as exc:
        raise _error(409, "privacy_rights_incomplete", str(exc)) from exc
    except PrivacyRightsCapacity as exc:
        raise _error(409, "privacy_rights_capacity", str(exc)) from exc
    except PrivacyRightsConflict as exc:
        raise _error(409, "privacy_rights_conflict", str(exc)) from exc
    except (PrivacyRightsUnavailable, PrivacyExecutionError) as exc:
        raise _error(
            503,
            "privacy_rights_unavailable",
            "privacy rights execution is unavailable",
        ) from exc
    conversation_keys = [
        key
        for step in report.executed
        if step.step_id == "erase-conversations" and step.outcome == "completed"
        for key in step.affected_keys
    ]
    dropped = _drop_conversation_runtime_cache(request, conversation_keys)
    _no_store(response)
    return {
        "snapshot": asdict(report.snapshot),
        "executed": [
            {
                "step_id": step.step_id,
                "outcome": step.outcome,
                "evidence_sha256": step.evidence_sha256,
                "affected_count": step.affected_count,
                "error_code": step.error_code,
            }
            for step in report.executed
        ],
        "skipped": [
            {"step_id": step.step_id, "reason": step.reason}
            for step in report.skipped
        ],
        "runtime_cache_dropped": dropped,
    }


@router.post("/retention/run")
async def run_retention(request: Request, response: Response) -> dict:
    """Enforce an explicit per-store retention window with tombstones.

    The caller names each store and its maximum age; every expired row is
    tombstoned before erasure.  Locked stores report a retryable outcome and
    unknown schemas a permanent one — neither is ever reported complete.
    """

    _ledger(request)
    body = _closed(
        await _bounded_json_object(request),
        required=frozenset({"stores"}),
    )
    raw_stores = body["stores"]
    if type(raw_stores) is not dict or not 1 <= len(raw_stores) <= 4:
        raise _error(
            422, "privacy_rights_invalid_body", "stores must name 1 to 4 stores"
        )
    engine = _execution_engine(request)
    results = []
    for store_id in sorted(raw_stores):
        raw_config = raw_stores[store_id]
        if type(raw_config) is not dict or set(raw_config) != {"max_age_seconds"}:
            raise _error(
                422,
                "privacy_rights_invalid_body",
                "each store requires exactly max_age_seconds",
            )
        max_age_seconds = raw_config["max_age_seconds"]
        try:
            outcome = await run_in_threadpool(
                lambda sid=store_id, age=max_age_seconds: engine.run_retention(
                    store_id=sid, max_age_seconds=age
                )
            )
        except ValueError as exc:
            raise _error(422, "privacy_rights_invalid", str(exc)) from exc
        results.append(
            {
                "store_id": store_id,
                "outcome": outcome.outcome,
                "affected_count": outcome.affected_count,
                "evidence_sha256": outcome.evidence_sha256,
                "error_code": outcome.error_code,
            }
        )
    _no_store(response)
    return {"stores": results}
