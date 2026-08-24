"""Dual-authority, no-replay recovery coordinator for channel queues."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key, require_approval_admin_key


_MAX_BODY_BYTES = 32 * 1024
_MAX_DECISION_FUTURE_SKEW_MS = 30_000
_AUTHORIZATION_DOMAIN = b"nachuan.channel-recovery.authorization/v1\0"
_FEISHU_BRIDGE_MODULE: ModuleType | None = None
_FEISHU_BRIDGE_LOCK = threading.Lock()

router = APIRouter(
    prefix="/admin/channel-recovery",
    dependencies=[
        Depends(require_api_key),
        Depends(require_approval_admin_key),
    ],
)


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
        headers={"Cache-Control": "no-store"},
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _reject_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("isolated Unicode surrogate")
        return
    if type(value) is list:
        for item in value:
            _reject_surrogates(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            _reject_surrogates(key)
            _reject_surrogates(item)


async def _bounded_json(request: Request) -> dict[str, Any]:
    media_type = str(request.headers.get("content-type") or "").split(";", 1)[0]
    if media_type.strip().casefold() != "application/json":
        raise _error(415, "channel_recovery_media_type", "application/json is required")
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        raise _error(400, "channel_recovery_invalid_body", "ambiguous content length")
    if lengths:
        try:
            declared = int(lengths[0], 10)
        except (TypeError, ValueError, OverflowError) as exc:
            raise _error(400, "channel_recovery_invalid_body", "invalid content length") from exc
        if declared < 0 or declared > _MAX_BODY_BYTES:
            raise _error(413, "channel_recovery_body_too_large", "request body is too large")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > _MAX_BODY_BYTES:
            raise _error(413, "channel_recovery_body_too_large", "request body is too large")
        chunks.append(chunk)
    try:
        body = json.loads(
            b"".join(chunks).decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _reject_surrogates(body)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise _error(422, "channel_recovery_invalid_body", "request body is invalid") from exc
    if type(body) is not dict:
        raise _error(422, "channel_recovery_invalid_body", "request body must be an object")
    return body


def _require_exact_fields(body: dict[str, Any], expected: set[str]) -> None:
    if set(body) != expected:
        raise _error(422, "channel_recovery_invalid_fields", "request fields do not match the closed schema")


def _validated_decision_clock(body: dict[str, Any]) -> tuple[int, int]:
    value = body.get("decided_at_ms")
    now_ms = int(time.time() * 1000)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > now_ms + _MAX_DECISION_FUTURE_SKEW_MS
    ):
        raise _error(
            422,
            "channel_recovery_invalid_decision",
            "channel recovery decision time is invalid",
        )
    return value, now_ms


def _weixin_bridge():
    return importlib.import_module("scripts.run_weixin_ilink_bridge")


def _feishu_bridge() -> ModuleType:
    """Load only Feishu's SQLite authority, never its channel SDK/client."""

    global _FEISHU_BRIDGE_MODULE
    if _FEISHU_BRIDGE_MODULE is not None:
        return _FEISHU_BRIDGE_MODULE
    with _FEISHU_BRIDGE_LOCK:
        if _FEISHU_BRIDGE_MODULE is not None:
            return _FEISHU_BRIDGE_MODULE
        path = Path(__file__).parents[1] / "scripts" / "run_feishu_bridge.py"
        module_name = "nachuan_feishu_recovery_state"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Feishu recovery state module is unavailable")
        module = importlib.util.module_from_spec(spec)
        module._NACHUAN_FEISHU_STATE_ONLY = True
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(module_name, None)
            raise
        if module._NACHUAN_FEISHU_STATE_ONLY is not True:
            sys.modules.pop(module_name, None)
            raise RuntimeError("Feishu recovery state-only boundary was not established")
        _FEISHU_BRIDGE_MODULE = module
        return module


def _translate_failure(error: BaseException) -> HTTPException:
    bridge = _weixin_bridge()
    if isinstance(error, ValueError):
        return _error(422, "channel_recovery_invalid_decision", str(error))
    if isinstance(error, bridge.WeixinRecoveryConflict):
        return _error(409, "channel_recovery_conflict", str(error))
    if isinstance(error, (sqlite3.Error, OSError)):
        return _error(503, "channel_recovery_unavailable", "channel recovery state is unavailable")
    return _error(503, "channel_recovery_unavailable", "channel recovery failed closed")


def _translate_feishu_failure(error: BaseException, bridge: ModuleType) -> HTTPException:
    if isinstance(error, ValueError):
        return _error(422, "channel_recovery_invalid_decision", str(error))
    if isinstance(error, (bridge.FeishuRecoveryConflict, bridge.FeishuQueueFull)):
        return _error(409, "channel_recovery_conflict", str(error))
    if isinstance(error, (sqlite3.Error, OSError)):
        return _error(503, "channel_recovery_unavailable", "channel recovery state is unavailable")
    return _error(503, "channel_recovery_unavailable", "channel recovery failed closed")


@router.post("/weixin/inspect")
async def inspect_weixin_recovery(request: Request) -> dict[str, object]:
    body = await _bounded_json(request)
    _require_exact_fields(body, {"target_kind", "target_key"})
    bridge = _weixin_bridge()
    try:
        snapshot = await run_in_threadpool(
            bridge._weixin_recovery_target_snapshot,
            body["target_kind"],
            body["target_key"],
        )
    except BaseException as exc:
        raise _translate_failure(exc) from exc
    return {
        **snapshot,
        "decision_id": secrets.token_hex(32),
        "decided_at_ms": int(time.time() * 1000),
    }


@router.post("/weixin/close-without-replay")
async def close_weixin_without_replay(request: Request) -> dict[str, object]:
    body = await _bounded_json(request)
    _require_exact_fields(
        body,
        {
            "target_kind",
            "target_key",
            "expected_before_digest",
            "decision_id",
            "decided_at_ms",
            "reason",
            "user_confirmed",
            "confirm_final",
        },
    )
    if body["user_confirmed"] is not True or body["confirm_final"] is not True:
        raise _error(
            422,
            "channel_recovery_confirmation_required",
            "channel recovery requires two explicit confirmations",
        )
    decided_at_ms, request_now_ms = _validated_decision_clock(body)
    bridge = _weixin_bridge()
    try:
        kind, key = bridge._validated_weixin_recovery_target(
            body["target_kind"], body["target_key"]
        )
        target_key_sha256 = bridge._weixin_recovery_target_key_sha256(kind, key)
        authorization = hashlib.sha256(
            _AUTHORIZATION_DOMAIN
            + json.dumps(
                {
                    "authority": "runtime-plus-approval-admin",
                    "confirm_final": True,
                    "decision_id": body["decision_id"],
                    "decided_at_ms": decided_at_ms,
                    "expected_before_digest": body["expected_before_digest"],
                    "target_key_sha256": target_key_sha256,
                    "target_kind": kind,
                    "user_confirmed": True,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
        fields = {
            "decision_id": body["decision_id"],
            "target_kind": kind,
            "target_key": key,
            "expected_before_digest": body["expected_before_digest"],
            "actor": "approval-admin:authenticated",
            "authorization": authorization,
            "reason": body["reason"],
            "decided_at_ms": decided_at_ms,
        }
        recovery_request = bridge._WeixinCloseWithoutReplayRequest(
            operation_digest=bridge._weixin_close_without_replay_operation_digest(
                **fields
            ),
            **fields,
        )
        result = await run_in_threadpool(
            bridge._weixin_close_without_replay,
            recovery_request,
            closed_at_ms=max(request_now_ms, decided_at_ms),
        )
    except BaseException as exc:
        if isinstance(exc, HTTPException):
            raise
        raise _translate_failure(exc) from exc
    return {
        "schema": "nachuan.channel-recovery-result.v1",
        "operation_digest": result.operation_digest,
        "receipt_sha256": result.receipt_sha256,
        "affected_counts": {
            "inbound": result.affected_inbound_count,
            "delivery": result.affected_delivery_count,
            "video": result.affected_video_count,
        },
        "applied": result.applied,
    }


@router.post("/feishu/inspect")
async def inspect_feishu_recovery(request: Request) -> dict[str, object]:
    body = await _bounded_json(request)
    _require_exact_fields(body, {"target_kind", "target_key"})
    bridge = _feishu_bridge()
    try:
        snapshot = await run_in_threadpool(
            bridge._recovery_target_snapshot,
            body["target_kind"],
            body["target_key"],
        )
    except BaseException as exc:
        raise _translate_feishu_failure(exc, bridge) from exc
    return {
        **snapshot,
        "decision_id": secrets.token_hex(32),
        "decided_at_ms": int(time.time() * 1000),
    }


@router.post("/feishu/close-without-replay")
async def close_feishu_without_replay(request: Request) -> dict[str, object]:
    body = await _bounded_json(request)
    _require_exact_fields(
        body,
        {
            "target_kind",
            "target_key",
            "expected_before_digest",
            "decision_id",
            "decided_at_ms",
            "reason",
            "user_confirmed",
            "confirm_final",
        },
    )
    if body["user_confirmed"] is not True or body["confirm_final"] is not True:
        raise _error(
            422,
            "channel_recovery_confirmation_required",
            "channel recovery requires two explicit confirmations",
        )
    decided_at_ms, request_now_ms = _validated_decision_clock(body)
    bridge = _feishu_bridge()
    try:
        kind, key = bridge._validated_recovery_target(
            body["target_kind"], body["target_key"]
        )
        target_key_sha256 = bridge._recovery_target_key_sha256(kind, key)
        authorization = hashlib.sha256(
            _AUTHORIZATION_DOMAIN
            + json.dumps(
                {
                    "authority": "runtime-plus-approval-admin",
                    "channel": "feishu",
                    "confirm_final": True,
                    "decision_id": body["decision_id"],
                    "decided_at_ms": decided_at_ms,
                    "expected_before_digest": body["expected_before_digest"],
                    "target_key_sha256": target_key_sha256,
                    "target_kind": kind,
                    "user_confirmed": True,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
        fields = {
            "decision_id": body["decision_id"],
            "target_kind": kind,
            "target_key": key,
            "expected_before_digest": body["expected_before_digest"],
            "actor": "approval-admin:authenticated",
            "authorization": authorization,
            "reason": body["reason"],
            "decided_at_ms": decided_at_ms,
        }
        recovery_request = bridge._FeishuCloseWithoutReplayRequest(
            operation_digest=bridge._close_without_replay_operation_digest(**fields),
            **fields,
        )
        result = await run_in_threadpool(
            bridge._close_without_replay,
            recovery_request,
            closed_at_ms=max(request_now_ms, decided_at_ms),
        )
    except BaseException as exc:
        if isinstance(exc, HTTPException):
            raise
        raise _translate_feishu_failure(exc, bridge) from exc
    return {
        "schema": "nachuan.channel-recovery-result.v1",
        "operation_digest": result.operation_digest,
        "receipt_sha256": result.receipt_sha256,
        "affected_counts": {
            "inbox": result.affected_inbox_count,
            "outbox": result.affected_outbox_count,
            "video": result.affected_video_count,
        },
        "applied": result.applied,
    }
