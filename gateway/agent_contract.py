"""Closed public contract for Agent Turn terminal results."""

from __future__ import annotations

import hashlib
import math
import re
import base64
import binascii
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable

from gateway.route_attestation import ATTESTATION_FIELD, verify_agent_author_receipt


AGENT_TERMINAL_OUTCOMES = frozenset(
    {
        "completed",
        "completed_unverified",
        "partial",
        "failed",
        "blocked",
        "accepted_async",
        "rejected_capacity",
    }
)

AGENT_STOPPED_REASONS = frozenset(
    {
        "wall_cap",
        "stall",
        "max_steps",
        "capability_violation",
        "empty_response",
        "error",
    }
)

_MAX_AGENT_REPLY_BYTES = 1024 * 1024
_MAX_AGENT_ID_BYTES = 512
_LOCAL_AGENT_AUTHOR = "nachuan-engine"
_UNDO_RECEIPT_RE = re.compile(r"[A-Za-z0-9_-]{16,8192}\.[A-Za-z0-9_-]{16,128}")
_PUBLIC_VIDEO_TASK_RE = re.compile(
    r"(?:nvt1_[0-9a-f]{64}|studio:[0-9a-f]{12})"
)
_PUBLIC_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}")
_PUBLIC_ASSET_URL_RE = re.compile(
    r"/v1/paid-media/assets/nma1_[A-Za-z0-9_-]{43}"
)
_MAX_PUBLIC_CHANGE_BYTES = 4 * 1024 * 1024
_MAX_PUBLIC_MEDIA_BYTES = 8 * 1024 * 1024


class AgentResultContractError(ValueError):
    """The orchestrator returned a malformed or contradictory terminal result."""


def _fail() -> None:
    raise AgentResultContractError("invalid Agent result")


def _bounded_id(value: object) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        if len(value.encode("utf-8")) > _MAX_AGENT_ID_BYTES:
            return False
    except UnicodeError:
        return False
    return not any(ord(char) < 32 or ord(char) == 127 for char in value)


def validate_agent_result(value: object) -> dict[str, Any]:
    """Validate truthfulness before a result is persisted, replayed, or returned.

    HTTP success only transports this document.  It must not promote an
    unverified, blocked, or merely accepted asynchronous Turn to ``completed``.
    """

    if not isinstance(value, dict):
        _fail()
    reply = value.get("reply")
    model = value.get("model")
    outcome = value.get("outcome")
    blocked = value.get("blocked")
    if (
        not isinstance(reply, str)
        or not reply.strip()
        or not _bounded_id(model)
        or not isinstance(outcome, str)
        or outcome not in AGENT_TERMINAL_OUTCOMES
        or type(blocked) is not bool
    ):
        _fail()
    try:
        if len(reply.encode("utf-8")) > _MAX_AGENT_REPLY_BYTES:
            _fail()
    except UnicodeError:
        _fail()

    for field in ("reviewed", "verified", "machine_verified"):
        item = value.get(field)
        if item is not None and type(item) is not bool:
            _fail()

    stopped_reason = value.get("stopped_reason")
    if stopped_reason is not None:
        if (
            not isinstance(stopped_reason, str)
            or stopped_reason not in AGENT_STOPPED_REASONS
            or outcome not in {"partial", "failed", "blocked"}
        ):
            _fail()

    must_be_blocked = outcome in {"blocked", "rejected_capacity"}
    if blocked is not must_be_blocked:
        _fail()

    verified = value.get("verified") is True
    machine_verified = value.get("machine_verified") is True
    if outcome == "completed":
        if not (verified and machine_verified):
            _fail()
    elif verified or machine_verified:
        _fail()

    if outcome == "accepted_async" and not any(
        _bounded_id(value.get(field))
        for field in ("video_task", "job_id", "task_id")
    ):
        _fail()
    return value


def _verified_receipt_model(value: object, *, reply: str) -> str | None:
    """Return a model only from a complete, internally verified route receipt."""

    if not isinstance(value, dict):
        return None
    if not verify_agent_author_receipt(value, reply=reply):
        if ATTESTATION_FIELD in value:
            _fail()
        return None
    if value.get("route_receipt_version") != 1:
        return None
    actual_model = value.get("actual_model")
    if not _bounded_id(actual_model):
        return None
    legacy_model = value.get("model")
    if legacy_model is not None and legacy_model != actual_model:
        _fail()
    if value.get("model_identity_error") is not None:
        return None
    # These fields are produced by route_receipt only after the adapter has
    # verified response.model against the frozen route.  A bare model string or
    # a partial receipt never grants public authorship.
    for field in ("provider", "upstream_model", "observed_model", "model_family"):
        if not _bounded_id(value.get(field)):
            return None
    return str(actual_model)


def _trusted_final_model(result: dict[str, Any]) -> str | None:
    receipts: list[object] = []
    if "final_route_receipt" in result:
        receipts.append(result.get("final_route_receipt"))
    route_meta = result.get("_route")
    if isinstance(route_meta, dict):
        if "final_route_receipt" in route_meta:
            receipts.append(route_meta.get("final_route_receipt"))
        elif route_meta.get("route_receipt_version") is not None:
            receipts.append(route_meta)

    trusted: str | None = None
    for receipt in receipts:
        candidate = _verified_receipt_model(receipt, reply=str(result.get("reply") or ""))
        if candidate is None:
            continue
        if trusted is not None and candidate != trusted:
            _fail()
        trusted = candidate
    if receipts:
        return trusted
    return None


def _record_unverified_model_claims(
    result: dict[str, Any],
    *extra_values: object,
) -> None:
    values = list(extra_values)
    for field in (
        "claimed_model",
        "requested_model",
        "claimed_actual_model",
    ):
        values.append(result.pop(field, None))
    clean = sorted(
        {
            value
            for value in values
            if isinstance(value, str) and value and value != _LOCAL_AGENT_AUTHOR
        }
    )
    if clean:
        payload = b"\x00".join(value.encode("utf-8", errors="replace") for value in clean)
        result["unverified_model_sha256"] = hashlib.sha256(payload).hexdigest()


def _seal_model_attribution(result: dict[str, Any]) -> None:
    """Bind public ``model`` to verified final-author evidence or downgrade it."""

    public_model = result.get("model")
    trusted_model = _trusted_final_model(result)
    if public_model == _LOCAL_AGENT_AUTHOR:
        if trusted_model is not None and trusted_model != _LOCAL_AGENT_AUTHOR:
            _fail()
        claimed_actual = result.get("actual_model")
        _record_unverified_model_claims(result, claimed_actual)
        result["actual_model"] = None
        return
    if trusted_model is not None:
        if public_model != trusted_model:
            _fail()
        if "actual_model" in result and result.get("actual_model") != trusted_model:
            _fail()
        result.setdefault("actual_model", trusted_model)
        return

    claimed_actual = result.get("actual_model")
    _record_unverified_model_claims(result, public_model, claimed_actual)
    result["actual_model"] = None
    result["model"] = _LOCAL_AGENT_AUTHOR


def _public_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if len(value.encode("utf-8", errors="ignore")) > 4096:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute():
        return None
    normalized = value.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts or any(part in {"", ".", ".."} or ":" in part for part in parts):
        return None
    return "/".join(parts)


def _public_usage(value: object) -> dict[str, int | float]:
    if not isinstance(value, dict):
        return {}
    projected: dict[str, int | float] = {}
    for field in (
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_tokens",
        "cost_usd",
    ):
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            continue
        if not math.isfinite(float(item)) or item < 0:
            continue
        projected[field] = item
    return projected


def _public_tool_log(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        "browser_action"
        if isinstance(item, str) and item.startswith("browser_")
        else "tool_action"
        for item in value[:256]
        if isinstance(item, str)
    ]


def _public_file_changes(
    value: object,
    *,
    validator: Callable[..., bool] | None,
) -> list[dict[str, str]]:
    if not isinstance(value, list) or validator is None:
        return []
    projected: list[dict[str, str]] = []
    byte_budget = _MAX_PUBLIC_CHANGE_BYTES
    for item in value[:128]:
        if not isinstance(item, dict):
            continue
        path = _public_relative_path(item.get("path"))
        before = item.get("before")
        after = item.get("after")
        receipt = item.get("undo_receipt")
        if (
            path is None
            or not isinstance(before, str)
            or not isinstance(after, str)
            or not isinstance(receipt, str)
            or _UNDO_RECEIPT_RE.fullmatch(receipt) is None
            or not validator(
                receipt,
                path=str(item.get("path")),
                before=before,
                after=after,
            )
        ):
            continue
        size = len(before.encode("utf-8", errors="replace")) + len(
            after.encode("utf-8", errors="replace")
        )
        if size > byte_budget:
            continue
        byte_budget -= size
        row = {
            "path": path,
            "before": before,
            "after": after,
            "undo_receipt": receipt,
        }
        projected.append(row)
    return projected


def _public_media(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    projected: list[str] = []
    byte_budget = _MAX_PUBLIC_MEDIA_BYTES
    for item in value[:16]:
        if not isinstance(item, str) or item != item.strip():
            continue
        if any(ord(char) < 32 or ord(char) == 127 for char in item):
            continue
        size = len(item.encode("utf-8", errors="replace"))
        if size > byte_budget:
            continue
        if _PUBLIC_ASSET_URL_RE.fullmatch(item) is None:
            if not item.startswith("data:image/"):
                continue
            head, separator, payload = item.partition(",")
            mime = head.removeprefix("data:").removesuffix(";base64").casefold()
            if (
                not separator
                or not head.casefold().endswith(";base64")
                or mime not in {"image/png", "image/jpeg", "image/gif", "image/webp"}
            ):
                continue
            try:
                raw = base64.b64decode(payload, validate=True)
            except (ValueError, binascii.Error):
                continue
            valid_magic = bool(
                raw.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a"))
                or (len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP")
            )
            if not valid_magic:
                continue
        byte_budget -= size
        projected.append(item)
    return projected


def _public_pending_videos(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    projected: list[dict[str, str]] = []
    for item in value[:16]:
        if not isinstance(item, dict):
            continue
        task_id = item.get("task_id")
        model = item.get("model")
        if (
            not isinstance(task_id, str)
            or _PUBLIC_VIDEO_TASK_RE.fullmatch(task_id) is None
            or not isinstance(model, str)
            or _PUBLIC_MODEL_RE.fullmatch(model) is None
        ):
            continue
        row = {"task_id": task_id, "model": model}
        projected.append(row)
    return projected


def project_public_agent_result(
    value: object,
    *,
    file_change_validator: Callable[..., bool] | None = None,
) -> dict[str, Any]:
    """Return only the bounded fields consumed by the Desktop Agent UI."""

    result = validate_agent_result(value)
    public: dict[str, Any] = {
        field: result[field]
        for field in (
            "reply",
            "model",
            "outcome",
            "blocked",
            "reviewed",
            "verified",
            "machine_verified",
        )
    }
    if "stopped_reason" in result:
        public["stopped_reason"] = result["stopped_reason"]
    steps = result.get("steps")
    if type(steps) is int and 0 <= steps <= 1000:
        public["steps"] = steps
    if "usage" in result:
        public["usage"] = _public_usage(result.get("usage"))
    if "tool_log" in result:
        public["tool_log"] = _public_tool_log(result.get("tool_log"))
    if "file_changes" in result:
        public["file_changes"] = _public_file_changes(
            result.get("file_changes"),
            validator=file_change_validator,
        )
    if "media" in result:
        public["media"] = _public_media(result.get("media"))
    if "pending_videos" in result:
        public["pending_videos"] = _public_pending_videos(
            result.get("pending_videos")
        )
    public_async_id = False
    for field in ("video_task", "task_id"):
        item = result.get(field)
        if isinstance(item, str) and _PUBLIC_VIDEO_TASK_RE.fullmatch(item):
            public[field] = item
            public_async_id = True
    job_id = result.get("job_id")
    if isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]{12}", job_id):
        public["job_id"] = job_id
        public_async_id = True
    if result.get("outcome") == "accepted_async" and not public_async_id:
        _fail()
    for field in ("needs_approval",):
        if type(result.get(field)) is bool:
            public[field] = result[field]
    approval_id = result.get("approval_id")
    if type(approval_id) is int and approval_id > 0:
        public["approval_id"] = approval_id
    for field in ("summary", "risk", "scope"):
        item = result.get(field)
        if isinstance(item, str) and len(item.encode("utf-8", errors="replace")) <= 8192:
            public[field] = item
    return public


def normalize_legacy_agent_result(value: object) -> dict[str, Any]:
    """Seal legacy internal Agent output into the closed public contract.

    This adapter only supplies fail-closed defaults.  In particular, an old
    producer that omitted verification metadata can become
    ``completed_unverified`` but can never be promoted to ``completed``.
    Explicit contradictory fields remain invalid and are rejected by
    :func:`validate_agent_result`.
    """

    if not isinstance(value, dict):
        _fail()
    result = dict(value)
    if "outcome" not in result:
        reply = result.get("reply")
        steps = result.get("steps")
        has_artifact_progress = bool(
            (type(steps) is int and steps > 0)
            or result.get("tool_log")
            or result.get("file_changes")
            or result.get("media")
            or result.get("pending_videos")
        )
        if result.get("stopped_reason"):
            result["outcome"] = "partial" if has_artifact_progress else "failed"
        elif not isinstance(reply, str) or not reply.strip():
            if not isinstance(reply, str):
                _fail()
            claimed_model = result.get("model")
            _record_unverified_model_claims(result, claimed_model)
            result.setdefault("actual_model", None)
            result["reply"] = (
                "模型未返回可显示内容，本轮未完成；请重试或更换模型。"
            )
            result["model"] = "nachuan-engine"
            result["stopped_reason"] = "empty_response"
            result["outcome"] = "partial" if has_artifact_progress else "failed"
        else:
            result["outcome"] = "completed_unverified"
    result.setdefault("reviewed", False)
    result.setdefault("verified", False)
    result.setdefault("machine_verified", False)
    result.setdefault(
        "blocked",
        result.get("outcome") in {"blocked", "rejected_capacity"},
    )
    _seal_model_attribution(result)
    return validate_agent_result(result)
