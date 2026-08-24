"""管理 API：供桌面「连接中心」调用（列目录 / 存连接 / 测试 / 删除）。

全部需要网关虚拟 Key 鉴权；密钥仅入连接存储，不回显、不打日志。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from gateway.auth import require_api_key, require_approval_admin_key
from gateway.catalog import preset, preset_models, rank_sort_key
from gateway.connections import (
    is_quarantine_handle,
    normalize_base_url,
    normalize_connection_candidate,
    normalize_provider_name,
    preserved_credential_target_matches,
)
from gateway.config import get_settings
from gateway.failover import (
    DEFAULT_ATTEMPT_TIMEOUT_SEC,
    DEFAULT_TOTAL_TIMEOUT_SEC,
    chat_once_with_deadline,
)
from gateway.pricing import cost_for
from gateway.provider_call_ledger import (
    ProviderCallLedgerUnavailable,
    bind_provider_call_scope,
    configured_provider_call_ledger,
)
from gateway.providers.kimi_subscription import (
    KIMI_CONNECTION_REASON_CODES,
    KimiSubscriptionProviderError,
)
from gateway.providers.perplexity import perplexity_model_catalog_url
from gateway.schemas import ChatCompletionRequest
from gateway.router import ModelRouteConflictError
from gateway.secure_store import SecureStorageError
from gateway.weixin_idempotency import WeixinIdempotencyUnavailable
from orchestrator.agent import ConversationReceiptUnavailable

router = APIRouter(prefix="/admin", dependencies=[Depends(require_api_key)])

# A one-token connectivity probe is interactive UI work.  Keep an independent
# hard cap even when the provider itself is configured for a 180/300s timeout.
_CONNECTION_TEST_ATTEMPT_TIMEOUT_SEC = min(DEFAULT_ATTEMPT_TIMEOUT_SEC, 10.0)
_CONNECTION_TEST_TOTAL_TIMEOUT_SEC = min(DEFAULT_TOTAL_TIMEOUT_SEC, 15.0)
_MAX_DECLARED_CONNECTION_PROBE_TIMEOUT_SEC = 300.0
_DECLARED_CONNECTION_PROBE_TOTAL_GRACE_SEC = 15.0
_MODEL_CATALOG_BODY_LIMIT = 256 * 1024
_MODEL_CATALOG_COUNT_LIMIT = 200
_MODEL_CATALOG_TOTAL_TIMEOUT_SEC = 6.0
_LOCAL_DETECT_TOTAL_TIMEOUT_SEC = 3.0
_CONNECTION_MODEL_PROBE_CONCURRENCY = 4
_CONNECTION_VALIDATION_FAILURE = {
    "ok": False,
    "error": "连接验证失败，请检查凭据、模型与服务状态",
}
_KIMI_CONNECTION_PROVIDER = "kimi-code"


def _connection_validation_failure(
    provider: str,
    reason_code: object = None,
) -> dict[str, object]:
    failure: dict[str, object] = dict(_CONNECTION_VALIDATION_FAILURE)
    if provider == _KIMI_CONNECTION_PROVIDER:
        failure["reason_code"] = (
            reason_code
            if isinstance(reason_code, str)
            and reason_code in KIMI_CONNECTION_REASON_CODES
            else "connector_unavailable"
        )
    return failure


def _connection_probe_deadlines(provider: object) -> tuple[float, float]:
    declared = getattr(provider, "connection_probe_timeout_s", None)
    if (
        isinstance(declared, bool)
        or not isinstance(declared, (int, float))
        or not math.isfinite(float(declared))
        or float(declared) <= 0
        or float(declared) > _MAX_DECLARED_CONNECTION_PROBE_TIMEOUT_SEC
    ):
        return (
            _CONNECTION_TEST_ATTEMPT_TIMEOUT_SEC,
            _CONNECTION_TEST_TOTAL_TIMEOUT_SEC,
        )
    attempt = float(declared)
    return (
        attempt,
        attempt + _DECLARED_CONNECTION_PROBE_TOTAL_GRACE_SEC,
    )


@dataclass
class _ProviderConnectLock:
    lock: asyncio.Lock
    users: int = 0


@dataclass(frozen=True)
class _ConnectionProbeResult:
    succeeded: bool
    reason_code: str | None = None


class _ConnectionConnectLocks:
    """Bounded per-provider locks scoped to one ASGI application/event loop."""

    def __init__(self) -> None:
        self._guard = asyncio.Lock()
        self._promotion_lock = asyncio.Lock()
        self._entries: dict[str, _ProviderConnectLock] = {}

    @asynccontextmanager
    async def hold(self, provider: str) -> AsyncIterator[None]:
        async with self._guard:
            entry = self._entries.get(provider)
            if entry is None:
                entry = _ProviderConnectLock(asyncio.Lock())
                self._entries[provider] = entry
            entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            async with self._guard:
                entry.users -= 1
                if entry.users == 0 and self._entries.get(provider) is entry:
                    self._entries.pop(provider, None)

    @asynccontextmanager
    async def promote(self) -> AsyncIterator[None]:
        # Router reload swaps one process-wide table.  Different providers may
        # validate concurrently, but their durable promotion must be ordered.
        async with self._promotion_lock:
            yield


def _connection_connect_locks(request: Request) -> _ConnectionConnectLocks:
    locks = getattr(request.app.state, "connection_connect_locks", None)
    if locks is None:
        locks = _ConnectionConnectLocks()
        request.app.state.connection_connect_locks = locks
    return locks


class _ConnectionPromotionRolledBack(RuntimeError):
    pass


class _ConnectionPromotionIndeterminate(RuntimeError):
    pass


class _ConnectionDiscoveryUnavailable(RuntimeError):
    pass


async def _promote_verified_connection(
    request: Request,
    provider: str,
    candidate: dict,
    *,
    served_receipt: dict | None = None,
) -> dict:
    store = request.app.state.store
    # Re-check under the process-wide promotion lock.  A different provider may
    # have claimed the short id while this candidate was performing probes.
    # Reassigning only the virtual alias is safe: upstream identity and the
    # exact credential that were probed remain unchanged.
    routed_candidate = request.app.state.router.assign_available_model_ids(
        provider, candidate
    )
    verified = store.mark_verified(provider, routed_candidate)
    if served_receipt is not None:
        verified = store.mark_actual_served(
            provider, verified, receipt=served_receipt
        )
    request.app.state.router.assert_connection_model_ids_available(provider, verified)
    previous = store.set(provider, verified)
    try:
        await request.app.state.router.reload_connection(provider)
    except Exception as exc:
        try:
            store.restore(previous)
        except Exception as rollback_exc:
            raise _ConnectionPromotionIndeterminate from rollback_exc
        raise _ConnectionPromotionRolledBack from exc
    return verified


@router.get("/catalog")
async def get_catalog(request: Request) -> dict:
    """内置目录：各来源 + 候选模型，供 UI 展示打勾。"""
    return {"providers": request.app.state.router.catalog_view()}


@router.get("/connections")
async def list_connections(request: Request) -> dict:
    """已保存的连接（api_key 已掩码）。"""
    return request.app.state.store.masked()


@router.get("/usage")
async def usage_summary(request: Request) -> dict:
    """非财务看板；逐 provider attempt 的财务真相在 provider_calls。"""
    out = []
    total_actual = 0.0
    for r in request.app.state.usage.summary():
        ci = cost_for(
            r["provider"], r["prompt_tokens"], r["completion_tokens"], r.get("actual_cost_usd", 0.0)
        )
        if isinstance(ci["cost_usd"], (int, float)):
            total_actual += float(ci["cost_usd"])
        out.append({**r, "cost_usd": ci["cost_usd"], "cost_basis": ci["basis"]})
    return {
        "models": out,
        "total_cost_usd": None,
        "legacy_estimated_cost_usd": round(total_actual, 4),
        "financial_source": False,
        "financial_ledger_table": "provider_calls",
    }


@router.get("/financial-usage")
async def financial_usage_summary(
    period: Literal["day", "month", "all"] = "month",
) -> dict:
    """Authoritative attempt ledger; unknown token/cost values remain unknown."""

    def _load() -> dict:
        return configured_provider_call_ledger().financial_summary(period=period)

    try:
        return await run_in_threadpool(_load)
    except ProviderCallLedgerUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="逐调用财务账本不可用，成本与预算显示已故障关闭",
        ) from exc


@router.get("/durable-turn-recovery/{recovery_id}")
async def durable_turn_recovery(
    recovery_id: str,
    request: Request,
    response: Response,
    _: str = Depends(require_approval_admin_key),
) -> dict:
    """Correlate one durable channel Turn without exposing business data."""

    normalized = str(recovery_id or "")
    response.headers["Cache-Control"] = "no-store"
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        raise HTTPException(
            status_code=422,
            detail="recovery_id must be a 64-character lowercase hexadecimal digest",
        )
    idempotency_store = getattr(request.app.state, "weixin_idempotency", None)
    provider_ledger = getattr(request.app.state, "provider_call_ledger", None)
    conversation_store = getattr(request.app.state, "conversations", None)
    if (
        idempotency_store is None
        or provider_ledger is None
        or conversation_store is None
    ):
        raise HTTPException(
            status_code=503,
            detail="durable Turn recovery storage is unavailable",
        )
    try:
        idempotency, provider_calls, conversation_receipt = await asyncio.gather(
            run_in_threadpool(idempotency_store.recovery_snapshot, normalized),
            run_in_threadpool(provider_ledger.recovery_snapshot, normalized),
            run_in_threadpool(conversation_store.turn_receipt_snapshot, normalized),
        )
    except (
        WeixinIdempotencyUnavailable,
        ProviderCallLedgerUnavailable,
        ConversationReceiptUnavailable,
    ) as exc:
        raise HTTPException(
            status_code=503,
            detail="durable Turn recovery storage is unavailable",
        ) from exc
    if not any(
        bool(snapshot.get("found"))
        for snapshot in (idempotency, provider_calls, conversation_receipt)
    ):
        raise HTTPException(status_code=404, detail="recovery_id was not found")

    response_persisted = bool(idempotency.get("response_persisted"))
    replay_available = bool(conversation_receipt.get("replay_available"))
    recovery_notice_persisted = bool(
        idempotency.get("recovery_notice_persisted")
    )
    processing_lease_active = bool(idempotency.get("processing_lease_active"))
    if replay_available:
        recovery_state = "replay_available"
        operator_action_required = False
    elif recovery_notice_persisted:
        recovery_state = "operator_action_required"
        operator_action_required = True
    elif response_persisted:
        recovery_state = "completed"
        operator_action_required = False
    elif processing_lease_active:
        recovery_state = "in_progress"
        operator_action_required = False
    else:
        operator_action_required = bool(
            idempotency.get("provider_phase_entered")
            or provider_calls.get("requires_operator_recovery")
        )
        recovery_state = (
            "operator_action_required"
            if operator_action_required
            else "retry_safe"
        )
    return {
        "recovery_id": normalized,
        "recovery_state": recovery_state,
        "operator_action_required": operator_action_required,
        "idempotency": idempotency,
        "provider_calls": provider_calls,
        "conversation_receipt": conversation_receipt,
    }


@router.post("/connections/{provider}")
async def save_connection(
    provider: str,
    request: Request,
    _: str = Depends(require_approval_admin_key),
) -> dict:
    try:
        normalized_provider = normalize_provider_name(provider)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="连接名称不符合接入策略") from exc
    async with _connection_connect_locks(request).hold(normalized_provider):
        return await _save_connection_locked(normalized_provider, request)


def _catalog_media_models_safe_to_activate(
    provider: str,
    conn: dict,
    routes: list,
) -> set[str]:
    """Return exact built-in media routes that need no paid connection probe.

    A successful chat probe proves the shared credential/endpoint works.  It
    must not be reused as a fake media probe, and connection setup must never
    spend image/video quota.  We therefore activate only media models declared
    by the exact built-in provider preset, on its exact API root, and only when
    the provider implementation explicitly opts into the durable asset
    protocol for that modality.
    """

    provider_preset = preset(provider)
    if not isinstance(provider_preset, dict) or not routes:
        return set()
    configured_root = str(conn.get("base_url") or "").rstrip("/")
    preset_root = str(provider_preset.get("base_url") or "").rstrip("/")
    if not configured_root or configured_root != preset_root:
        return set()

    provider_client = routes[0].provider
    image_ready = "2" in frozenset(
        getattr(provider_client, "paid_media_asset_protocol_versions", ()) or ()
    )
    video_ready = "2" in frozenset(
        getattr(provider_client, "paid_media_video_asset_protocol_versions", ()) or ()
    )
    allowed_modalities = {
        modality
        for modality, ready in (("image", image_ready), ("video", video_ready))
        if ready
    }
    declared = {
        (
            str(model.get("upstream_model") or model.get("id") or "").strip(),
            str(model.get("modality") or "chat").strip().casefold(),
        )
        for model in provider_preset.get("models", [])
        if isinstance(model, dict)
    }
    return {
        str(model.get("id") or "")
        for model in conn.get("enabled_models", [])
        if isinstance(model, dict)
        and str(model.get("modality") or "chat").strip().casefold()
        in allowed_modalities
        and (
            str(model.get("upstream_model") or model.get("id") or "").strip(),
            str(model.get("modality") or "chat").strip().casefold(),
        )
        in declared
    }


async def _save_connection_locked(provider: str, request: Request) -> dict:
    """Validate one transient candidate, then promote it to live routing."""
    try:
        body = await request.json()
        required_fields = {
            "type",
            "api_key",
            "base_url",
            "enabled_models",
        }
        allowed_fields = required_fields | {"preserve_existing_credential"}
        if (
            not isinstance(body, dict)
            or not required_fields.issubset(body)
            or bool(set(body) - allowed_fields)
        ):
            raise ValueError("connection body is not a closed object")
        preserve_credential = body.get("preserve_existing_credential", False)
        if not isinstance(preserve_credential, bool):
            raise ValueError("preserve_existing_credential must be boolean")
        candidate_key = body["api_key"]
        if preserve_credential:
            if candidate_key != "":
                raise ValueError("preserved credential must not be supplied again")
            existing = request.app.state.store.get(provider)
            if (
                not isinstance(existing, dict)
                or not (
                    request.app.state.store.is_verified(provider, existing)
                    or request.app.state.store.can_reverify_imported_credential(
                        provider, existing
                    )
                )
                or not isinstance(existing.get("api_key"), str)
                or not existing["api_key"]
                or not preserved_credential_target_matches(
                    existing,
                    candidate_type=body.get("type"),
                    candidate_base_url=body.get("base_url"),
                )
            ):
                raise ValueError("no verified credential is available to preserve")
            candidate_key = existing["api_key"]
        requested_models = body["enabled_models"]
        if requested_models == []:
            preliminary = normalize_connection_candidate(
                provider,
                {
                    "type": body["type"],
                    "api_key": candidate_key,
                    "base_url": body["base_url"],
                    "enabled_models": [
                        {
                            "id": "connection-discovery-probe",
                            "upstream_model": "connection-discovery-probe",
                        }
                    ],
                },
            )
            if preliminary["type"] not in {"openai_compat", "perplexity"}:
                raise ValueError("this connection type needs an explicit model")
            discovered = await _discover_connection_models(
                str(preliminary["base_url"]),
                str(preliminary.get("api_key") or ""),
                provider_type=str(preliminary["type"]),
            )
            recommended_model = _recommended_discovered_chat_model(provider, discovered)
            if recommended_model is None:
                raise _ConnectionDiscoveryUnavailable
            requested_models = [recommended_model]
        conn = normalize_connection_candidate(
            provider,
            {
                "type": body["type"],
                "api_key": candidate_key,
                "base_url": body["base_url"],
                "enabled_models": requested_models,
            },
        )
        conn = request.app.state.router.assign_available_model_ids(provider, conn)
    except _ConnectionDiscoveryUnavailable:
        return _connection_validation_failure(provider)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422, detail="连接配置不符合接入策略"
        ) from exc

    try:
        routes = request.app.state.router.build_transient_routes(provider, conn)
    except ModelRouteConflictError as exc:
        raise HTTPException(
            status_code=409, detail="模型显示 ID 已被另一个连接占用"
        ) from exc
    except Exception:  # noqa: BLE001 - constructors may echo credentials/targets
        return _connection_validation_failure(provider)
    if not routes:
        return _connection_validation_failure(provider)

    semaphore = asyncio.Semaphore(_CONNECTION_MODEL_PROBE_CONCURRENCY)

    async def _probe_route(route) -> _ConnectionProbeResult:
        probe = ChatCompletionRequest(
            model=route.virtual_model,
            messages=[{"role": "user", "content": "ping"}],
            stream=False,
            max_tokens=1,
        )
        attempt_timeout, total_timeout = _connection_probe_deadlines(
            route.provider
        )
        try:
            async with semaphore:
                with bind_provider_call_scope(role="admin.connection_connect"):
                    await chat_once_with_deadline(
                        route.provider,
                        probe,
                        route.upstream_model,
                        attempt_timeout=attempt_timeout,
                        total_timeout=total_timeout,
                        probe=True,
                    )
            return _ConnectionProbeResult(succeeded=True)
        except KimiSubscriptionProviderError as exc:
            return _ConnectionProbeResult(
                succeeded=False,
                reason_code=exc.reason_code,
            )
        except Exception:  # noqa: BLE001 - never expose provider errors or targets
            return _ConnectionProbeResult(
                succeeded=False,
                reason_code=(
                    "connector_unavailable"
                    if provider == _KIMI_CONNECTION_PROVIDER
                    else None
                ),
            )

    probe_results: list[_ConnectionProbeResult]
    cleanup_succeeded = True
    try:
        probe_results = list(
            await asyncio.gather(*[_probe_route(route) for route in routes])
        )
    finally:
        try:
            await routes[0].provider.aclose()
        except Exception:  # noqa: BLE001 - cleanup errors follow the same redaction rule
            cleanup_succeeded = False

    if not cleanup_succeeded:
        return _connection_validation_failure(
            provider,
            "connector_unavailable",
        )

    successful_chat_model_ids = {
        route.virtual_model
        for route, succeeded in zip(routes, probe_results, strict=True)
        if succeeded.succeeded
    }
    if not successful_chat_model_ids:
        reason_code = next(
            (
                result.reason_code
                for result in probe_results
                if result.reason_code is not None
            ),
            None,
        )
        return _connection_validation_failure(provider, reason_code)
    unprobed_media_model_ids = _catalog_media_models_safe_to_activate(
        provider,
        conn,
        routes,
    )
    successful_model_ids = successful_chat_model_ids | unprobed_media_model_ids
    verified_candidate = {
        **conn,
        "enabled_models": [
            model
            for model in conn["enabled_models"]
            if model["id"] in successful_model_ids
        ],
    }
    rejected_models = [
        model["id"]
        for model in conn["enabled_models"]
        if model["id"] not in successful_model_ids
    ]

    # The real probe turn is the interrogation of the official wire.  A
    # provider that knows its wire may attach an honest actual-served receipt;
    # a hook failure is fail-closed, never silently dropped.
    served_receipt: dict | None = None
    receipt_hook = getattr(routes[0].provider, "actual_served_receipt", None)
    if callable(receipt_hook):
        try:
            served_receipt = receipt_hook()
        except Exception:  # noqa: BLE001 - never expose provider errors or targets
            return _connection_validation_failure(
                provider,
                "connector_unavailable"
                if provider == _KIMI_CONNECTION_PROVIDER
                else None,
            )

    locks = _connection_connect_locks(request)
    async with locks.promote():
        promotion = asyncio.create_task(
            _promote_verified_connection(
                request, provider, verified_candidate, served_receipt=served_receipt
            )
        )
        try:
            verified = await asyncio.shield(promotion)
        except asyncio.CancelledError:
            # Once durable promotion starts, let it either commit or restore the
            # pre-image before request cancellation releases the mutation lock.
            try:
                await asyncio.shield(promotion)
            except Exception:
                pass
            raise
        except ModelRouteConflictError as exc:
            raise HTTPException(
                status_code=409, detail="模型显示 ID 已被另一个连接占用"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="连接目标或配置不符合安全策略"
            ) from exc
        except (OSError, SecureStorageError) as exc:
            raise HTTPException(
                status_code=503, detail="连接配置未能安全持久化"
            ) from exc
        except _ConnectionPromotionRolledBack as exc:
            raise HTTPException(
                status_code=503, detail="连接切换失败，旧连接已保留"
            ) from exc
        except _ConnectionPromotionIndeterminate as exc:
            raise HTTPException(
                status_code=503, detail="连接切换失败，连接状态需要管理员检查"
            ) from exc
    return {
        "ok": True,
        "state": "verified",
        "verified_at": verified["_verification"]["verified_at"],
        "actual_served": request.app.state.store.actual_served(provider, verified),
        "models": [m["id"] for m in verified["enabled_models"]],
        "unprobed_models": [
            m["id"]
            for m in verified["enabled_models"]
            if m["id"] in unprobed_media_model_ids
        ],
        "rejected_models": rejected_models,
    }


@router.delete("/connections/{provider}")
async def delete_connection(
    provider: str,
    request: Request,
    _: str = Depends(require_approval_admin_key),
) -> dict:
    if is_quarantine_handle(provider):
        normalized_provider = provider
    else:
        try:
            normalized_provider = normalize_provider_name(provider)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="连接名称不符合接入策略") from exc
    async with _connection_connect_locks(request).hold(normalized_provider):
        return await _delete_connection_locked(normalized_provider, request)


async def _delete_connection_locked(provider: str, request: Request) -> dict:
    locks = _connection_connect_locks(request)
    async with locks.promote():
        if is_quarantine_handle(provider):
            try:
                request.app.state.store.delete_quarantined(provider)
            except (ValueError, OSError, SecureStorageError) as exc:
                raise HTTPException(
                    status_code=503, detail="隔离连接未能安全删除"
                ) from exc
            return {"ok": True}
        try:
            previous = request.app.state.store.delete(provider)
        except (ValueError, OSError, SecureStorageError) as exc:
            raise HTTPException(
                status_code=503, detail="连接配置未能安全持久化"
            ) from exc
        if not previous.active_present:
            return {"ok": True}
        try:
            await request.app.state.router.reload_connection(provider)
        except Exception as exc:  # noqa: BLE001 - restore exact pre-image
            try:
                request.app.state.store.restore(previous)
            except Exception as rollback_exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=503, detail="连接删除失败，连接状态需要管理员检查"
                ) from rollback_exc
            raise HTTPException(
                status_code=503, detail="连接删除失败，旧连接已保留"
            ) from exc
    return {"ok": True}


@router.post("/connections/{provider}/test")
async def test_connection(
    provider: str,
    request: Request,
    _: str = Depends(require_approval_admin_key),
) -> dict:
    """对已连接来源发一个极小请求；该操作可能计费，必须进入审批域。"""
    try:
        normalized_provider = normalize_provider_name(provider)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="连接名称不符合接入策略") from exc
    routes = request.app.state.router.routes_for_provider(normalized_provider)
    if not routes:
        raise HTTPException(status_code=404, detail="该来源未连接或没有已启用模型")
    semaphore = asyncio.Semaphore(_CONNECTION_MODEL_PROBE_CONCURRENCY)

    async def _test_route(route) -> dict[str, object]:
        req = ChatCompletionRequest(
            model=route.virtual_model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
        attempt_timeout, total_timeout = _connection_probe_deadlines(
            route.provider
        )
        try:
            async with semaphore:
                with bind_provider_call_scope(role="admin.connection_test"):
                    await chat_once_with_deadline(
                        route.provider,
                        req,
                        route.upstream_model,
                        attempt_timeout=attempt_timeout,
                        total_timeout=total_timeout,
                        probe=True,
                    )
            return {"model": route.virtual_model, "ok": True}
        except Exception:  # noqa: BLE001 - never expose provider details
            return {"model": route.virtual_model, "ok": False}

    results = list(await asyncio.gather(*[_test_route(route) for route in routes]))
    failed = sum(1 for result in results if not result["ok"])
    response: dict[str, object] = {
        "ok": failed == 0,
        "tested_models": results,
        "tested_count": len(results),
        "failed_count": failed,
    }
    if len(results) == 1:
        response["model"] = results[0]["model"]
    if failed:
        response["error"] = "部分模型当前不可达，请检查服务状态与凭据"
    return response


# 常见本地大模型服务（均 OpenAI 兼容），用于自动探测
LOCAL_PROBES = [
    {"name": "ollama", "label": "Ollama", "base_url": "http://localhost:11434/v1"},
    {"name": "lmstudio", "label": "LM Studio", "base_url": "http://localhost:1234/v1"},
    {"name": "llamacpp", "label": "llama.cpp", "base_url": "http://localhost:8080/v1"},
    {"name": "jan", "label": "Jan", "base_url": "http://localhost:1337/v1"},
    {"name": "vllm", "label": "vLLM", "base_url": "http://localhost:8000/v1"},
]


def _is_loopback_model_base(base_url: str) -> bool:
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").rstrip(".").casefold()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


async def _bounded_model_catalog(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> list[str]:
    body = bytearray()
    async with client.stream(
        "GET", url, headers=headers or {"Accept": "application/json"}
    ) as response:
        if not 200 <= response.status_code < 300:
            raise ValueError("model catalog returned a non-success status")
        declared = getattr(response, "headers", {}).get("content-length")
        if declared is not None:
            if not str(declared).isdigit() or int(declared) > _MODEL_CATALOG_BODY_LIMIT:
                raise ValueError("model catalog content length is invalid")
        async for chunk in response.aiter_bytes():
            raw = bytes(chunk)
            if len(body) + len(raw) > _MODEL_CATALOG_BODY_LIMIT:
                raise ValueError("model catalog body exceeds its limit")
            body.extend(raw)
    try:
        payload = json.loads(bytes(body).decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("model catalog is not strict UTF-8 JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("model catalog response shape is invalid")
    models = payload["data"]
    if len(models) > _MODEL_CATALOG_COUNT_LIMIT:
        raise ValueError("model catalog contains too many models")
    ids: list[str] = []
    seen: set[str] = set()
    for model in models:
        if not isinstance(model, dict):
            raise ValueError("model catalog entry is invalid")
        model_id = model.get("id")
        if (
            not isinstance(model_id, str)
            or not 1 <= len(model_id) <= 512
            or model_id != model_id.strip()
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in model_id)
            or model_id in seen
        ):
            raise ValueError("model catalog id is invalid")
        seen.add(model_id)
        ids.append(model_id)
    return ids


def _likely_chat_models(model_ids: list[str]) -> list[str]:
    non_chat_markers = (
        "embedding",
        "embed-",
        "rerank",
        "dall-e",
        "image",
        "imagen",
        "flux",
        "sdxl",
        "stable-diffusion",
        "sora",
        "veo",
        "whisper",
        "speech",
        "tts",
    )
    likely = [
        model_id
        for model_id in model_ids
        if not any(marker in model_id.casefold() for marker in non_chat_markers)
    ]
    return likely


def _recommended_discovered_chat_model(
    provider: str, model_ids: list[str]
) -> dict[str, str] | None:
    """Choose exactly one explainable chat candidate for simple Connect.

    Prefer a currently declared provider recommendation when the upstream
    catalog proves it exists.  Otherwise prefer an explicit chat/instruction
    id, then retain upstream order as the final bounded fallback.  Automatic
    onboarding never fans one click out into paid probes of several models.
    """

    likely = _likely_chat_models(model_ids)
    if not likely:
        return None
    discovered = set(likely)
    declared = [
        (index, model)
        for index, model in enumerate(preset_models(provider))
        if str(model.get("modality") or "chat").casefold() == "chat"
    ]
    declared.sort(key=lambda item: (rank_sort_key(item[1].get("rank")), item[0]))
    for _, model in declared:
        upstream = str(model.get("upstream_model") or "").strip()
        alias = str(model.get("id") or "").strip()
        if upstream in discovered and alias:
            return {"id": alias, "upstream_model": upstream}
    explicit = re.compile(r"(?:^|[-_.:/])(?:chat|instruct|assistant)(?:$|[-_.:/])", re.I)
    selected = next((model_id for model_id in likely if explicit.search(model_id)), likely[0])
    return {"id": selected, "upstream_model": selected}


async def _discover_connection_models(
    base_url: str,
    api_key: str,
    *,
    provider_type: str = "openai_compat",
) -> list[str]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        if provider_type == "perplexity":
            catalog_url = perplexity_model_catalog_url(base_url)
        elif provider_type == "openai_compat":
            catalog_url = f"{base_url.rstrip('/')}/models"
        else:
            raise ValueError("connection type has no model discovery adapter")
        async with httpx.AsyncClient(
            timeout=5.0,
            follow_redirects=False,
            trust_env=not _is_loopback_model_base(base_url),
        ) as client:
            return await asyncio.wait_for(
                _bounded_model_catalog(
                    client, catalog_url, headers=headers
                ),
                timeout=_MODEL_CATALOG_TOTAL_TIMEOUT_SEC,
            )
    except (asyncio.TimeoutError, httpx.HTTPError, OSError, ValueError) as exc:
        raise _ConnectionDiscoveryUnavailable from exc


@router.get("/local/detect")
async def detect_local(request: Request) -> dict:
    """探测本机常见本地模型服务（Ollama/LM Studio 等），返回存活状态与模型列表。

    UI 据此一键接入本机模型。跨机地址默认拒绝；如需远程服务，应使用 HTTPS、公网
    精确 allowlist 以及独立传输认证，不能复开通用内网访问。
    """

    async def _probe(client: httpx.AsyncClient, p: dict) -> dict:
        try:
            ids = await asyncio.wait_for(
                _bounded_model_catalog(client, p["base_url"] + "/models"),
                timeout=_LOCAL_DETECT_TOTAL_TIMEOUT_SEC,
            )
            return {**p, "alive": True, "models": ids}
        except Exception:  # noqa: BLE001 — 探测失败即视为未启动
            pass
        return {**p, "alive": False, "models": []}

    own_port = str(get_settings().gateway_port)
    probes = [p for p in LOCAL_PROBES if f":{own_port}" not in p["base_url"]]
    async with httpx.AsyncClient(
        timeout=2.0, follow_redirects=False, trust_env=False
    ) as client:
        results = await asyncio.gather(*[_probe(client, p) for p in probes])
    return {"local": list(results)}


@router.get("/local/models")
async def list_local_models(request: Request, base_url: str) -> dict:
    """拉取经过目标策略校验的 OpenAI 兼容服务模型列表。"""
    try:
        normalized = normalize_base_url(base_url)
        if not normalized or not _is_loopback_model_base(normalized):
            raise ValueError("base_url 不能为空")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="模型服务地址不符合安全策略") from exc
    url = normalized + "/models"
    try:
        async with httpx.AsyncClient(
            timeout=5.0, follow_redirects=False, trust_env=False
        ) as client:
            ids = await asyncio.wait_for(
                _bounded_model_catalog(client, url),
                timeout=_MODEL_CATALOG_TOTAL_TIMEOUT_SEC,
            )
        return {"ok": True, "models": ids}
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": "无法读取模型目录"}
