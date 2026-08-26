"""FastAPI 网关入口：OpenAI 兼容的 /v1/chat/completions 与 /v1/models，外加 /admin 管理 API。"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from gateway import audio as audio_mod
from gateway import local_model
from gateway import websearch
from gateway import mcp_registry
from gateway import semcache
from gateway.runtime_profile import RuntimeCapability, current_runtime_profile
from gateway.admission import (
    AdmissionControlMiddleware,
    BackgroundJobLimitExceeded,
    configure_background_job_pool,
    get_background_job_pool,
    hash_api_keys,
    reset_background_job_lease,
    set_background_job_lease,
)
from gateway.admin import router as admin_router
from gateway.channel_recovery import router as channel_recovery_router
from gateway.subscription_connectors import router as subscription_connectors_router
from gateway.team_session import router as team_session_router
from gateway.enterprise_rag import router as enterprise_rag_router
from gateway.privacy_admin import (
    initialize_privacy_rights,
    router as privacy_admin_router,
)
from gateway.audio import AudioUnavailable
from gateway.body_limit import RequestBodyLimitMiddleware
from gateway.bridge_protocol import BridgeProtocolMiddleware, PersistentNonceReplayGuard
from gateway.channel_media_protocol import (
    ChannelMediaFrame,
    ChannelMediaFrameError,
    decode_channel_media_frame,
    recompute_channel_media_identity,
)
from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.channel_media_installation_control import (
    ChannelMediaInstallationControl,
    ChannelMediaInstallationControlUnavailable,
)
from gateway.durable_media_requests import (
    DurableMediaAssetConflict,
    DurableMediaRequestClaim,
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    hash_media_request,
    validate_media_idempotency_key,
)
from gateway.desktop_engine_session_gateway import (
    SESSION_STATE_KEY as DESKTOP_SESSION_STATE_KEY,
    DesktopEngineSessionGatewayApp,
)
from gateway.gateway_installation_control import (
    GatewayInstallationControl,
    GatewayInstallationControlUnavailable,
    stable_paid_principal,
)
from gateway.asset_installation_control import (
    AssetInstallationControl,
    AssetInstallationControlUnavailable,
)
from gateway.installation_root import (
    InstallationRoot,
    InstallationRootError,
    InstallationRootLocked,
    default_installation_root_path,
    installation_principal,
)
from gateway.installation_paths import (
    default_channel_media_ledger_path,
    default_gateway_ledger_path,
    default_paid_media_asset_store_path,
)
from gateway.installation_root_gateway import InstallationRootGatewayApp
from gateway.auth import (
    require_api_key,
    require_approval_admin_key,
    require_bridge_or_api_key,
    require_paid_media_api_key,
)
from gateway.config import PROJECT_ROOT, desktop_engine_keys, get_settings
from gateway.connections import ConnectionStore
from gateway.secure_store import SecureStorageError, read_protected_json, write_protected_json
from gateway.failover import chat_with_fallback, stream_with_fallback
from gateway.media_call_metering import (
    bind_paid_media_authority,
    generate_image_asset_urls_with_accounting,
    generate_image_with_accounting,
    generate_video_with_accounting,
    get_video_with_accounting,
)
from gateway.paid_media_asset_protocol import (
    MAX_RESULT_BYTES as PAID_MEDIA_RESULT_MAX_BYTES,
    PROTOCOL_HEADER as PAID_MEDIA_PROTOCOL_HEADER,
    PROTOCOL_VERSION as PAID_MEDIA_PROTOCOL_VERSION,
    PaidMediaAssetProtocolError,
    PaidMediaAssetResult,
    asset_result_document,
    canonical_asset_result,
    parse_asset_ack,
    parse_asset_result,
    require_protocol_v2,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES as PAID_MEDIA_ASSET_RESERVATION_BYTES,
    PaidMediaAssetAuthorizationError,
    PaidMediaAssetCapacityError,
    PaidMediaAssetConflictError,
    PaidMediaAssetStore,
    PaidMediaAssetStoreError,
)
from gateway.paid_media_asset_delivery import (
    PaidMediaAssetDeliveryUnavailable,
    pin_paid_media_asset_for_principal,
    pinned_asset_streaming_response,
)
from gateway.paid_media_engine_session_gateway import (
    PaidMediaEngineSessionGatewayApp,
)
from gateway.agent_contract import (
    AGENT_TERMINAL_OUTCOMES,
    AgentResultContractError,
    normalize_legacy_agent_result,
    project_public_agent_result,
    validate_agent_result,
)
from gateway.route_attestation import (
    reset_agent_author_context,
    set_agent_author_context,
)
from gateway.providers.base import ChatProvider, ProviderError, friendly_status
from gateway.public_media import (
    PublicFetchContentTypeError,
    PublicFetchError,
    PublicFetchHTTPError,
    PublicFetchSecurityError,
    PublicFetchTimeout,
    PublicFetchTooLarge,
    download_public_file,
)
from gateway.media_binary import MediaBinaryUnavailable, require_media_binary
from gateway.model_identity import (
    canonical_model_id,
    model_family_from_identifier,
    review_strength_from_identifier,
)
from gateway.trusted_media_http import (
    TrustedMediaRequestError,
    trusted_media_readiness_receipt,
    validate_trusted_media_request,
)
from gateway.trusted_media_probe import (
    TrustedMediaProbeBusy,
    TrustedMediaProbeError,
    TrustedMediaProbeTimeout,
    TrustedMediaTooLarge,
    TrustedMediaProbeUnavailable,
    TrustedMediaRejected,
)
from gateway.provider_call_ledger import (
    ProviderCallContext,
    ProviderCallLedgerUnavailable,
    bind_provider_call_context,
    bind_provider_call_scope,
    configured_provider_call_ledger,
)
from gateway.url_safety import is_public_http_url
from gateway.router import Router
from gateway.schemas import (
    ChatCompletionRequest,
    ChatMessage,
    DebateWorkflowRequest,
    DecomposeWorkflowRequest,
    ImageGenerationRequest,
    PanelWorkflowRequest,
    PipelineWorkflowRequest,
    VideoGenerationRequest,
    WorkflowOutputLimitError,
)
from gateway.streaming import sse_encode
from gateway.usage import UsageLogger
from gateway.weixin_idempotency import (
    WeixinIdempotencyStore,
    WeixinIdempotencyUnavailable,
    hash_channel_principal,
    hash_turn_identity,
    hash_weixin_request,
    validate_channel_idempotency_key,
)
from orchestrator.agent import (
    BufferedConversationStore,
    ConversationReceiptUnavailable,
    ConversationStore,
    agent_chat,
    memory_system_note,
    record_feedback,
    record_feedback_once,
)
from orchestrator.approval import ApprovalStore, needs_approval, should_escalate
from orchestrator.cases import CaseLibrary
from orchestrator.durable_event_log import (
    DurableWorkflowEventLog,
    DurableWorkflowEventUnavailable,
)
from orchestrator.knowledge import KnowledgeBase, build_context as kb_context
from orchestrator.studio import generate_plan, get_job, start_execution
from orchestrator.hooks import HookGuard
from orchestrator.identity import (
    normalize_independence_domain,
    normalize_model_family,
)
from orchestrator.intent import classify_intent
from orchestrator.webread import read_and_summarize
from orchestrator.ledger import (
    TaskLedger,
    freeze_execution_spec,
    plan_job,
    run_job,
    validate_execution_spec,
)
from orchestrator.memory import MemoryStore, extract_and_store, reflect
from orchestrator.modes import SINGLE_ANSWER_MODES, pick_model
from orchestrator import scoreboard
from orchestrator.translate import translate
from orchestrator import conv_summary
from orchestrator import inject as steer  # 运行中插话注入（Claude Code 式 steering）
from orchestrator.conductor import run_conductor_agent
from orchestrator.history_compress import compress_history
from orchestrator.orchestrated_agent import run_orchestrated_agent
from orchestrator.tool_agent import TOOLS, run_tool_agent
from orchestrator.plugin_kernel import ServiceNotFound
from orchestrator.workflow_plugins import PIPELINE_WORKFLOW_SERVICE
from orchestrator.workspace_guard import (
    WorkspaceBoundaryError,
    resolve_workspace,
    workspace_root,
)
from orchestrator import undo_receipts
from orchestrator.undo_receipts import UndoReceiptError, UndoReceiptStore
from orchestrator.vision import describe_image, pick_vision_model
from orchestrator.workflows.coding_team import run_arch_editor, run_coding_team
from orchestrator.workflows.lapian import run_lapian
from orchestrator.workflows.debate import run_debate
from orchestrator.workflows.decompose import run_decompose
from orchestrator.workflows.panel_judge import run_panel
from scripts.sqlite_backup import backup_databases


_SQLITE_BACKUP_INITIAL_DELAY_SEC = 5.0
_SQLITE_BACKUP_MIN_INTERVAL_SEC = 300.0
_SQLITE_BACKUP_KEEP = 14
_GATEWAY_THREAD_DRAIN_TIMEOUT_SEC = 5.0
_GATEWAY_TASK_DRAIN_TIMEOUT_SEC = 5.0
_gateway_thread_drain_now = time.monotonic


def _new_sqlite_backup_health() -> dict[str, Any]:
    """Return the non-secret runtime status for the online SQLite backup worker."""

    return {
        "status": "pending",
        "last_attempt_at": None,
        "last_success_at": None,
        "last_error": None,
        "snapshot_path": None,
        "database_count": 0,
    }


def _backup_timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


async def _run_sqlite_backup_once(
    target_app: FastAPI,
    data_dir: Path,
    *,
    backup_fn: Any = None,
) -> None:
    """Create one verified all-database snapshot and atomically publish its status."""

    health = dict(
        getattr(target_app.state, "sqlite_backup_health", None)
        or _new_sqlite_backup_health()
    )
    health.update(status="running", last_attempt_at=_backup_timestamp())
    target_app.state.sqlite_backup_health = health
    try:
        result = await run_in_threadpool(
            backup_fn or backup_databases,
            data_dir,
            data_dir / "backup" / "sqlite",
            keep=_SQLITE_BACKUP_KEEP,
        )
    except asyncio.CancelledError:
        health.update(status="cancelled")
        target_app.state.sqlite_backup_health = health
        raise
    except Exception as exc:  # noqa: BLE001 -- backup failure degrades, never stops chat
        # Exception messages may contain paths, DSNs or injected credentials.
        # The exception class is actionable enough for both health and logs;
        # do not assume the process-log destination is a protected secret sink.
        health.update(status="degraded", last_error=type(exc).__name__[:128])
        target_app.state.sqlite_backup_health = health
        _REQUEST_LOG.error(
            "online SQLite backup failed error_type=%s", type(exc).__name__[:128]
        )
        return

    health.update(
        status="ok",
        last_success_at=_backup_timestamp(),
        last_error=None,
        snapshot_path=str(result.snapshot_dir),
        database_count=len(result.databases),
    )
    target_app.state.sqlite_backup_health = health


async def _sqlite_backup_loop(
    target_app: FastAPI,
    data_dir: Path,
    *,
    initial_delay_sec: float = _SQLITE_BACKUP_INITIAL_DELAY_SEC,
    interval_sec: float,
    backup_fn: Any = None,
    sleep_fn: Any = asyncio.sleep,
) -> None:
    """Run verified online snapshots after a short delay until shutdown cancels us."""

    await sleep_fn(max(0.0, float(initial_delay_sec)))
    while True:
        await _run_sqlite_backup_once(
            target_app,
            data_dir,
            backup_fn=backup_fn,
        )
        await sleep_fn(max(0.0, float(interval_sec)))


def _is_packaged_runtime() -> bool:
    return bool(getattr(sys, "frozen", False))


_DESKTOP_ENGINE_SESSION_BOOT_ENV = frozenset(
    {
        "NACHUAN_ENGINE_BOOT_TOKEN",
        "NACHUAN_ENGINE_GENERATION",
        "NACHUAN_ENGINE_PORT",
    }
)


def _desktop_engine_session_environment_requested(
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Detect an Electron-owned source launch without treating it as paid."""

    source = os.environ if environ is None else environ
    return any(str(source.get(name) or "").strip() for name in _DESKTOP_ENGINE_SESSION_BOOT_ENV)


def _paid_media_authority_status(
    *,
    mode: str,
    reason_code: str,
    new_operations_ready: bool,
    replay_available: bool,
    packaged: bool,
) -> dict[str, Any]:
    """Build the only non-secret lifecycle projection exposed to health."""

    return {
        "mode": mode,
        "reason_code": reason_code,
        "new_operations_ready": bool(new_operations_ready),
        "replay_available": bool(replay_available),
        "packaged": bool(packaged),
    }


def _set_paid_media_authority_status(
    target_app: FastAPI,
    *,
    mode: str,
    reason_code: str,
    new_operations_ready: bool,
    replay_available: bool,
    packaged: bool,
) -> dict[str, Any]:
    status = _paid_media_authority_status(
        mode=mode,
        reason_code=reason_code,
        new_operations_ready=new_operations_ready,
        replay_available=replay_available,
        packaged=packaged,
    )
    target_app.state.paid_media_authority = status
    return status


def _set_channel_media_authority_status(
    target_app: FastAPI,
    *,
    mode: str,
    reason_code: str,
    new_operations_ready: bool,
    replay_available: bool,
    packaged: bool,
) -> dict[str, Any]:
    """Publish a non-secret channel-media lifecycle projection."""

    status = _paid_media_authority_status(
        mode=mode,
        reason_code=reason_code,
        new_operations_ready=new_operations_ready,
        replay_available=replay_available,
        packaged=packaged,
    )
    target_app.state.channel_media_authority = status
    return status


def _close_channel_media_resource(
    controller: Any,
    store: Any,
    *,
    pending: tuple[Any, ...] = (),
) -> tuple[Any, ...]:
    """Close each owned channel resource once and retain failed handles."""

    resources = (controller if controller is not None else store, *pending)
    seen: set[int] = set()
    failed: list[Any] = []
    for resource in resources:
        if resource is None or id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            resource.close()
        except BaseException:
            failed.append(resource)
    return tuple(failed)


def _initialize_channel_media_authority(
    target_app: FastAPI,
    data_dir: Path,
) -> dict[str, Any]:
    """Open channel authority without granting packaged create semantics."""

    packaged = _is_packaged_runtime()
    previous_controller = getattr(
        target_app.state, "channel_media_installation_control", None
    )
    previous_store = getattr(target_app.state, "channel_media_requests", None)
    previous_pending = tuple(
        getattr(target_app.state, "channel_media_close_pending", ()) or ()
    )
    target_app.state.channel_media_installation_control = None
    target_app.state.channel_media_requests = None
    target_app.state.channel_media_close_pending = _close_channel_media_resource(
        previous_controller,
        previous_store,
        pending=previous_pending,
    )
    if target_app.state.channel_media_close_pending:
        return _set_channel_media_authority_status(
            target_app,
            mode="disabled",
            reason_code="store-close-incomplete",
            new_operations_ready=False,
            replay_available=False,
            packaged=packaged,
        )
    if not packaged:
        try:
            store = DurableChannelMediaRequestStore(
                data_dir / "channel_media_requests.db"
            )
        except (OSError, ValueError, DurableMediaRequestUnavailable):
            return _set_channel_media_authority_status(
                target_app,
                mode="disabled",
                reason_code="channel-media-store-unavailable",
                new_operations_ready=False,
                replay_available=False,
                packaged=False,
            )
        target_app.state.channel_media_requests = store
        return _set_channel_media_authority_status(
            target_app,
            mode="development",
            reason_code="development-unbound",
            new_operations_ready=True,
            replay_available=True,
            packaged=False,
        )

    control: ChannelMediaInstallationControl | None = None
    try:
        paid_installation_id = getattr(
            target_app.state, "paid_media_installation_id", None
        )
        paid_epoch = getattr(target_app.state, "paid_media_epoch", None)
        if (
            not isinstance(paid_installation_id, str)
            or re.fullmatch(r"[0-9a-f]{64}", paid_installation_id) is None
            or not isinstance(paid_epoch, int)
            or isinstance(paid_epoch, bool)
            or paid_epoch < 1
        ):
            raise ChannelMediaInstallationControlUnavailable(
                "paid authority epoch is unavailable"
            )
        root = InstallationRoot.open(default_installation_root_path())
        initial_snapshot = root.snapshot()
        control = ChannelMediaInstallationControl.open_bound(
            root,
            default_channel_media_ledger_path(),
        )
        final_snapshot = root.snapshot()
        control_state = control.state
        if (
            initial_snapshot.installation_id != paid_installation_id
            or initial_snapshot.epoch != paid_epoch
            or final_snapshot.installation_id != paid_installation_id
            or final_snapshot.epoch != paid_epoch
            or control_state.installation_id != paid_installation_id
            or control_state.epoch != paid_epoch
        ):
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media authority changed during startup"
            )
        if control_state.mode == "provisioned_not_active":
            # A clean install starts the engine before Desktop binds its Root
            # component. Keep the strict controller (and its writer ownership)
            # attached, but expose no store until an in-process refresh proves
            # the final active Root. Closing it here would require an engine
            # restart after first-run activation.
            target_app.state.channel_media_installation_control = control
            return _set_channel_media_authority_status(
                target_app,
                mode="provisioned_not_active",
                reason_code=control_state.reason_code,
                new_operations_ready=False,
                replay_available=False,
                packaged=True,
            )
        if control_state.mode not in {"ready", "manual_only"}:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media authority is not read capable"
            )
        if control_state.mode == "ready" and not bool(
            control_state.provider_dispatch_ready
        ):
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media provider authority is unavailable"
            )
        store = control.store
        target_app.state.channel_media_installation_control = control
        target_app.state.channel_media_requests = store
        manual_only = control_state.mode == "manual_only"
        return _set_channel_media_authority_status(
            target_app,
            mode="manual_only" if manual_only else "ready",
            reason_code=(
                "manual-recovery-required" if manual_only else "authority-exact"
            ),
            new_operations_ready=not manual_only,
            replay_available=True,
            packaged=True,
        )
    except InstallationRootLocked:
        reason_code = "installation-root-locked"
    except InstallationRootError:
        reason_code = "installation-root-unavailable"
    except ChannelMediaInstallationControlUnavailable:
        reason_code = "channel-media-installation-control-unavailable"
    except (DurableMediaRequestUnavailable, OSError, ValueError):
        reason_code = "channel-media-store-unavailable"
    except Exception:
        reason_code = "channel-media-authority-initialization-failed"

    target_app.state.channel_media_close_pending = _close_channel_media_resource(
        control,
        None,
    )
    target_app.state.channel_media_installation_control = None
    target_app.state.channel_media_requests = None
    return _set_channel_media_authority_status(
        target_app,
        mode="disabled",
        reason_code=reason_code,
        new_operations_ready=False,
        replay_available=False,
        packaged=True,
    )


def _close_channel_media_authority(target_app: FastAPI) -> None:
    """Drain channel ownership once; preserve failed handles for one retry."""

    controller = getattr(
        target_app.state, "channel_media_installation_control", None
    )
    store = getattr(target_app.state, "channel_media_requests", None)
    pending = tuple(
        getattr(target_app.state, "channel_media_close_pending", ()) or ()
    )
    failed = _close_channel_media_resource(
        controller,
        store,
        pending=pending,
    )
    target_app.state.channel_media_close_pending = failed
    target_app.state.channel_media_installation_control = None
    target_app.state.channel_media_requests = None
    _set_channel_media_authority_status(
        target_app,
        mode="disabled",
        reason_code=("store-close-incomplete" if failed else "store-closed"),
        new_operations_ready=False,
        replay_available=False,
        packaged=_is_packaged_runtime(),
    )
    if failed:
        raise RuntimeError("channel-media authority close incomplete") from None


def _control_paid_principal_is_consistent(
    control_state: Any,
    expected_principal: object,
) -> bool:
    """Require every controller-published principal to match the root epoch."""

    if (
        not isinstance(expected_principal, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_principal) is None
        or expected_principal == "0" * 64
    ):
        return False
    mode = str(getattr(control_state, "mode", "") or "")
    published = getattr(control_state, "paid_principal", None)
    if mode in {"ready", "manual_only"}:
        return (
            isinstance(published, str)
            and re.fullmatch(r"[0-9a-f]{64}", published) is not None
            and published != "0" * 64
            and hmac.compare_digest(published, expected_principal)
        )
    # Waiting/fused states intentionally publish no mutation principal.  Their
    # cached-replay identity remains the matching root snapshot validated by
    # installation id and epoch during strict open_bound construction.
    if mode in {"provisioned_not_active", "fused"}:
        return published is None
    return False


def _close_paid_media_resource(
    control: Any,
    store: Any,
    asset_control: Any = None,
    assets: Any = None,
    *,
    pending: tuple[Any, ...] = (),
) -> tuple[Any, ...]:
    """Best-effort close that cannot take down ordinary gateway shutdown."""

    resources = (
        control if control is not None else store,
        asset_control if asset_control is not None else assets,
        *pending,
    )
    seen: set[int] = set()
    failed: list[Any] = []
    for resource in resources:
        if resource is None or id(resource) in seen:
            continue
        seen.add(id(resource))
        try:
            resource.close()
        except BaseException:  # close failure must not skip the peer controller
            failed.append(resource)
    return tuple(failed)


def _initialize_paid_media_authority(
    target_app: FastAPI,
    data_dir: Path,
) -> dict[str, Any]:
    """Open the paid ledger under the correct runtime construction policy.

    Source runs retain the historical development store so existing local
    workflows and tests do not silently acquire installer semantics.  A frozen
    executable can only open the two installer-bound Root-v4 controllers and
    never calls a create, migration or provisioning API.
    """

    packaged = _is_packaged_runtime()
    previous_control = getattr(
        target_app.state, "installation_root_control", None
    )
    previous_asset_control = getattr(
        target_app.state, "asset_installation_control", None
    )
    previous_store = getattr(target_app.state, "media_requests", None)
    previous_assets = getattr(target_app.state, "paid_media_assets", None)
    previous_pending = tuple(
        getattr(target_app.state, "paid_media_close_pending", ()) or ()
    )
    target_app.state.installation_root_control = None
    target_app.state.asset_installation_control = None
    target_app.state.media_requests = None
    target_app.state.paid_media_assets = None
    target_app.state.paid_media_epoch = None
    target_app.state.paid_media_installation_id = None
    target_app.state.paid_media_principal = None
    target_app.state.paid_media_root_principal = None
    previous_web_ledger = getattr(target_app.state, "paid_media_web_ledger", None)
    previous_web_archive = getattr(target_app.state, "paid_media_web_archive", None)
    target_app.state.paid_media_web_ledger = None
    target_app.state.paid_media_web_archive = None
    for web_resource in (previous_web_ledger, previous_web_archive):
        if web_resource is not None:
            try:
                web_resource.close()
            except Exception:  # noqa: BLE001 -- Web stores close independently
                pass
    target_app.state.paid_media_authority_mode = (
        "installation-root" if packaged else "development"
    )
    target_app.state.paid_media_close_pending = _close_paid_media_resource(
        previous_control,
        previous_store,
        previous_asset_control,
        previous_assets,
        pending=previous_pending,
    )
    if target_app.state.paid_media_close_pending:
        return _set_paid_media_authority_status(
            target_app,
            mode="disabled",
            reason_code="store-close-incomplete",
            new_operations_ready=False,
            replay_available=False,
            packaged=packaged,
        )
    if not packaged:
        try:
            store = DurableMediaRequestStore(data_dir / "paid_media_requests.db")
            development_installation_id = hashlib.sha256(
                b"nachuan-paid-media-development-installation-v1\x00"
                + str(data_dir.resolve()).encode("utf-8")
            ).hexdigest()
            development_assets = data_dir / "paid-media-assets"
            if development_assets.exists():
                asset_store = PaidMediaAssetStore.open_bound(
                    development_assets,
                    installation_id=development_installation_id,
                    epoch=1,
                )
            else:
                asset_store = PaidMediaAssetStore.provision(
                    development_assets,
                    installation_id=development_installation_id,
                    epoch=1,
                )
        except Exception:  # noqa: BLE001 -- paid storage never blocks ordinary startup
            target_app.state.paid_media_close_pending = _close_paid_media_resource(
                locals().get("control"),
                locals().get("store"),
                assets=locals().get("asset_store"),
            )
            return _set_paid_media_authority_status(
                target_app,
                mode="disabled",
                reason_code="paid-media-store-unavailable",
                new_operations_ready=False,
                replay_available=False,
                packaged=False,
            )
        target_app.state.media_requests = store
        target_app.state.paid_media_assets = asset_store
        target_app.state.paid_media_epoch = 1
        target_app.state.paid_media_installation_id = development_installation_id
        try:
            target_app.state.paid_media_web_ledger = PaidMediaWebLedger(
                data_dir / "paid_media_web_operations.db"
            )
            target_app.state.paid_media_web_archive = PaidMediaWebAssetArchive(
                data_dir / "paid-media-web-archive"
            )
        except Exception:  # noqa: BLE001 -- web journal failure fails its routes closed
            for web_resource in (
                getattr(target_app.state, "paid_media_web_ledger", None),
                getattr(target_app.state, "paid_media_web_archive", None),
            ):
                if web_resource is not None:
                    try:
                        web_resource.close()
                    except Exception:
                        pass
            target_app.state.paid_media_web_ledger = None
            target_app.state.paid_media_web_archive = None
        return _set_paid_media_authority_status(
            target_app,
            mode="development",
            reason_code="development-unbound",
            new_operations_ready=True,
            replay_available=True,
            packaged=False,
        )

    control: GatewayInstallationControl | None = None
    asset_control: AssetInstallationControl | None = None
    try:
        root = InstallationRoot.open(default_installation_root_path())
        root_snapshot = root.snapshot()
        control = GatewayInstallationControl.open_bound(
            root,
            default_gateway_ledger_path(),
        )
        control_state = control.state
        if (
            control_state.installation_id != root_snapshot.installation_id
            or control_state.epoch != root_snapshot.epoch
        ):
            # One bounded reread closes a concurrent legitimate re-anchor
            # window.  Never attach a principal from a different controller
            # epoch merely because both snapshots were individually valid.
            root_snapshot = root.snapshot()
            if (
                control_state.installation_id != root_snapshot.installation_id
                or control_state.epoch != root_snapshot.epoch
            ):
                raise GatewayInstallationControlUnavailable(
                    "installation principal changed during controller startup"
                )
        # Preserve the matching epoch principal while a controller is waiting
        # or has entered its bounded manual-only read mode.
        root_principal = stable_paid_principal(root_snapshot.principal_digest)
        if not _control_paid_principal_is_consistent(
            control_state,
            root_principal,
        ):
            raise GatewayInstallationControlUnavailable(
                "controller paid principal does not match installation root"
            )
        asset_control = AssetInstallationControl.open_bound(
            root,
            default_paid_media_asset_store_path(),
        )
        # One last bounded triple read prevents attaching a store opened for a
        # root/controller epoch that changed between those two opens.
        final_root_snapshot = root.snapshot()
        final_control_state = control.state
        final_asset_control_state = asset_control.state
        final_root_principal = stable_paid_principal(
            final_root_snapshot.principal_digest
        )
        if (
            final_root_snapshot.installation_id != root_snapshot.installation_id
            or final_root_snapshot.epoch != root_snapshot.epoch
            or final_control_state.installation_id != root_snapshot.installation_id
            or final_control_state.epoch != root_snapshot.epoch
            or final_asset_control_state.installation_id
            != root_snapshot.installation_id
            or final_asset_control_state.epoch != root_snapshot.epoch
            or not _control_paid_principal_is_consistent(
                final_control_state,
                final_root_principal,
            )
        ):
            raise GatewayInstallationControlUnavailable(
                "paid-media root, controller, and asset store changed during startup"
            )
        root_snapshot = final_root_snapshot
        root_principal = final_root_principal
        control_state = final_control_state
        target_app.state.installation_root_control = control
        target_app.state.asset_installation_control = asset_control
        target_app.state.paid_media_principal = root_principal
        target_app.state.paid_media_root_principal = root_snapshot.principal_digest
        target_app.state.paid_media_epoch = root_snapshot.epoch
        target_app.state.paid_media_installation_id = root_snapshot.installation_id
        if (
            control_state.mode == "provisioned_not_active"
            or final_asset_control_state.mode == "provisioned_not_active"
        ):
            # Desktop may complete its bind through the private API while this
            # process stays alive.  Retain the bounded controller, but do not
            # expose its store until an explicit reconciliation proves active.
            target_app.state.media_requests = None
            target_app.state.paid_media_assets = None
            return _set_paid_media_authority_status(
                target_app,
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                new_operations_ready=False,
                replay_available=False,
                packaged=True,
            )
        if (
            control_state.mode not in {"ready", "manual_only"}
            or final_asset_control_state.mode not in {"ready", "manual_only"}
        ):
            raise GatewayInstallationControlUnavailable(
                "paid-media controller pair is not read capable"
            )
        store = control.store
        asset_store = asset_control.store
        target_app.state.media_requests = store
        target_app.state.paid_media_assets = asset_store
        try:
            target_app.state.paid_media_web_ledger = PaidMediaWebLedger(
                data_dir / "paid_media_web_operations.db"
            )
            target_app.state.paid_media_web_archive = PaidMediaWebAssetArchive(
                data_dir / "paid-media-web-archive"
            )
        except Exception:  # noqa: BLE001 -- isolate Web delivery from core authority
            for web_resource in (
                getattr(target_app.state, "paid_media_web_ledger", None),
                getattr(target_app.state, "paid_media_web_archive", None),
            ):
                if web_resource is not None:
                    try:
                        web_resource.close()
                    except Exception:
                        pass
            target_app.state.paid_media_web_ledger = None
            target_app.state.paid_media_web_archive = None
        combined_manual_only = (
            control_state.mode == "manual_only"
            or final_asset_control_state.mode == "manual_only"
        )
        return _set_paid_media_authority_status(
            target_app,
            mode="manual_only" if combined_manual_only else "ready",
            reason_code=(
                "manual-recovery-required"
                if combined_manual_only
                else "authority-exact"
            ),
            new_operations_ready=(
                not combined_manual_only and bool(control_state.outbound_ready)
            ),
            replay_available=True,
            packaged=True,
        )
    except InstallationRootLocked:
        reason_code = "installation-root-locked"
    except InstallationRootError:
        reason_code = "installation-root-unavailable"
    except GatewayInstallationControlUnavailable:
        reason_code = "installation-control-unavailable"
    except AssetInstallationControlUnavailable:
        reason_code = "asset-installation-control-unavailable"
    except (DurableMediaRequestUnavailable, OSError, ValueError):
        reason_code = "paid-media-store-unavailable"
    except Exception:  # noqa: BLE001 -- failure is isolated and text is secret-adjacent
        reason_code = "paid-media-authority-initialization-failed"

    target_app.state.paid_media_close_pending = _close_paid_media_resource(
        control,
        None,
        asset_control,
    )
    target_app.state.installation_root_control = None
    target_app.state.asset_installation_control = None
    target_app.state.media_requests = None
    target_app.state.paid_media_assets = None
    target_app.state.paid_media_epoch = None
    target_app.state.paid_media_installation_id = None
    target_app.state.paid_media_principal = None
    target_app.state.paid_media_root_principal = None
    return _set_paid_media_authority_status(
        target_app,
        mode="disabled",
        reason_code=reason_code,
        new_operations_ready=False,
        replay_available=False,
        packaged=True,
    )


def _disable_paid_media_authority(target_app: FastAPI, reason_code: str) -> None:
    """Close only the paid subsystem after a startup-localized fault."""

    control = getattr(target_app.state, "installation_root_control", None)
    asset_control = getattr(target_app.state, "asset_installation_control", None)
    store = getattr(target_app.state, "media_requests", None)
    assets = getattr(target_app.state, "paid_media_assets", None)
    pending = tuple(getattr(target_app.state, "paid_media_close_pending", ()) or ())
    target_app.state.paid_media_close_pending = _close_paid_media_resource(
        control,
        store,
        asset_control,
        assets,
        pending=pending,
    )
    target_app.state.installation_root_control = None
    target_app.state.asset_installation_control = None
    target_app.state.media_requests = None
    target_app.state.paid_media_assets = None
    target_app.state.paid_media_epoch = None
    target_app.state.paid_media_installation_id = None
    target_app.state.paid_media_principal = None
    target_app.state.paid_media_root_principal = None
    web_ledger = getattr(target_app.state, "paid_media_web_ledger", None)
    web_archive = getattr(target_app.state, "paid_media_web_archive", None)
    target_app.state.paid_media_web_ledger = None
    target_app.state.paid_media_web_archive = None
    for web_resource in (web_ledger, web_archive):
        if web_resource is not None:
            try:
                web_resource.close()
            except Exception:  # noqa: BLE001 -- Web stores close independently
                pass
    _set_paid_media_authority_status(
        target_app,
        mode="disabled",
        reason_code=reason_code,
        new_operations_ready=False,
        replay_available=False,
        packaged=_is_packaged_runtime(),
    )


def _close_paid_media_authority(target_app: FastAPI) -> None:
    control = getattr(target_app.state, "installation_root_control", None)
    asset_control = getattr(target_app.state, "asset_installation_control", None)
    store = getattr(target_app.state, "media_requests", None)
    assets = getattr(target_app.state, "paid_media_assets", None)
    pending = tuple(getattr(target_app.state, "paid_media_close_pending", ()) or ())
    failed = _close_paid_media_resource(
        control,
        store,
        asset_control,
        assets,
        pending=pending,
    )
    target_app.state.paid_media_close_pending = failed
    target_app.state.installation_root_control = None
    target_app.state.asset_installation_control = None
    target_app.state.media_requests = None
    target_app.state.paid_media_assets = None
    target_app.state.paid_media_epoch = None
    target_app.state.paid_media_installation_id = None
    target_app.state.paid_media_principal = None
    target_app.state.paid_media_root_principal = None
    web_ledger = getattr(target_app.state, "paid_media_web_ledger", None)
    web_archive = getattr(target_app.state, "paid_media_web_archive", None)
    target_app.state.paid_media_web_ledger = None
    target_app.state.paid_media_web_archive = None
    for web_resource in (web_ledger, web_archive):
        if web_resource is not None:
            try:
                web_resource.close()
            except Exception:  # noqa: BLE001 -- Web stores close independently
                pass
    _set_paid_media_authority_status(
        target_app,
        mode="disabled",
        reason_code="store-close-incomplete" if failed else "store-closed",
        new_operations_ready=False,
        replay_available=False,
        packaged=_is_packaged_runtime(),
    )


class GatewayShutdownError(RuntimeError):
    """Sanitized summary raised only after every shutdown close was attempted."""

    def __init__(self, failed_resources: tuple[str, ...]) -> None:
        self.failed_resources = failed_resources
        super().__init__(
            "gateway shutdown incomplete: " + ",".join(failed_resources)
        )


async def _close_gateway_resources(
    target_app: FastAPI,
    provider_call_ledger: Any,
) -> None:
    """Close owned resources without exposing secret-adjacent exceptions."""

    failed: list[str] = []
    cancellation: asyncio.CancelledError | None = None

    def close_sync(name: str, operation: Callable[[], Any]) -> bool:
        try:
            operation()
        except BaseException:  # report only the fixed resource label, then continue
            failed.append(name)
            return False
        return True

    async def close_async(name: str, operation: Callable[[], Any]) -> bool:
        nonlocal cancellation
        try:
            await operation()
        except asyncio.CancelledError as exc:
            failed.append(name)
            if cancellation is None:
                cancellation = exc
            return False
        except BaseException:  # report only the fixed resource label, then continue
            failed.append(name)
            return False
        return True

    def close_state_sync(name: str, attribute: str) -> None:
        try:
            resource = getattr(target_app.state, attribute, None)
            operation = getattr(resource, "close", None)
        except BaseException:
            failed.append(name)
            return
        if callable(operation) and not close_sync(name, operation):
            return
        if getattr(target_app.state, attribute, None) is resource:
            setattr(target_app.state, attribute, None)

    local_worker = getattr(target_app.state, "local_model_worker", None)
    local_stop_event = getattr(target_app.state, "local_model_stop_event", None)
    owns_local_model = local_worker is not None or local_stop_event is not None
    close_local_model = getattr(local_model, "stop", None)
    local_model_closed = True
    if owns_local_model and callable(close_local_model):
        local_model_closed = close_sync("local_model", close_local_model)
    join_local_worker = getattr(local_worker, "join", None)
    local_worker_is_alive = getattr(local_worker, "is_alive", None)
    local_worker_closed = True
    if callable(join_local_worker) and callable(local_worker_is_alive):
        def wait_for_local_worker() -> None:
            try:
                join_local_worker(timeout=5.0)
            except RuntimeError:
                # Thread.join raises before start; that state owns no running
                # worker and is safe after a failed Thread.start call.
                if local_worker_is_alive():
                    raise
                return
            if local_worker_is_alive():
                # The worker may be stuck inside an uninterruptible model
                # download/cold start; it is daemon by design (see startup)
                # and Python cannot kill it.  Failing the whole shutdown only
                # hides real close failures, so leave log evidence and let the
                # daemon exit with the process.
                _REQUEST_LOG.warning(
                    "local model worker did not stop within join budget; "
                    "daemon left to exit with the process"
                )

        local_worker_closed = await close_async(
            "local_model_worker",
            lambda: run_in_threadpool(wait_for_local_worker),
        )
    if local_model_closed and local_worker_closed and getattr(
        target_app.state, "local_model_worker", None
    ) is local_worker:
        target_app.state.local_model_worker = None
        target_app.state.local_model_stop_event = None

    async def close_optional_warmup_workers() -> None:
        workers = dict(
            getattr(target_app.state, "gateway_warmup_workers", {}) or {}
        )
        retained: dict[str, Any] = {}
        cancellation: asyncio.CancelledError | None = None
        timeout = max(0.001, float(_GATEWAY_THREAD_DRAIN_TIMEOUT_SEC))
        deadline = _gateway_thread_drain_now() + timeout
        for label, worker in workers.items():
            join_worker = getattr(worker, "join", None)
            worker_is_alive = getattr(worker, "is_alive", None)
            remaining = max(0.0, deadline - _gateway_thread_drain_now())

            def wait_for_worker() -> None:
                if not callable(join_worker) or not callable(worker_is_alive):
                    raise RuntimeError("warmup worker is not joinable")
                try:
                    join_worker(timeout=remaining)
                except RuntimeError:
                    if worker_is_alive():
                        raise
                    return
                if worker_is_alive():
                    raise RuntimeError("warmup worker did not stop")

            try:
                await run_in_threadpool(wait_for_worker)
            except asyncio.CancelledError as exc:
                retained[label] = worker
                if cancellation is None:
                    cancellation = exc
            except BaseException:
                retained[label] = worker
        target_app.state.gateway_warmup_workers = retained or None
        if cancellation is not None:
            raise cancellation
        if retained:
            raise RuntimeError("optional warmup workers did not stop")

    await close_async(
        "optional_warmup_workers",
        close_optional_warmup_workers,
    )
    router = getattr(target_app.state, "router", None)
    close_router = getattr(router, "aclose", None)
    router_closed = not callable(close_router) or await close_async(
        "router", close_router
    )
    if router_closed and getattr(target_app.state, "router", None) is router:
        target_app.state.router = None
        target_app.state.store = None
    if router_closed:
        close_state_sync("workflow_event_log", "workflow_event_log")
    close_state_sync("usage", "usage")
    close_state_sync("memory", "memory")
    close_state_sync("cases", "cases")
    close_state_sync("knowledge", "kb")
    close_state_sync("approvals", "approvals")
    close_state_sync("conversations", "conversations")
    close_state_sync("ledger", "ledger")

    def close_paid_media_authority() -> None:
        _close_paid_media_authority(target_app)
        if getattr(target_app.state, "paid_media_close_pending", ()):
            raise RuntimeError("paid-media authority close incomplete")

    close_sync(
        "paid_media_authority",
        close_paid_media_authority,
    )
    close_state_sync("weixin_idempotency", "weixin_idempotency")
    if (
        getattr(target_app.state, "channel_media_installation_control", None)
        is not None
        or getattr(target_app.state, "channel_media_requests", None) is not None
        or getattr(target_app.state, "channel_media_close_pending", ())
    ):
        close_sync(
            "channel_media_requests",
            lambda: _close_channel_media_authority(target_app),
        )
    close_state_sync("undo_receipts", "undo_receipts")
    close_sync("undo_receipts_global", lambda: undo_receipts.configure(None))
    close_provider_ledger = getattr(provider_call_ledger, "close", None)
    provider_ledger_closed = not callable(close_provider_ledger)
    if callable(close_provider_ledger):
        provider_ledger_closed = await close_async(
            "provider_call_ledger",
            lambda: run_in_threadpool(close_provider_ledger),
        )
    if provider_ledger_closed and getattr(
        target_app.state, "provider_call_ledger", None
    ) is provider_call_ledger:
        target_app.state.provider_call_ledger = None

    # These generation-scoped collaborators own no persistent close handle.
    # Once all closeable peers above have detached, retaining these objects can
    # only make a later early-startup failure mistake them for live ownership.
    target_app.state.privacy_rights = None
    target_app.state.guard = None

    target_app.state.gateway_shutdown_failures = tuple(failed)
    if failed:
        message = "gateway shutdown incomplete: " + ",".join(failed)
        _REQUEST_LOG.error(message)
    if cancellation is not None:
        raise cancellation
    if failed:
        raise GatewayShutdownError(tuple(failed)) from None


async def _drain_gateway_lifespan_once(target_app: FastAPI) -> None:
    """Drain a complete or partially initialized lifespan exactly once."""

    if bool(
        getattr(target_app.state, "gateway_lifespan_drain_finished", False)
    ):
        return

    task_failures: list[str] = []
    drain_timeout = max(0.001, float(_GATEWAY_TASK_DRAIN_TIMEOUT_SEC))
    service_tasks = set(
        getattr(target_app.state, "gateway_service_tasks", set()) or set()
    )
    pending_service_tasks: set[asyncio.Task[Any]] = set()
    for task in tuple(service_tasks):
        task.cancel()
    if service_tasks:
        _done, pending = await asyncio.wait(
            tuple(service_tasks), timeout=drain_timeout
        )
        if pending:
            task_failures.append("service_tasks")
            pending_service_tasks = set(pending)
    target_app.state.gateway_service_tasks = pending_service_tasks or None

    finite_background_tasks = set(
        getattr(target_app.state, "background_tasks", set()) or set()
    )
    pending_background_tasks: set[asyncio.Task[Any]] = set()
    if finite_background_tasks:
        _done, pending = await asyncio.wait(
            tuple(finite_background_tasks), timeout=drain_timeout
        )
        for task in pending:
            task.cancel()
        if pending:
            _cancelled, still_pending = await asyncio.wait(
                tuple(pending), timeout=drain_timeout
            )
            if still_pending:
                task_failures.append("background_tasks")
                pending_background_tasks = set(still_pending)
    target_app.state.background_tasks = pending_background_tasks or None
    if not task_failures:
        target_app.state.background_jobs = None

    local_stop = getattr(target_app.state, "local_model_stop_event", None)
    set_local_stop = getattr(local_stop, "set", None)
    if callable(set_local_stop):
        set_local_stop()

    provider_call_ledger = getattr(
        target_app.state, "provider_call_ledger", None
    )
    resource_failures: tuple[str, ...] = ()
    cancellation: asyncio.CancelledError | None = None
    try:
        await _close_gateway_resources(target_app, provider_call_ledger)
    except GatewayShutdownError as exc:
        resource_failures = exc.failed_resources
    except asyncio.CancelledError as exc:
        resource_failures = tuple(
            getattr(target_app.state, "gateway_shutdown_failures", ()) or ()
        )
        cancellation = exc

    combined_failures = tuple(task_failures) + tuple(resource_failures)
    target_app.state.gateway_shutdown_failures = combined_failures
    target_app.state.gateway_lifespan_drain_finished = True
    if task_failures:
        _REQUEST_LOG.error(
            "gateway shutdown incomplete: " + ",".join(combined_failures)
        )
    if cancellation is not None:
        raise cancellation
    if combined_failures:
        raise GatewayShutdownError(combined_failures) from None


async def _drain_gateway_lifespan(target_app: FastAPI) -> None:
    """Shield the bounded cleanup transaction, then propagate caller cancel."""

    cleanup = asyncio.create_task(_drain_gateway_lifespan_once(target_app))
    caller_cancellation: asyncio.CancelledError | None = None
    cleanup_error: BaseException | None = None
    while True:
        try:
            await asyncio.shield(cleanup)
            break
        except asyncio.CancelledError as exc:
            if cleanup.done():
                cleanup_error = exc
                break
            if caller_cancellation is None:
                caller_cancellation = exc
        except BaseException as exc:
            cleanup_error = exc
            break
    if caller_cancellation is not None:
        raise caller_cancellation
    if cleanup_error is not None:
        raise cleanup_error


async def _retry_previous_gateway_generation(target_app: FastAPI) -> None:
    """Resolve prior cleanup debt before any next-generation startup gate."""

    drain_finished = getattr(
        target_app.state, "gateway_lifespan_drain_finished", None
    )
    if drain_finished is None:
        return
    previous_failures = tuple(
        getattr(target_app.state, "gateway_shutdown_failures", ()) or ()
    )
    if bool(drain_finished) and not previous_failures:
        return
    target_app.state.gateway_lifespan_drain_finished = False
    await _drain_gateway_lifespan(target_app)


@asynccontextmanager
async def _lifespan_impl(app: FastAPI):
    settings = get_settings()
    # Required commercial accounting is a startup dependency, not a lazy cost
    # paid by the first user message.  Initialization runs off-loop and a broken
    # ledger prevents the process from advertising readiness.
    lifespan_provider_call_ledger = await run_in_threadpool(
        configured_provider_call_ledger
    )
    app.state.provider_call_ledger = lifespan_provider_call_ledger
    runtime_keys = set(settings.api_keys)
    approval_key = str(settings.approval_admin_key or "").strip()
    bridge_keys_by_channel = {
        "weixin": str(settings.nachuan_weixin_bridge_api_key or "").strip(),
        "feishu": str(settings.nachuan_feishu_bridge_api_key or "").strip(),
    }
    for channel, key in bridge_keys_by_channel.items():
        if key and not re.fullmatch(rf"sk-bridge-v2-{channel}-[0-9a-f]{{64}}", key):
            raise RuntimeError(f"{channel} bridge key format is invalid")
    bridge_keys = set(bridge_keys_by_channel.values())
    bridge_keys.discard("")
    if len(bridge_keys) != sum(
        bool(str(value or "").strip())
        for value in (
            settings.nachuan_weixin_bridge_api_key,
            settings.nachuan_feishu_bridge_api_key,
        )
    ):
        raise RuntimeError("channel bridge API keys must be distinct")
    if bridge_keys & runtime_keys or (approval_key and approval_key in bridge_keys):
        raise RuntimeError("channel bridge API keys must not overlap runtime or approval keys")
    service_tasks: set[asyncio.Task[Any]] = set()
    finite_background_tasks: set[asyncio.Task[Any]] = set()
    app.state.gateway_service_tasks = service_tasks
    # Fire-and-forget work must stay strongly referenced until completion.
    # ``_grow_memory`` uses this finite registry; the lifespan gives those
    # tasks a bounded graceful drain before cancellation on shutdown.
    app.state.background_tasks = finite_background_tasks
    warmup_workers: dict[str, Any] = {}
    app.state.gateway_warmup_workers = warmup_workers
    app.state.background_jobs = configure_background_job_pool(
        max_global=settings.admission_background_jobs_global,
        max_per_key=settings.admission_background_jobs_per_key,
        lease_ttl_seconds=settings.admission_background_job_ttl_sec,
    )

    def spawn_background(coro: Any) -> None:
        task = asyncio.create_task(coro)
        service_tasks.add(task)

        def _finish_service(done: asyncio.Task[Any]) -> None:
            service_tasks.discard(done)
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001
                _REQUEST_LOG.error(
                    "gateway background service failed", exc_info=True
                )

        task.add_done_callback(_finish_service)

    data_dir = Path(settings.usage_db_path).parent
    workflow_event_log = DurableWorkflowEventLog(data_dir / "workflow-events.db")
    app.state.workflow_event_log = workflow_event_log
    store = ConnectionStore(data_dir / "connections.json")
    app.state.store = store
    app.state.router = Router(
        store=store,
        durable_event_sink=workflow_event_log.append,
    )
    # 本地 GGUF 冷启/验证最长可达 90s，绝不能阻塞网关、微信或健康检查。
    # 先建立云端 Router 并开放服务，再在后台启动受审 local；成功后热重载。
    import threading as _threading

    _loop = asyncio.get_running_loop()
    _local_stop = _threading.Event()
    app.state.local_model_stop_event = _local_stop

    def _bg_local() -> None:
        try:
            if _local_stop.is_set():
                return
            if local_model.should_autodownload() and not local_model.available():
                if not local_model.download_model():
                    return
            if _local_stop.is_set() or not local_model.start(_local_stop):
                return
            if _local_stop.is_set():
                local_model.stop()
                return
            asyncio.run_coroutine_threadsafe(app.state.router.reload(), _loop)
        except Exception:  # noqa: BLE001 - local is optional and stays hidden on failure
            return

    # Do not start optional local work until every mandatory startup step has
    # succeeded.  Python cannot forcibly stop a thread blocked in a remote
    # model download, so starting it here used to leak that daemon when a
    # later cloud/database initialization failed before lifespan yielded.
    local_model_worker = _threading.Thread(
        target=_bg_local,
        name="nachuan-local-model",
        daemon=True,
    )
    app.state.local_model_worker = local_model_worker
    app.state.usage = UsageLogger(settings.usage_db_path)
    app.state.conversations = ConversationStore(
        db_path=str(Path(settings.usage_db_path).parent / "conversations.db")
    )  # 短期多轮记忆·持久化(引擎重启不丢上下文，飞书常驻机器人尤其需要)
    # The ordinary chat surface remains diagnosable if this fails, while every
    # rights endpoint fails closed before parsing a request body. Production
    # readiness must treat None as a compliance-control failure.
    app.state.privacy_rights = initialize_privacy_rights(data_dir)
    # Bind cloud credentials to the same runtime root as every other gateway
    # store, then migrate/revoke any legacy plaintext before the API becomes
    # reachable. Waiting for the periodic worker would leave exposed bearer
    # tokens on disk for at least another sync interval.
    from orchestrator import cloud_sync

    cloud_sync.bind_data_dir(data_dir)
    await run_in_threadpool(cloud_sync.load_cfg)
    app.state.weixin_idempotency = WeixinIdempotencyStore(
        data_dir / "weixin_agent_idempotency.db"
    )
    # Open paid authority first so packaged channel media can prove that its
    # independently opened Root/controller belongs to that exact installation
    # epoch.  Development still opens only its historical data-dir store.
    await run_in_threadpool(_initialize_paid_media_authority, app, data_dir)
    await run_in_threadpool(_initialize_channel_media_authority, app, data_dir)
    if app.state.media_requests is not None:
        try:
            await _restore_durable_video_capacity(app.state.background_jobs)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- isolate paid recovery from chat startup
            await run_in_threadpool(
                _disable_paid_media_authority,
                app,
                "paid-video-capacity-restore-failed",
            )
    app.state.memory = MemoryStore(str(data_dir / "memory.db"))  # 长期用户记忆
    app.state.cases = CaseLibrary(str(data_dir / "cases.db"))  # 案例库/技能库（师生进化）
    app.state.kb = KnowledgeBase(str(data_dir / "knowledge.db"))  # 知识库（IMA：文档检索+引用）
    app.state.approvals = ApprovalStore(
        str(data_dir / "approvals.db"),
        action_ttl_sec=settings.approval_action_ttl_sec,
    )  # P5/P6 待审：重大动作 + 技能卡入库
    app.state.ledger = TaskLedger(str(data_dir / "ledger.db"))  # 执行脊柱·任务台账（断点续跑）
    # 撤销能力使用 DPAPI 保护的持久签名密钥 + 一次性 SQLite receipt。密钥不可用时
    # 安全降级为“无撤销按钮”，绝不回退成任意 path/content 写接口。
    app.state.undo_receipts = None
    undo_key_path = data_dir / "undo-signing-key.protected.json"
    try:
        try:
            undo_key_doc = read_protected_json(
                undo_key_path, purpose="undo-receipt-signing/v1"
            )
            undo_key = bytes.fromhex(str(undo_key_doc.get("key_hex") or ""))
        except FileNotFoundError:
            undo_key = secrets.token_bytes(32)
            write_protected_json(
                undo_key_path,
                {"key_hex": undo_key.hex()},
                purpose="undo-receipt-signing/v1",
            )
        app.state.undo_receipts = UndoReceiptStore(data_dir / "undo_receipts.db", undo_key)
        undo_receipts.configure(app.state.undo_receipts)
    except (SecureStorageError, OSError, ValueError):
        undo_receipts.configure(None)
    app.state.guard = HookGuard(  # 确定性 Hooks：成本闸 + 内容拦截
        daily_cap=settings.agent_daily_call_cap,
        denylist=settings.content_denylist_list,
        owner_id=settings.agent_user_id,
    )
    # 预热本地语音模型：首次转写不再卡在"加载模型"（base 在 CPU 上加载要好几秒）。后台线程，不阻塞启动。
    import threading

    def _warm_audio() -> None:
        try:
            from gateway.audio import warm as _warm

            _warm()  # 预热主路径 SenseVoice + 兜底 whisper（缺哪个都安全降级）
        except Exception:  # noqa: BLE001
            pass

    # 预热省 token 组件（都安全降级，缺模型/依赖也不影响启动）：
    #  · LLMLingua-2 压缩器（CPU 加载十几秒，提前热好首次压缩不卡）
    #  · 语义缓存 embedding + GPTCache（仅在 SEMCACHE_ENABLED 时才值得预热）
    def _warm_savers() -> None:
        # 压缩器（713MB BERT）默认不在启动预热，改为首次用到时懒加载，
        # 避免和语音/首屏抢 CPU 与内存。需提前热可设 SAVERS_WARM=1。
        import os

        try:
            if os.getenv("SAVERS_WARM") == "1":
                from orchestrator.compress import enabled as _c_en, warm as _c_warm

                if _c_en():
                    _c_warm()
        except Exception:  # noqa: BLE001
            pass
        try:
            if semcache.enabled():
                semcache.warm()
        except Exception:  # noqa: BLE001
            pass

    # The legacy self-hosted sync path used the gateway bearer as an outbound
    # credential and relied on a pre-check followed by a second DNS resolution.
    # It is not a production trust boundary.  Keep the setting only to detect a
    # stale deployment and fail closed; Supabase cloud_sync uses an independent
    # credential, target fencing and protected storage.
    if settings.sync_server_url:
        raise RuntimeError(
            "SYNC_SERVER_URL is disabled: migrate to protected cloud sync before startup"
        )

    # 自动备份：定时把案例库快照成 JSON（容灾/点位恢复；backup_dir 可指向网盘做离线异地）
    async def _backup_loop() -> None:
        import os as _os

        from orchestrator.sync import snapshot_cases

        _bdir = settings.backup_dir or _os.path.join(str(data_dir), "backup")
        _uid = settings.agent_user_id or "owner"
        while True:
            await asyncio.sleep(max(300, settings.backup_interval_sec))
            try:
                snapshot_cases(app.state.cases, _bdir, _uid)
            except Exception:  # noqa: BLE001
                pass

    spawn_background(_backup_loop())

    # 打包版也必须在进程内用 SQLite Backup API 定期备份全部顶层 *.db。
    # 首轮只短暂让路启动；后续沿用运维备份周期，且纳入 lifespan 可取消任务集。
    app.state.sqlite_backup_health = _new_sqlite_backup_health()
    spawn_background(
        _sqlite_backup_loop(
            app,
            data_dir,
            interval_sec=max(
                _SQLITE_BACKUP_MIN_INTERVAL_SEC,
                float(settings.backup_interval_sec),
            ),
        )
    )

    # 跨设备云同步（Supabase）：就绪（已配置+登录）则定时自动 push/pull 记忆/案例/知识库，优雅降级
    async def _cloud_sync_loop() -> None:
        from starlette.concurrency import run_in_threadpool

        from orchestrator import cloud_sync

        while True:
            await asyncio.sleep(max(120, settings.sync_interval_sec))
            try:
                if cloud_sync.available():
                    await run_in_threadpool(cloud_sync.sync_all)
            except Exception:  # noqa: BLE001
                pass

    spawn_background(_cloud_sync_loop())

    # Optional daemons and warmups start only after every mandatory startup
    # gate has passed. Preserve Thread.start as the startup root cause even if
    # closing a previously constructed database also fails.
    try:
        local_model_worker.start()
    except BaseException:
        try:
            await _drain_gateway_lifespan(app)
        except BaseException:
            pass
        raise
    try:
        if os.getenv("NACHUAN_WARM_AUDIO") == "1":
            try:
                audio_warmup_worker = threading.Thread(
                    target=_warm_audio,
                    name="nachuan-audio-warm",
                    daemon=True,
                )
                warmup_workers["audio"] = audio_warmup_worker
                audio_warmup_worker.start()
            except Exception:  # noqa: BLE001 -- optional warmup stays optional
                pass
        try:
            from orchestrator.embedder import start_warmup as _emb_warm

            embedding_warmup_worker = _emb_warm()
            if embedding_warmup_worker is not None:
                warmup_workers["embedding"] = embedding_warmup_worker
        except Exception:  # noqa: BLE001 -- optional warmup stays optional
            pass
        try:
            savers_warmup_worker = threading.Thread(
                target=_warm_savers,
                name="nachuan-savers-warm",
                daemon=True,
            )
            warmup_workers["savers"] = savers_warmup_worker
            savers_warmup_worker.start()
        except Exception:  # noqa: BLE001 -- optional warmup stays optional
            pass
        yield
    finally:
        await _drain_gateway_lifespan(app)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Guard startup failures that occur before the implementation yields."""

    await _retry_previous_gateway_generation(app)
    app.state.gateway_lifespan_drain_finished = False
    app.state.gateway_shutdown_failures = ()
    startup_completed = False
    try:
        async with _lifespan_impl(app):
            startup_completed = True
            yield
    except BaseException:
        if not startup_completed:
            try:
                await _drain_gateway_lifespan(app)
            except BaseException:  # preserve the original startup root cause
                pass
        raise


app = FastAPI(title="大模型聚合器网关", version="0.2.0", lifespan=lifespan)

_REQUEST_LOG = logging.getLogger("nachuan.requests")
_USAGE_LOG = logging.getLogger("nachuan.usage")
_TRACE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PAID_MEDIA_ASSET_PATH_PREFIX = "/v1/paid-media/assets/"


def _redacted_request_path(path: object) -> str:
    normalized = str(path or "")
    if (
        normalized.startswith(_PAID_MEDIA_ASSET_PATH_PREFIX)
        and normalized != f"{_PAID_MEDIA_ASSET_PATH_PREFIX}ack"
    ):
        return f"{_PAID_MEDIA_ASSET_PATH_PREFIX}<redacted>"
    return normalized


async def _log_usage_best_effort(logger: Any, **values: Any) -> bool:
    """Write synchronous SQLite usage accounting off-loop without risking the reply."""

    try:
        await run_in_threadpool(logger.log, **values)
        return True
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 -- accounting failure must not replace business output
        _USAGE_LOG.error("usage accounting write failed", exc_info=True)
        return False


@app.middleware("http")
async def attach_trace_id(request: Request, call_next):
    """Give every Turn a safe correlation id without logging payloads or credentials."""
    incoming = request.headers.get("x-request-id", "")
    trace_id = incoming if _TRACE_ID_RE.fullmatch(incoming) else secrets.token_hex(16)
    request.state.trace_id = trace_id
    started = time.perf_counter()
    status_code = 500
    log_path = _redacted_request_path(request.url.path)
    try:
        with bind_provider_call_context(
            ProviderCallContext(
                trace_id=trace_id,
                turn_id=None,
                workflow_id=f"http:{log_path}",
            )
        ):
            response = await call_next(request)
        status_code = response.status_code
        elapsed_ms = (time.perf_counter() - started) * 1000
        # The outer Desktop engine-session wrapper signs a strict, bounded JSON
        # response contract.  Its non-secret authenticated state is already the
        # correlation boundary, so do not make the inner middleware append
        # unsigned diagnostic headers that would invalidate every response.
        state = request.scope.get("state")
        session_state = (
            state.get(DESKTOP_SESSION_STATE_KEY)
            if isinstance(state, dict)
            else None
        )
        session_capability = (
            session_state.get("capability")
            if isinstance(session_state, dict)
            else None
        )
        desktop_verifier = getattr(
            request.app.state, "desktop_engine_session_verifier", None
        )
        desktop_session = (
            isinstance(desktop_verifier, DesktopEngineSessionGatewayApp)
            and isinstance(session_capability, str)
            and desktop_verifier.accepts_authenticated_state(
                session_state,
                expected_capability=session_capability,
            )
        )
        if not desktop_session:
            response.headers["X-Trace-ID"] = trace_id
            response.headers["Server-Timing"] = f"app;dur={elapsed_ms:.1f}"
        return response
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000
        _REQUEST_LOG.info(
            "trace=%s method=%s path=%s status=%s latency_ms=%.1f",
            trace_id,
            request.method,
            log_path,
            status_code,
            elapsed_ms,
        )


_PAID_MEDIA_CREATE_PATHS = frozenset(
    {"/v1/images/generations", "/v1/videos/generations"}
)
_PAID_IMAGE_BODY_FIELDS = frozenset(
    {"model", "prompt", "n", "size", "response_format"}
)
_PAID_VIDEO_BODY_FIELDS = frozenset(
    {
        "model",
        "prompt",
        "image",
        "mode",
        "height",
        "width",
        "num_frames",
        "frame_rate",
        "extra_body",
    }
)
_PAID_VIDEO_EXTRA_BODY_FIELDS = frozenset({"image", "mode"})


def _require_versioned_paid_media_body(body: object, *, video: bool) -> None:
    """Reject provider-specific extras that bypass Desktop's trusted summary."""

    if not isinstance(body, dict):
        raise ValueError("paid media body must be an object")
    allowed = _PAID_VIDEO_BODY_FIELDS if video else _PAID_IMAGE_BODY_FIELDS
    if not set(body).issubset(allowed):
        raise ValueError("paid media body contains an unsupported field")
    if not video:
        return
    extra_body = body.get("extra_body")
    if extra_body is not None:
        if not isinstance(extra_body, dict) or not set(extra_body).issubset(
            _PAID_VIDEO_EXTRA_BODY_FIELDS
        ):
            raise ValueError("paid video extra_body contains an unsupported field")
    inputs: list[object] = []
    for value in (
        body.get("image"),
        extra_body.get("image") if isinstance(extra_body, dict) else None,
    ):
        if value is None:
            continue
        inputs.extend(value if isinstance(value, list) else [value])
    if len(inputs) > 4 or any(
        not isinstance(item, str) or not item.strip() for item in inputs
    ):
        raise ValueError("paid video keyframes must be non-empty strings")


def _invalid_paid_media_body_response() -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": {
                "code": "invalid_media_request",
                "message": "Paid media request body is invalid.",
                "retryable": False,
            }
        },
        headers={"Cache-Control": "no-store"},
    )


@app.exception_handler(UnicodeDecodeError)
async def _bad_encoding(request: Request, _exc: UnicodeDecodeError) -> JSONResponse:
    """请求体不是 UTF-8（如客户端用了 GBK）→ 给个干净的 400，而不是难看的 500。"""
    if request.url.path in _PAID_MEDIA_CREATE_PATHS:
        return _invalid_paid_media_body_response()
    return JSONResponse(status_code=400, content={"detail": "请求体编码需为 UTF-8"})


@app.exception_handler(json.JSONDecodeError)
async def _bad_json(request: Request, _exc: json.JSONDecodeError) -> JSONResponse:
    """请求体不是合法 JSON → 干净的 400。"""
    if request.url.path in _PAID_MEDIA_CREATE_PATHS:
        return _invalid_paid_media_body_response()
    return JSONResponse(status_code=400, content={"detail": "请求体不是合法 JSON"})


@app.exception_handler(RequestValidationError)
async def _request_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    missing_paid_media_key = request.url.path in _PAID_MEDIA_CREATE_PATHS and any(
        len(location := tuple(error.get("loc") or ())) >= 2
        and str(location[0]).lower() == "header"
        and str(location[-1]).lower() == "idempotency-key"
        for error in exc.errors()
    )
    if missing_paid_media_key:
        http_error = _invalid_media_idempotency_key_error()
        return JSONResponse(
            status_code=http_error.status_code,
            content={"detail": http_error.detail},
            headers=http_error.headers,
        )
    if request.url.path in _PAID_MEDIA_CREATE_PATHS:
        return _invalid_paid_media_body_response()
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(BackgroundJobLimitExceeded)
async def _background_job_full(
    _request: Request, _exc: BackgroundJobLimitExceeded
) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "后台任务已达稳定性上限，请等待已有任务结束"},
        headers={"Retry-After": "30", "Cache-Control": "no-store"},
    )


def _admission_key_hashes() -> frozenset[str]:
    """Use exactly the same live key sources as ``require_api_key``.

    The middleware receives hashes only. Clearing the legacy dynamic-source cache
    before each snapshot prevents a newly accepted desktop key from getting one
    unmetered request before authentication refreshes that cache.
    """

    desktop_engine_keys.cache_clear()
    settings = get_settings()
    bridge_keys = {
        str(settings.nachuan_weixin_bridge_api_key or "").strip(),
        str(settings.nachuan_feishu_bridge_api_key or "").strip(),
    }
    bridge_keys.discard("")
    return hash_api_keys(settings.api_keys | desktop_engine_keys() | bridge_keys)


class _ConfiguredAdmissionControlMiddleware(AdmissionControlMiddleware):
    """Resolve settings when Starlette builds the stack, not at module import.

    This keeps startup/test environment injection authoritative while ensuring the
    middleware receives only API-key hashes, never plaintext credentials.
    """

    def __init__(self, downstream: Any) -> None:
        settings = get_settings()
        super().__init__(
            downstream,
            db_path=Path(settings.usage_db_path).parent / "admission.db",
            valid_key_hashes_provider=_admission_key_hashes,
            max_concurrency_per_key=settings.admission_max_concurrency_per_key,
            max_concurrency_global=settings.admission_max_concurrency_global,
            rolling_minute_per_key=settings.admission_rolling_minute_per_key,
            daily_expensive_per_key=settings.admission_daily_expensive_per_key,
        )


def _bridge_protocol_keys() -> dict[str, str]:
    """Return only channel-scoped capabilities to the loopback envelope terminator."""

    settings = get_settings()
    return {
        "weixin": str(settings.nachuan_weixin_bridge_api_key or "").strip(),
        "feishu": str(settings.nachuan_feishu_bridge_api_key or "").strip(),
    }


class _ConfiguredBridgeProtocolMiddleware(BridgeProtocolMiddleware):
    def __init__(self, downstream: Any) -> None:
        settings = get_settings()
        replay_path = Path(settings.usage_db_path).parent / "bridge_protocol_replay.db"
        super().__init__(
            downstream,
            key_provider=_bridge_protocol_keys,
            replay_guard=PersistentNonceReplayGuard(replay_path),
        )


app.add_middleware(_ConfiguredAdmissionControlMiddleware)
app.add_middleware(_ConfiguredBridgeProtocolMiddleware)
app.add_middleware(RequestBodyLimitMiddleware)
# Starlette wraps user middleware in reverse addition order.  CORS must be
# added last so BodyLimit/Bridge/Admission short-circuit responses still carry
# the desktop renderer's allow-origin header.  The allowlist remains loopback
# only; a remote web origin cannot drive the local gateway.
# X-Nachuan-Paid-Media-Key is deliberately absent: renderer code must cross the
# validated Electron main IPC proxy and never receive the paid capability.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_origin_regex=r"^(?:https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?|null|file://)$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.include_router(admin_router)
app.include_router(channel_recovery_router)
app.include_router(privacy_admin_router)
app.include_router(subscription_connectors_router)
app.include_router(team_session_router)
app.include_router(enterprise_rag_router)


def _compute_code_version() -> int:
    """引擎源码版本 = gateway/ + orchestrator/ 下 .py 文件的最新 mtime（秒，取整）。
    桌面 app 据此判断 :8080 上运行中的引擎是不是"当前源码版"——改了代码但引擎没重启（旧代码还在内存里）
    → app 自动杀掉旧引擎重起，加载新代码。根治"复用旧引擎、改了没生效"的反复坑。"""
    import glob as _glob
    import os as _os
    latest = 0.0
    for pat in ("gateway/**/*.py", "orchestrator/**/*.py"):
        for f in _glob.glob(str(PROJECT_ROOT / pat), recursive=True):
            try:
                latest = max(latest, _os.path.getmtime(f))
            except OSError:  # noqa: PERF203
                pass
    return int(latest)


_CODE_VERSION = _compute_code_version()


def _database_readiness() -> dict[str, Any]:
    """Probe the live SQLite handles without exposing paths, SQL, or credentials."""
    handles = {
        "usage": getattr(getattr(app.state, "usage", None), "_conn", None),
        "conversations": getattr(getattr(app.state, "conversations", None), "_conn", None),
        "memory": getattr(getattr(app.state, "memory", None), "_conn", None),
        "cases": getattr(getattr(app.state, "cases", None), "_conn", None),
        "knowledge": getattr(getattr(app.state, "kb", None), "_conn", None),
        "approvals": getattr(getattr(app.state, "approvals", None), "_conn", None),
        "ledger": getattr(getattr(app.state, "ledger", None), "_db", None),
        "workflow_events": getattr(
            getattr(app.state, "workflow_event_log", None), "_conn", None
        ),
    }
    failed: list[str] = []
    for name, conn in handles.items():
        try:
            if conn is None or conn.execute("SELECT 1").fetchone() is None:
                failed.append(name)
        except Exception:  # noqa: BLE001 -- health must degrade instead of throwing
            failed.append(name)
    return {"ready": not failed, "checked": len(handles), "failed": failed}


def _provider_readiness() -> dict[str, Any]:
    try:
        models = app.state.router.list_models()
        providers = {str(m.get("owned_by") or "") for m in models if m.get("owned_by")}
        return {
            "ready": bool(providers - {"echo"}),
            "count": len(providers),
            "external_count": len(providers - {"echo"}),
            "model_count": len(models),
        }
    except Exception:  # noqa: BLE001
        return {"ready": False, "count": 0, "external_count": 0, "model_count": 0}


def _connection_store_readiness() -> dict[str, Any]:
    """Expose quarantined provider names only; never values or validation details."""

    try:
        invalid = app.state.store.invalid()
        names = sorted({str(name)[:64] for name in invalid})
        return {"ready": not names, "quarantined": names}
    except Exception:  # noqa: BLE001 -- diagnostics must degrade without leaking internals
        return {"ready": False, "quarantined": []}


def _financial_ledger_readiness() -> dict[str, Any]:
    """Project the required provider-call ledger without exposing its path."""

    ledger = getattr(app.state, "provider_call_ledger", None)
    try:
        snapshot = ledger.operational_snapshot()
        required = bool(snapshot.get("required"))
        return {
            "required": required,
            # Formal channel/review operation requires durable commercial
            # accounting.  A disabled or best-effort handle may be useful for
            # development, but it is never production readiness.
            "ready": bool(required and snapshot.get("ready")),
            "status": str(snapshot.get("status") or "unavailable")[:32],
            "capacity_status": str(
                snapshot.get("capacity_status") or "unknown"
            )[:32],
            "database_bytes": max(0, int(snapshot.get("database_bytes") or 0)),
            "wal_bytes": max(0, int(snapshot.get("wal_bytes") or 0)),
            "max_database_bytes": max(
                0, int(snapshot.get("max_database_bytes") or 0)
            ),
            "disk_free_bytes": max(0, int(snapshot.get("disk_free_bytes") or 0)),
            "last_write_error_type": (
                str(snapshot.get("last_write_error_type") or "")[:128] or None
            ),
            "last_write_error_at": snapshot.get("last_write_error_at"),
        }
    except Exception as exc:  # noqa: BLE001 -- readiness must fail closed, not leak text
        return {
            "required": bool(getattr(ledger, "required", False)),
            "ready": False,
            "status": "unavailable",
            "capacity_status": "unknown",
            "database_bytes": 0,
            "wal_bytes": 0,
            "max_database_bytes": 0,
            "disk_free_bytes": 0,
            "last_write_error_type": type(exc).__name__[:128],
            "last_write_error_at": None,
        }


def _sqlite_backup_readiness() -> dict[str, Any]:
    """Expose backup progress without leaking exception text or local parent paths."""

    health = dict(
        getattr(app.state, "sqlite_backup_health", None)
        or _new_sqlite_backup_health()
    )
    status = str(health.get("status") or "pending")[:32]
    snapshot_path = str(health.get("snapshot_path") or "")
    return {
        "ready": status == "ok",
        "status": status,
        "last_attempt_at": health.get("last_attempt_at"),
        "last_success_at": health.get("last_success_at"),
        "last_error": str(health.get("last_error") or "")[:128] or None,
        "snapshot": Path(snapshot_path).name if snapshot_path else None,
        "database_count": max(0, int(health.get("database_count") or 0)),
    }


def _weixin_readiness(data_dir: Path, *, fresh_for_sec: int = 120) -> dict[str, Any]:
    token_file = data_dir / "ilink_token.json"
    configured = False
    storage_error = False
    try:
        configured = bool(
            read_protected_json(
                token_file,
                purpose="nachuan/ilink-token",
                migrate_plaintext=True,
            ).get("bot_token")
        )
    except FileNotFoundError:
        pass
    except SecureStorageError:
        storage_error = True

    result: dict[str, Any] = {
        "configured": configured,
        "state": "storage_error" if storage_error else ("not_configured" if not configured else "missing"),
        "fresh": False,
        "ready": False,
        "age_sec": None,
        "pending_inbound": 0,
        "pending_outbound": 0,
        "dead_inbound": 0,
        "dead_outbound": 0,
    }
    try:
        snapshot = json.loads((data_dir / "weixin_bridge_health.json").read_text("utf-8"))
        age = max(0, int(time.time() - float(snapshot.get("updated_at") or 0)))
        result.update(
            fresh=age <= fresh_for_sec,
            age_sec=age,
            pending_inbound=max(0, int(snapshot.get("pending_inbound") or 0)),
            pending_outbound=max(0, int(snapshot.get("pending_outbound") or 0)),
            dead_inbound=max(0, int(snapshot.get("dead_inbound") or 0)),
            dead_outbound=max(0, int(snapshot.get("dead_outbound") or 0)),
        )
        if not storage_error:
            result["state"] = str(snapshot.get("state") or "unknown")[:40]
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    result["ready"] = bool(
        result["configured"]
        and result["fresh"]
        and result["state"] == "healthy"
        and result["pending_inbound"] == 0
        and result["pending_outbound"] == 0
        and result["dead_inbound"] == 0
        and result["dead_outbound"] == 0
    )
    return result


def _paid_media_authority_readiness() -> dict[str, Any]:
    """Return live controller state without identifiers, digests or paths."""

    stored = dict(
        getattr(app.state, "paid_media_authority", None)
        or _paid_media_authority_status(
            mode="disabled",
            reason_code="not-initialized",
            new_operations_ready=False,
            replay_available=False,
            packaged=_is_packaged_runtime(),
        )
    )
    control = getattr(app.state, "installation_root_control", None)
    asset_control = getattr(app.state, "asset_installation_control", None)
    gateway_mode = "development" if not bool(stored.get("packaged")) else "unavailable"
    asset_mode = "development" if not bool(stored.get("packaged")) else "unavailable"
    if control is not None and asset_control is not None:
        try:
            current = control.state
            current_asset = asset_control.state
            gateway_mode = str(current.mode or "unavailable")
            asset_mode = str(current_asset.mode or "unavailable")
            pair_modes = {gateway_mode, asset_mode}
            replay_available = (
                gateway_mode in {"ready", "manual_only"}
                and asset_mode in {"ready", "manual_only"}
                and getattr(app.state, "media_requests", None) is not None
                and getattr(app.state, "paid_media_assets", None) is not None
            )
            if "provisioned_not_active" in pair_modes and pair_modes <= {
                "provisioned_not_active",
                "ready",
            }:
                stored.update(
                    mode="provisioned_not_active",
                    reason_code="awaiting-installation-activation",
                    new_operations_ready=False,
                    replay_available=False,
                )
            elif "manual_only" in pair_modes and pair_modes <= {
                "ready",
                "manual_only",
            }:
                stored.update(
                    mode="manual_only",
                    reason_code="manual-recovery-required",
                    new_operations_ready=False,
                    replay_available=replay_available,
                )
            elif pair_modes == {"ready"}:
                stored.update(
                    mode="ready",
                    reason_code="authority-exact",
                    new_operations_ready=bool(current.outbound_ready),
                    replay_available=replay_available,
                )
            else:
                stored.update(
                    mode="disabled",
                    reason_code="controller-state-unavailable",
                    new_operations_ready=False,
                    replay_available=False,
                )
        except Exception:  # noqa: BLE001 -- diagnostics remain fixed and secret-free
            gateway_mode = "unavailable"
            asset_mode = "unavailable"
            stored.update(
                mode="disabled",
                reason_code="controller-state-unavailable",
                new_operations_ready=False,
                replay_available=False,
            )
    elif bool(stored.get("packaged")):
        stored.update(
            mode="disabled",
            reason_code="controller-pair-unavailable",
            new_operations_ready=False,
            replay_available=False,
        )
    # Installation Root, the boot-scoped session verifier, and Desktop's v2
    # staging authority are independent gates. A green HMAC verifier must never
    # be projected as permission to create a new paid operation.
    session_verifier = getattr(
        app.state, "paid_media_engine_session_verifier", None
    )
    try:
        session_verifier_ready = bool(
            getattr(session_verifier, "ready", False)
        )
    except Exception:  # noqa: BLE001 -- diagnostics fail closed
        session_verifier_ready = False
    try:
        desktop_v2_stage_ready = bool(
            getattr(session_verifier, "stage_ready", False)
        )
    except Exception:  # noqa: BLE001 -- diagnostics fail closed
        desktop_v2_stage_ready = False
    if bool(stored.get("packaged")):
        if not session_verifier_ready:
            stored.update(
                mode="disabled",
                reason_code="engine-session-capability-unavailable",
                new_operations_ready=False,
            )
        elif not desktop_v2_stage_ready:
            stored.update(
                mode="disabled",
                reason_code="desktop-v2-stage-authority-unavailable",
                new_operations_ready=False,
            )
    mode = str(stored.get("mode") or "disabled")
    reason_code = str(stored.get("reason_code") or "unknown")
    if re.fullmatch(r"[a-z0-9_-]{1,64}", mode) is None:
        mode = "disabled"
    if re.fullmatch(r"[a-z0-9-]{1,96}", reason_code) is None:
        reason_code = "unknown"
    status = _paid_media_authority_status(
        mode=mode,
        reason_code=reason_code,
        new_operations_ready=bool(stored.get("new_operations_ready")),
        replay_available=bool(stored.get("replay_available")),
        packaged=bool(stored.get("packaged")),
    )
    # The generic repository SQLite snapshot does not include Installation
    # Root, its controller ledger, the asset-store database, or private object
    # bytes. Expose this release blocker explicitly instead of implying that a
    # green generic backup check protects paid-media authority.
    status.update(
        gateway_mode=(
            gateway_mode
            if gateway_mode
            in {"development", "provisioned_not_active", "ready", "manual_only", "fused"}
            else "unavailable"
        ),
        asset_mode=(
            asset_mode
            if asset_mode
            in {"development", "provisioned_not_active", "ready", "manual_only", "fused"}
            else "unavailable"
        ),
        engine_session_verifier_ready=session_verifier_ready,
        desktop_v2_stage_authority_ready=desktop_v2_stage_ready,
        backup_supported=False,
        backup_reason_code="paid-authority-backup-unsupported",
        reanchor_supported=False,
    )
    return status


def _channel_media_request_readiness() -> dict[str, Any]:
    """Expose durable channel-media authority without paths or identities."""

    store = getattr(app.state, "channel_media_requests", None)
    authority = getattr(app.state, "channel_media_authority", None)
    if isinstance(authority, Mapping) and bool(authority.get("packaged")):
        controller = getattr(
            app.state, "channel_media_installation_control", None
        )
        mode = str(authority.get("mode") or "")
        ready = False
        read_capable = False
        try:
            control_state = controller.state
            attached_store = controller.store
            read_capable = (
                isinstance(controller, ChannelMediaInstallationControl)
                and isinstance(store, DurableChannelMediaRequestStore)
                and attached_store is store
                and control_state.mode in {"ready", "manual_only"}
                and control_state.installation_id
                == getattr(app.state, "paid_media_installation_id", None)
                and control_state.epoch
                == getattr(app.state, "paid_media_epoch", None)
            )
            ready = (
                read_capable
                and mode == "ready"
                and bool(authority.get("new_operations_ready"))
                and bool(control_state.provider_dispatch_ready)
            )
        except (AttributeError, ChannelMediaInstallationControlUnavailable):
            ready = False
            read_capable = False
        public_mode = (
            "ready"
            if ready
            else "manual_only"
            if read_capable and mode == "manual_only"
            else "unavailable"
        )
    else:
        ready = isinstance(store, DurableChannelMediaRequestStore)
        public_mode = "durable" if ready else "unavailable"
    return {
        "ready": ready,
        "mode": public_mode,
        # Generic SQLite snapshots exist, but a tested installation-level
        # restore/re-anchor contract for this new authority does not yet.
        "backup_supported": False,
        "reanchor_supported": False,
        "real_channel_e2e_verified": False,
    }


@app.get("/health")
async def health(request: Request) -> dict[str, Any]:
    # Supervisor 以随机 challenge 校验本次托管子进程的 boot token。proof 不泄露
    # runtime/approval key，并能拒绝普通的回环端口抢占；它不是同一 OS 用户下的
    # 恶意进程隔离边界（同用户隔离必须由独立低权限身份/AppContainer 提供）。
    challenge = str(request.query_params.get("challenge") or "").strip().lower()
    boot_token = str(os.getenv("NACHUAN_ENGINE_BOOT_TOKEN") or "").strip().lower()
    boot_proof = ""
    if re.fullmatch(r"[0-9a-f]{64}", challenge) and re.fullmatch(
        r"[0-9a-f]{64}", boot_token
    ):
        boot_proof = hmac.new(
            bytes.fromhex(boot_token), challenge.encode("ascii"), hashlib.sha256
        ).hexdigest()
    settings = get_settings()
    data_dir = Path(settings.usage_db_path).parent
    database = _database_readiness()
    financial_ledger = _financial_ledger_readiness()
    connection_store = _connection_store_readiness()
    core_ready = bool(
        database["ready"]
        and financial_ledger["ready"]
        and connection_store["ready"]
    )
    return {
        "status": "ok",
        "readiness": "ok" if core_ready else "degraded",
        "pid": os.getpid(),
        "code_version": _CODE_VERSION,
        "boot_proof": boot_proof,
        "checks": {
            "database": database,
            "financial_ledger": financial_ledger,
            "sqlite_backup": _sqlite_backup_readiness(),
            "connection_store": connection_store,
            "paid_media_authority": _paid_media_authority_readiness(),
            "channel_media_requests": _channel_media_request_readiness(),
            "providers": _provider_readiness(),
            "weixin": _weixin_readiness(data_dir),
        },
    }


@app.get("/v1/bridge/health")
async def bridge_health(
    model: str | None = None,
    credential: str = Depends(require_bridge_or_api_key),
) -> dict[str, Any]:
    """Cheap authenticated readiness probe for a channel-scoped capability."""

    channel = credential.split(":", 1)[1] if credential.startswith("bridge:") else "runtime"
    try:
        _select_agent_chat_model(app.state.router, model)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, Mapping) else {}
        reason = str(detail.get("code") or "")
        if exc.status_code != 503 or reason not in {
            "ready_no_model",
            "requested_model_unavailable",
        }:
            reason = "ready_no_model"
        return {
            "status": "ok",
            "channel": channel,
            "chat_ready": False,
            "reason": reason,
        }
    except Exception:  # noqa: BLE001 - readiness must fail closed without details
        return {
            "status": "ok",
            "channel": channel,
            "chat_ready": False,
            "reason": "ready_no_model",
        }
    if not _financial_ledger_readiness()["ready"]:
        return {
            "status": "ok",
            "channel": channel,
            "chat_ready": False,
            "reason": "provider_call_ledger_not_ready",
        }
    return {
        "status": "ok",
        "channel": channel,
        "chat_ready": True,
        "reason": "ready",
    }


_MAX_ORCHESTRATION_CAPABILITY_ROUTES = 256


def _closed_orchestration_capabilities(reason: str) -> dict[str, Any]:
    return {
        "chat_model_count": 0,
        "review_candidate_count": 0,
        "independent_identity_count": 0,
        "single_review_ready": False,
        "post_summary_final_review_ready": False,
        "four_vendor_review_ready": False,
        "reason": reason,
    }


def _capability_route_text(value: Any, *, max_chars: int = 512) -> str | None:
    """Accept only bounded plain route metadata; malformed values grant no capability."""

    if not isinstance(value, str):
        return None
    text = value.strip()
    if (
        not text
        or len(text) > max_chars
        or any(ord(char) < 0x20 for char in text)
    ):
        return None
    return text


def _maximum_independent_identity_count(
    identities: list[tuple[str, str, str]],
) -> int:
    """Return the largest set with distinct model families and trust domains."""

    graph: dict[str, set[str]] = {}
    for _model, family, domain in identities:
        graph.setdefault(family, set()).add(domain)

    domain_owner: dict[str, str] = {}

    def claim(family: str, visited: set[str]) -> bool:
        for domain in sorted(graph.get(family, ())):
            if domain in visited:
                continue
            visited.add(domain)
            owner = domain_owner.get(domain)
            if owner is None or claim(owner, visited):
                domain_owner[domain] = family
                return True
        return False

    matched = 0
    for family in sorted(graph):
        if claim(family, set()):
            matched += 1
    return matched


def _can_schedule_independent_reviews(
    initiators: list[tuple[str, str, str]],
    reviewers: list[tuple[str, str, str]],
    *,
    reviewer_count: int,
) -> bool:
    """Check for one initiator plus the requested number of independent reviewers."""

    for initiator_model, initiator_family, initiator_domain in initiators:
        eligible = [
            (model, family, domain)
            for model, family, domain in reviewers
            if model != initiator_model
            and family != initiator_family
            and domain != initiator_domain
        ]
        if _maximum_independent_identity_count(eligible) >= reviewer_count:
            return True
    return False


def _orchestration_capabilities(router: Router) -> dict[str, Any]:
    """Conservatively derive scheduling capability from the live route snapshot.

    This is prospective scheduling metadata, never proof that a review call ran or
    that an upstream model returned the expected identity.  Call-time ReviewGate
    receipts remain mandatory before any review receives a vote.
    """

    try:
        rows = router.routes_info()
    except Exception:  # noqa: BLE001 - a broken snapshot must fail closed
        return _closed_orchestration_capabilities("routes_snapshot_unavailable")
    if (
        not isinstance(rows, list)
        or len(rows) > _MAX_ORCHESTRATION_CAPABILITY_ROUTES
        or any(not isinstance(row, Mapping) for row in rows)
    ):
        return _closed_orchestration_capabilities("routes_snapshot_invalid")

    chat_models: set[str] = set()
    conflicted_models: set[str] = set()
    identity_by_model: dict[str, tuple[str, str, str]] = {}
    reviewer_by_model: dict[str, tuple[str, str, str]] = {}

    for row in rows:
        if _capability_route_text(row.get("modality"), max_chars=32) != "chat":
            continue
        model = _capability_route_text(row.get("model"))
        provider = _capability_route_text(row.get("provider"), max_chars=256)
        upstream = canonical_model_id(row.get("upstream_model"))
        if model is None or provider is None or upstream is None:
            continue
        # Echo is a local transport self-test, not a usable orchestration model.
        if model.casefold() == "echo" and provider.casefold() == "echo":
            continue
        if model in conflicted_models:
            continue
        if model in chat_models:
            # A real Router stores routes by unique virtual-model key.  Any
            # duplicate snapshot row is corrupt/forged, even when it repeats
            # the same advertised identity or candidate flag.
            chat_models.discard(model)
            identity_by_model.pop(model, None)
            reviewer_by_model.pop(model, None)
            conflicted_models.add(model)
            continue
        chat_models.add(model)

        family = normalize_model_family(row.get("model_family"))
        domain = normalize_independence_domain(row.get("independence_domain"))
        registry_family = model_family_from_identifier(upstream)
        if family is None or domain is None or family != registry_family:
            continue
        identity = (model, family, domain)
        identity_by_model[model] = identity

        tier = _capability_route_text(row.get("tier"), max_chars=32)
        if (
            row.get("review_vote_candidate") is True
            and row.get("review_strength") == "strong"
            and review_strength_from_identifier(upstream) == "strong"
            and tier is not None
            and tier.casefold() == "premium"
        ):
            reviewer_by_model[model] = identity

    identities = list(identity_by_model.values())
    reviewers = list(reviewer_by_model.values())
    independent_identity_count = _maximum_independent_identity_count(identities)
    single_review_ready = _can_schedule_independent_reviews(
        identities, reviewers, reviewer_count=1
    )
    post_summary_final_review_ready = _can_schedule_independent_reviews(
        identities, reviewers, reviewer_count=2
    )
    # Project policy means four reviewers *besides* the zero-vote initiator.
    four_vendor_review_ready = _can_schedule_independent_reviews(
        identities, reviewers, reviewer_count=4
    )

    if not chat_models:
        reason: str | None = "no_chat_models"
    elif not identities:
        reason = "no_trusted_chat_identity"
    elif not reviewers:
        reason = "no_schedulable_strong_review_candidates"
    elif not single_review_ready:
        reason = "single_review_requires_independent_initiator_and_reviewer"
    elif not post_summary_final_review_ready:
        reason = "post_summary_final_review_requires_two_independent_reviewers"
    elif not four_vendor_review_ready:
        reason = "four_vendor_review_requires_four_independent_reviewers"
    else:
        reason = None

    return {
        "chat_model_count": len(chat_models),
        "review_candidate_count": len(reviewers),
        "independent_identity_count": independent_identity_count,
        "single_review_ready": single_review_ready,
        "post_summary_final_review_ready": post_summary_final_review_ready,
        "four_vendor_review_ready": four_vendor_review_ready,
        "reason": reason,
    }


@app.get("/v1/orchestration/capabilities")
async def orchestration_capabilities(
    _: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Report only what the current route identities can conservatively schedule."""

    return _orchestration_capabilities(app.state.router)


def _plugin_ui_snapshot(router: Router) -> dict[str, object]:
    try:
        slots = router.plugin_kernel.ui_slot_snapshot()
    except Exception as exc:  # noqa: BLE001 -- project only a fixed failure
        raise HTTPException(
            status_code=503,
            detail="插件界面清单当前不可用",
            headers={"Cache-Control": "no-store"},
        ) from exc
    if len(slots) > 64:
        raise HTTPException(
            status_code=503,
            detail="插件界面清单当前不可用",
            headers={"Cache-Control": "no-store"},
        )
    return {
        "schema": "nachuan.plugin-ui.snapshot.v1",
        "slots": [dict(item) for item in slots],
    }


@app.get("/v1/plugin-ui/snapshot")
@app.get(
    "/internal/v1/desktop/session/plugin-ui-snapshot",
    include_in_schema=False,
)
async def plugin_ui_snapshot(
    api_key: str = Depends(require_api_key),
) -> JSONResponse:
    del api_key
    return JSONResponse(
        _plugin_ui_snapshot(app.state.router),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/v1/models")
async def list_models(_: str = Depends(require_api_key)) -> dict[str, Any]:
    router: Router = app.state.router
    data = router.list_models()
    # F5 虚拟模型号（Fugu「one model to command them all」）：舰队在（≥1 个真模型）才露出。
    if _fleet_available(router):
        data = data + [
            {"id": vid, "object": "model", "owned_by": "fleet", "tier": "premium",
             "modality": "chat", "description": desc, "chat_usable": True,
             "review_vote_candidate": False, "review_strength": None}
            for vid, desc in _FLEET_DESC.items()
        ]
    return {"object": "list", "data": data}


@app.get("/v1/local/catalog")
async def local_catalog(_: str = Depends(require_api_key)) -> dict[str, Any]:
    """自带本地模型目录（含下载/激活状态），供前端"模型选择"。"""
    ready_alias = local_model.ready_model_alias()
    return {
        "enabled": bool(ready_alias),
        "ready": bool(ready_alias),
        "attested": local_model.available(),
        "active": local_model.active_model_id(),
        "models": local_model.catalog(),
    }


@app.post("/v1/local/select")
async def local_select(request: Request, _: str = Depends(require_api_key)) -> dict[str, Any]:
    """Switch a verified local model after an exact one-time approval."""
    body = await request.json()
    mid = str(body.get("model_id", ""))
    if not any(e["id"] == mid for e in local_model.CATALOG):
        raise HTTPException(status_code=422, detail="未知本地模型 id")
    task = str(body.get("task") or f"切换本地模型为 {mid}")
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=str(PROJECT_ROOT),
        user_id=str(body.get("user_id") or get_settings().agent_user_id or "owner"),
        scope="local_model_select",
        mode="full",
        require_explicit_capability=True,
        payload_extra={"model_id": mid},
    )
    if held is not None:
        return held
    try:
        switched = await run_in_threadpool(local_model.switch, mid)
        if not switched:
            raise HTTPException(
                status_code=409,
                detail="模型文件/llama-server 未就绪；正式版不会下载无固定 revision+SHA256 的模型",
            )
        await app.state.router.reload()
    except Exception:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return {"status": "ready", "model_id": mid}


def _resolve_workdir(text: str, fallback: str) -> str:
    """消息里点名【真实存在】的绝对路径 → 取第一个命中（文件取父目录）；没点名 → fallback。

    只认真实存在的路径，让「整理我的下载文件夹 D:\\Downloads」这类明确目标能自动切换工作区，
    不再框死在项目根。任何异常都安全降级为 fallback；这里保持为网关通用能力，
    不依赖任何已停用的模型适配器。
    """
    if not text:
        return fallback
    candidates = re.findall(
        r'[A-Za-z]:[\\/][^\s，。、；：:"\'<>|?*\n\r]*', text
    )
    candidates += re.findall(
        r'/[^\s，。、；：:"\'<>|?*\n\r]+(?:/[^\s，。、；：:"\'<>|?*\n\r]+)*',
        text,
    )
    for raw in candidates:
        candidate = raw.rstrip("\\/，。、；:：")
        try:
            if os.path.exists(candidate):
                return candidate if os.path.isdir(candidate) else os.path.dirname(candidate)
        except OSError:
            continue
    return fallback


def _grow_memory(
    router: Any, user_msg: str, assistant_msg: str
) -> asyncio.Task[Any] | None:
    """A·记忆成长：后台从一次对话抽取并存机主长期记忆（任何对话路径都调它，让记忆越用越多）。"""
    if not (user_msg and assistant_msg):
        return None
    coro: Any | None = None
    try:
        owner = get_settings().agent_user_id or "owner"
        em = "agnes-flash" if router.resolve("agnes-flash") else (pick_model(router, "cheap") or "")
        if em:
            coro = extract_and_store(
                router,
                app.state.memory,
                user_id=owner,
                user_msg=user_msg,
                assistant_msg=assistant_msg,
                model=em,
            )
            registry = getattr(app.state, "background_tasks", None)
            if not isinstance(registry, set):
                raise RuntimeError("gateway background task registry is unavailable")
            with bind_provider_call_scope(role="memory.extract"):
                task = asyncio.create_task(coro)
            registry.add(task)

            def _finish_memory_extraction(done: asyncio.Task[Any]) -> None:
                registry.discard(done)
                try:
                    done.result()
                except asyncio.CancelledError:
                    pass
                except Exception:  # noqa: BLE001
                    _REQUEST_LOG.error(
                        "memory extraction background task failed", exc_info=True
                    )

            task.add_done_callback(_finish_memory_extraction)
            return task
    except Exception:  # noqa: BLE001
        if coro is not None and hasattr(coro, "close"):
            coro.close()
    return None


def _grow_from_terminal_agent_result(
    router: Any, task: str, result: Mapping[str, Any]
) -> asyncio.Task[Any] | None:
    """Learn only from synchronous terminal answers that claim completion."""

    if result.get("outcome") not in {"completed", "completed_unverified"}:
        return None
    reply = result.get("reply")
    if not isinstance(reply, str) or not reply.strip():
        return None
    return _grow_memory(router, task, reply)


async def _extract_and_store_scoped(
    provider_context: ProviderCallContext,
    router: Any,
    memory_store: Any,
    **kwargs: Any,
) -> Any:
    """Run deferred memory extraction with the originating Turn attribution."""

    with bind_provider_call_context(provider_context):
        return await extract_and_store(router, memory_store, **kwargs)


_SHORT_FOLLOWUP_RE = re.compile(
    r"^\s*(然后呢|然后|接着呢|接下来呢|下一步呢|下一步|继续|后来呢|结果呢|所以呢|那呢|怎么办|现在呢)[？?。.!！\s]*$",
    re.I,
)


def _msg_role(msg: Any) -> str:
    return str(msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", "") or "")


def _msg_text(msg: Any) -> str:
    content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict) and part.get("type") in (None, "text")
        )
    return "" if content is None else str(content)


def _shorten_context(text: str, limit: int = 1400) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[-limit:]


def _inject_followup_context(messages: list[Any]) -> bool:
    """短追问（如“然后呢？”）必须绑定前文，避免弱模型把它当孤立短语解释。"""
    last_user = max((i for i, m in enumerate(messages) if _msg_role(m) == "user"), default=-1)
    if last_user < 0:
        return False
    current = _msg_text(messages[last_user]).strip()
    if not _SHORT_FOLLOWUP_RE.match(current):
        return False
    prev_assistant = ""
    prev_user = ""
    for m in reversed(messages[:last_user]):
        role = _msg_role(m)
        text = _msg_text(m).strip()
        if not text:
            continue
        if role == "assistant" and not prev_assistant:
            prev_assistant = text
        elif role == "user" and not prev_user:
            prev_user = text
        if prev_assistant and prev_user:
            break
    if not (prev_assistant or prev_user):
        return False
    hint = (
        "本轮用户是对上一轮的短追问，不是让你解释这个短语本身。"
        "请承接前文回答下一步、后续状态或需要用户做什么。\n"
        f"上一条用户请求：{_shorten_context(prev_user)}\n"
        f"上一条助手回复：{_shorten_context(prev_assistant)}"
    )
    system_msg: Any = (
        {"role": "system", "content": hint}
        if messages and isinstance(messages[0], dict)
        else ChatMessage(role="system", content=hint)
    )
    messages.insert(last_user, system_msg)
    return True


# ══════════════ F5 虚拟模型号（Fugu「one model to command them all」的产品形态）══════════════
# 对外是两个"模型"，对内是被点将的模型舰队：nachuan=TRINITY 快档，nachuan-ultra=Conductor 深档。
# 任何 OpenAI 兼容客户端（桌面/飞书桥/第三方 SDK）选它们就等于调用整套编排。
VIRTUAL_FLEET: dict[str, str] = {"nachuan": "trinity", "nachuan-ultra": "conductor"}
_FLEET_DESC = {
    "nachuan": "纳川·智脑 —— 一个模型号背后的模型舰队（快档：点将轮转，日常任务）",
    "nachuan-ultra": "纳川·智脑 Ultra —— 深编排档（工作流 DAG + 并行分工，复杂任务）",
}
# OpenAI 兼容聊天面是 advisory：虚拟舰队可做多模型规划/评审，但显式授予零工具。
# 真正的浏览器、文件、命令和媒体动作只能走 /v1/agent/run 或 /v1/agent/exec。


def _fleet_available(router: "Router") -> bool:
    # 互审(Kimi)：畸形路由缺 model 键时 None != "echo" 会误判有真模型 → 显式要求非空。
    return any(r.get("model") and r.get("model") != "echo" for r in router.routes_info())


def _fleet_task_history(req: ChatCompletionRequest) -> tuple[str, list[dict[str, Any]]]:
    """从 OpenAI messages 里抽出（本次任务, 历史），保留多模态图片给执行 agent。"""
    def _text(c: Any) -> str:
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return "\n".join(str(b.get("text", "")) for b in c if isinstance(b, dict) and b.get("text"))
        return str(c or "")

    last_user = max((i for i, m in enumerate(req.messages) if m.role == "user"), default=-1)
    if last_user < 0:
        return "", []
    task = _text(req.messages[last_user].content).strip()
    history: list[dict[str, Any]] = []
    for m in req.messages[:last_user]:
        if m.role not in ("system", "user", "assistant"):
            continue
        content = m.content if isinstance(m.content, list) else _text(m.content)
        has_image = isinstance(content, list) and any(
            isinstance(part, dict) and part.get("type") == "image_url" for part in content
        )
        if _text(content).strip() or has_image:
            history.append({"role": m.role, "content": content})
    history = history[-12:]  # 只带最近 12 条，省 token

    # run_tool_agent 会另行把 task 追加成当前 user 文本；这里仅把当前消息的图片作为紧邻它的
    # image-only user 消息放进 history，既不重复文字，又让 staged_images/视觉模型拿到真图。
    current = req.messages[last_user].content
    if isinstance(current, list):
        current_images = [
            part for part in current
            if isinstance(part, dict) and part.get("type") == "image_url"
        ]
        # 大图 base64 直接进 agent history 会撑爆上下文/上游 → 限总量 ~4MB，超出丢弃(MiniMax/Opus 审)
        budget, kept = 4_000_000, []
        for part in current_images:
            iu = part.get("image_url")
            url = str((iu.get("url") if isinstance(iu, dict) else iu) or "")
            if budget - len(url) >= 0:
                budget -= len(url)
                kept.append(part)
        if kept:
            history.append({"role": "user", "content": kept})
    return task, history


def _fleet_event_line(ev: dict[str, Any]) -> str | None:
    """把编排事件压成流式聊天里的一行进度（None=不展示该事件）。"""
    t = ev.get("type")
    try:
        if t == "route":
            return f"⚙ 路由 → {ev.get('model')}（{'复杂' if ev.get('complex') else '简单'}任务）"
        if t in ("plan", "replan"):
            head = (ev.get("plan") or "").strip().splitlines()
            return f"⚙ {'重新规划' if t == 'replan' else '规划'}：{head[0][:80] if head else '…'}"
        if t == "cast":
            return f"⚙ 点将#{ev.get('turn')}：{ev.get('role')} → {ev.get('model')}"
        if t == "think":
            # 互审(GLM)：TRINITY think 事件字段是 text（曾误读 digest → 思考行恒空）。
            return f"💭 {str(ev.get('text') or ev.get('digest') or '')[:100]}"
        if t == "step":
            # 换行压平：工具输出多行（如 list_dir 的 [F]/[D] 清单）会撕裂进度行、残片漏进正文
            #（机主截图实锤 "[F] A" 怪码）。压成单行再截断。
            return f"  · {' '.join(str(ev.get('log') or '').split())[:110]}"
        if t == "dag":
            plan = ev.get("plan")
            if not isinstance(plan, dict):  # 互审(Kimi)：上游若给了非 dict，别在这抛
                return "⚙ 工作流 DAG 已生成"
            return f"⚙ 工作流 DAG：{len(plan.get('model_id') or [])} 步 → {'、'.join(plan.get('model_id') or [])}"
        if t == "node":
            st = "开跑" if ev.get("status") == "start" else "完成"
            return f"⚙ 节点#{ev.get('index')}（{ev.get('model')}）{st}"
        if t == "verify":
            return f"🔍 审核（{ev.get('reviewer')}）：{'通过' if ev.get('verified') else '未达标'}"
        if t == "escalate":
            return f"⬆ 升级：{ev.get('from')} → {ev.get('to')}"
        if t == "done":
            return None  # 收尾后直接跟正文，不再报一行
    except Exception:  # noqa: BLE001
        return None
    return None


async def _run_fleet(
    router: "Router", vid: str, task: str, history: list[dict[str, Any]],
    on_event=None,
) -> dict[str, Any]:
    """按虚拟模型号跑对应编排。

    标准 chat.completions 只允许 advisory；显式空能力集确保不会读写本机、运行命令或生成媒体。
    workdir 解放：消息点名真实路径就切过去，否则默认用户主目录（"整理我的下载文件夹"要能干）。
    记忆进编排：调编排前注入机主长期记忆，编排结束后台成长回写（全吞异常，失败不影响主流程）。
    """
    import os as _os

    s = get_settings()
    # Standard chat has no host-file capability.  Keep even its incidental
    # workdir metadata inside the dedicated agent workspace; never probe HOME
    # or arbitrary paths mentioned in untrusted chat text.
    workdir = str(workspace_root())
    uid = s.agent_user_id or "owner"
    # 长对话上下文压缩（无状态兜底；fleet 的累积滚动摘要已在 _fleet_chat_response 前置处理）。
    history = await compress_history(router, list(history or []))
    # 身份罩袍：对外是"一个模型"，工人不得漏自家型号名（Fugu 的单一模型号门面）。
    history = [{
        "role": "system",
        "content": "你是「纳川·智脑」多模型舰队的执行单元。对外一律以「纳川·智脑」身份回答，"
                   "不要自称任何其它模型/厂商名，也不要提及内部编排细节。",
    }] + list(history or [])
    # ④记忆进编排：把机主长期记忆作为一条 system 消息插到 history 头部（try/except 全吞）。
    try:
        _note, _ = memory_system_note(app.state.memory, uid, task)
        if _note:
            history = [{"role": "system", "content": _note}] + history
    except Exception:  # noqa: BLE001
        pass
    if VIRTUAL_FLEET.get(vid) == "conductor":
        res = await run_conductor_agent(
            router, task, workdir=workdir, max_steps=24,
            history=history or None, allow=set(), on_event=on_event,
            preload_context=False,  # 聊天面不预读工作区/知识库（纯文字任务省几千 token+几十秒）
        )
    else:
        res = await run_orchestrated_agent(
            router, task, workdir=workdir, max_steps=24,
            history=history or None, allow=set(), on_event=on_event,
            preload_context=False,
        )
    # ④编排结束成长回写（后台，吞异常）。
    try:
        _grow_memory(router, task, str((res or {}).get("reply") or ""))
    except Exception:  # noqa: BLE001
        pass
    return res


async def _fleet_chat_response(req: ChatCompletionRequest, api_key: str, conv_id: str = "") -> Any:
    """/v1/chat/completions 的虚拟模型分流：非流式=标准 chat.completion；流式=进度行+正文。"""
    router: Router = app.state.router
    usage: UsageLogger = app.state.usage
    task, history = _fleet_task_history(req)
    # 跨请求累积滚动摘要：长对话把老的折进摘要、近的原样留（真正无限长，不丢主线）。
    history = await conv_summary.rolling_compress(router, conv_id, history) or history
    if not task:
        raise HTTPException(
            status_code=422,
            detail="需要至少一条含文字的 user 消息（舰队聊天面暂不支持纯图片/纯音频输入）",
        )
    started = time.time()
    # 互审(Kimi)：秒级时间戳并发同秒会撞 id → 毫秒 + 随机尾。
    rid = f"chatcmpl-fleet-{int(started * 1000)}-{secrets.token_hex(3)}"

    def _final_receipt(result: dict[str, Any]) -> dict[str, Any]:
        route_meta = result.get("_route")
        if isinstance(route_meta, dict):
            nested = route_meta.get("final_route_receipt")
            if isinstance(nested, dict):
                return nested
            if route_meta.get("route_receipt_version") is not None:
                return route_meta
        direct = result.get("final_route_receipt")
        return direct if isinstance(direct, dict) else {}

    async def _log_fleet(
        u: dict[str, Any], stream: int, receipt: dict[str, Any], status: str = "ok"
    ) -> None:
        await _log_usage_best_effort(
            usage,
            api_key=api_key,
            virtual_model=req.model,
            provider=str(receipt.get("provider") or "fleet-unserved"),
            upstream_model=str(receipt.get("upstream_model") or ""),
            tier=str(receipt.get("tier") or "fleet"),
            prompt_tokens=int(u.get("prompt_tokens", 0) or 0),
            completion_tokens=int(u.get("completion_tokens", 0) or 0),
            total_tokens=int(u.get("total_tokens", 0) or 0),
            cached_tokens=int(u.get("cached_tokens", 0) or 0),
            cost_usd=0.0,
            stream=stream,
            status=status,
            latency_ms=int((time.time() - started) * 1000),
        )

    def _content(result: dict[str, Any]) -> str:
        text = result.get("reply") or ""
        for u in result.get("media") or []:  # 编排里生成的图，作为 markdown 贴进正文
            if u:  # 互审(Kimi)：防御非 str 元素
                text += f"\n\n![生成图片]({str(u)})"
        return text

    if req.stream:
        cid = rid

        def _chunk(delta: dict[str, Any], finish: str | None = None) -> dict[str, Any]:
            return {"id": cid, "object": "chat.completion.chunk", "created": int(started),
                    "model": req.model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}

        async def _gen():
            queue: asyncio.Queue = asyncio.Queue()

            async def on_event(ev):
                await queue.put(ev)

            async def runner():
                try:
                    res = await _run_fleet(router, req.model, task, history, on_event=on_event)
                    await queue.put({"type": "_result", "result": res})
                except Exception as e:  # noqa: BLE001
                    await queue.put({"type": "_fail", "message": str(e)})
                finally:
                    await queue.put(None)

            t = asyncio.create_task(runner())
            yield _chunk({"role": "assistant"})
            result: dict[str, Any] = {}
            failed = False
            try:
                while True:
                    ev = await queue.get()
                    if ev is None:
                        break
                    if ev.get("type") == "_result":
                        result = ev.get("result") or {}
                        continue
                    if ev.get("type") == "_fail":
                        failed = True
                        yield _chunk(
                            {"content": "\n（舰队编排失败，请到诊断中心查看详情）"}
                        )
                        continue
                    line = _fleet_event_line(ev)
                    if line:
                        yield _chunk({"content": line + "\n"})
            finally:
                # 互审(Kimi)：只 cancel 不等，深层若吞 CancelledError 会留孤儿继续烧配额 → 有界等待。
                if not t.done():
                    t.cancel()
                    try:
                        await asyncio.wait_for(t, timeout=5.0)
                    except Exception:  # noqa: BLE001 含 CancelledError/超时，尽力而为
                        pass
            if result:
                yield _chunk({"content": "\n" + _content(result)})
                await _log_fleet(
                    result.get("usage") or {}, 1, _final_receipt(result)
                )
                # #6 生视频异步任务→随流末尾发结构化字段，前端据此轮询到成片自动贴回对话。
                _pv = result.get("pending_videos") or []
                if _pv:
                    ch = _chunk({})
                    ch["_pending_videos"] = _pv
                    yield ch
            elif failed:
                await _log_fleet(
                    {}, 1, {}, status="error"
                )  # 互审(MiniMax)：流式失败也记账
            yield _chunk({}, finish="stop")

        return StreamingResponse(sse_encode(_gen()), media_type="text/event-stream")

    try:
        result = await _run_fleet(router, req.model, task, history)
    except Exception:  # noqa: BLE001 互审(GLM)：非流式编排炸了别裸 500，记账+友好 502
        await _log_fleet({}, 0, {}, status="error")
        raise HTTPException(
            status_code=502,
            detail="舰队编排失败，请到诊断中心查看详情",
            headers={"Cache-Control": "no-store"},
        )
    u = result.get("usage") or {}
    final_receipt = _final_receipt(result)
    final_model = final_receipt.get("actual_model")
    await _log_fleet(u, 0, final_receipt)
    return JSONResponse({
        "id": rid,
        "object": "chat.completion",
        "created": int(started),
        "model": req.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": _content(result)},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": int(u.get("prompt_tokens", 0) or 0),
                  "completion_tokens": int(u.get("completion_tokens", 0) or 0),
                  "total_tokens": int(u.get("total_tokens", 0) or 0)},
        "_fleet": {"mode": result.get("mode") or ("conductor" if VIRTUAL_FLEET.get(req.model) == "conductor" else "auto"),
                   "verified": result.get("verified"), "rounds": result.get("rounds"),
                   "final_model": final_model},
        "_pending_videos": result.get("pending_videos") or [],  # #6：前端轮询到成片自动贴回
    })

def _public_provider_http_error(exc: ProviderError) -> HTTPException:
    """Map adapter failures to bounded public text without echoing secrets."""

    try:
        status_code = int(exc.status_code)
    except (TypeError, ValueError, OverflowError):
        status_code = 502
    if not 400 <= status_code <= 599:
        status_code = 502
    return HTTPException(
        status_code=status_code,
        detail=friendly_status(status_code),
        headers={"Cache-Control": "no-store"},
    )


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, api_key: str = Depends(require_api_key)):
    router: Router = app.state.router
    usage: UsageLogger = app.state.usage

    body = await request.json()
    try:
        req = ChatCompletionRequest(**body)
    except (ValidationError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_chat_request", "retryable": False},
            headers={"Cache-Control": "no-store"},
        ) from exc

    # F5 虚拟模型号：选中舰队 → 整套编排当作"一个模型"应答（缓存/记忆注入等直连逻辑不适用）。
    if req.model in VIRTUAL_FLEET:
        return await _fleet_chat_response(req, api_key, str(body.get("conversation_id") or ""))

    _is_short_followup = _inject_followup_context(req.messages)

    # 本轮用户消息（记忆检索 + 成长都用它）
    _user_msg = next(
        (m.content for m in reversed(req.messages) if m.role == "user" and isinstance(m.content, str)),
        "",
    )
    # A·记忆做成底层通用：注入机主长期记忆（只读检索；写入由 _grow_memory 后台负责）
    # ②缓存友好：放在「最后一条用户消息之前」作为独立 system 消息，不动 messages[0]。
    # 原生 prompt 缓存是「前缀匹配」——每轮都改第一条会让整段历史缓存全失效；
    # 把易变的记忆挪到末尾，稳定的系统提示+历史才能被各家自动缓存命中。
    try:
        _note, _ = memory_system_note(app.state.memory, get_settings().agent_user_id or "owner", _user_msg)
        if _note:
            _mem_msg = ChatMessage(role="system", content=_note)
            _last_user = max(
                (i for i, m in enumerate(req.messages) if m.role == "user"), default=-1
            )
            if _last_user >= 0:
                req.messages.insert(_last_user, _mem_msg)
            else:
                req.messages.append(_mem_msg)
    except Exception:  # noqa: BLE001
        pass

    # 联网搜索增强：请求带 web_search=true 时，搜最后一条用户消息、把结果作为 system 资料插到最前。
    # 任何模型可用，本地小模型尤其需要（据实回答时事/事实题）。失败安全跳过。
    if not _is_short_followup:
        try:
            await websearch.maybe_augment_request(req)
        except Exception:  # noqa: BLE001
            pass

    started = time.time()

    async def _log(
        *,
        model: str,
        route: Any,
        u: dict[str, Any],
        stream: int,
        status: str,
        receipt: dict[str, Any] | None = None,
    ) -> None:
        # 原生 prompt 缓存命中的 token：OpenAI/DeepSeek/火山 在 prompt_tokens_details.cached_tokens；
        # Claude 经 _usage_from_claude 暴露为 cached_tokens。两者都抓，便于「用量」页量化省了多少。
        _pd = u.get("prompt_tokens_details") or {}
        cached = int(u.get("cached_tokens", 0) or _pd.get("cached_tokens", 0) or 0)
        if receipt is None:
            provider = route.provider.name if route else "?"
            upstream_model = route.upstream_model if route else model
            tier = route.tier if route else "?"
        else:
            # These scalar fields were frozen when the stream committed.  For
            # an unserved request, keep them empty instead of guessing from a
            # router that may have hot-reloaded since the invocation began.
            provider = str(receipt.get("provider") or "direct-unserved")
            upstream_model = str(receipt.get("upstream_model") or "")
            tier = str(receipt.get("tier") or "unserved")
        await _log_usage_best_effort(
            usage,
            api_key=api_key,
            virtual_model=model,
            provider=provider,
            upstream_model=upstream_model,
            tier=tier,
            prompt_tokens=int(u.get("prompt_tokens", 0) or 0),
            completion_tokens=int(u.get("completion_tokens", 0) or 0),
            total_tokens=int(u.get("total_tokens", 0) or 0),
            cached_tokens=cached,
            cost_usd=float(u.get("cost_usd", 0) or 0),
            stream=stream,
            status=status,
            latency_ms=int((time.time() - started) * 1000),
        )

    # ── 流式（带失败转移）──
    if req.stream:
        captured: dict[str, Any] = {
            "usage": {},
            "receipt": {
                "route_receipt_version": 1,
                "requested": req.model,
                "actual": "",
                "provider": "direct-unserved",
                "upstream_model": "",
                "tier": "unserved",
            },
            "receipt_frozen": False,
        }
        trace_id = str(getattr(request.state, "trace_id", "") or "")

        async def gen():
            acc: list[str] = []
            terminal_status = "error"
            saw_chunk = False
            try:
                async for raw_chunk in stream_with_fallback(router, req):
                    chunk = dict(raw_chunk) if isinstance(raw_chunk, dict) else {
                        "error": {"message": "上游返回了非法流式数据", "type": "provider_error"}
                    }
                    if chunk.get("usage"):
                        captured["usage"] = chunk["usage"]
                    served_receipt = chunk.get("_served_by")
                    if (
                        not captured["receipt_frozen"]
                        and isinstance(served_receipt, dict)
                        and served_receipt.get("route_receipt_version") == 1
                    ):
                        # Freeze only scalar accounting fields from the trusted
                        # failover layer.  Later provider chunks cannot rewrite it.
                        captured["receipt"] = {
                            "route_receipt_version": 1,
                            "requested": str(served_receipt.get("requested") or req.model),
                            "actual": str(served_receipt.get("actual") or ""),
                            "provider": str(served_receipt.get("provider") or ""),
                            "upstream_model": str(
                                served_receipt.get("upstream_model") or ""
                            ),
                            "tier": str(served_receipt.get("tier") or ""),
                        }
                        captured["receipt_frozen"] = True
                    if isinstance(chunk.get("error"), dict):
                        error = dict(chunk["error"])
                        error["trace_id"] = trace_id
                        chunk["error"] = error
                        terminal_status = "error"
                        yield chunk
                        return
                    saw_chunk = True
                    try:
                        _d = (chunk.get("choices") or [{}])[0].get("delta", {}).get("content")
                        if _d:
                            acc.append(_d)
                    except Exception:  # noqa: BLE001
                        pass
                    yield chunk
                if not saw_chunk:
                    yield {
                        "error": {
                            "message": "上游未返回任何流式数据",
                            "type": "empty_stream",
                            "status_code": 502,
                            "trace_id": trace_id,
                        }
                    }
                    terminal_status = "error"
                else:
                    terminal_status = "ok"
            except asyncio.CancelledError:
                terminal_status = "cancelled"
                raise
            except Exception:  # noqa: BLE001 -- headers are already sent; terminate via SSE
                terminal_status = "error"
                yield {
                    "error": {
                        "message": "流式响应异常，请凭 trace_id 排查",
                        "type": "stream_error",
                        "status_code": 502,
                        "trace_id": trace_id,
                    }
                }
            finally:
                final_receipt = captured["receipt"]
                await _log(
                    model=str(
                        final_receipt.get("actual")
                        or final_receipt.get("requested")
                        or req.model
                    ),
                    route=None,
                    u=captured["usage"],
                    stream=1,
                    status=terminal_status,
                    receipt=final_receipt,
                )
                if terminal_status == "ok" and acc:
                    _grow_memory(router, _user_msg, "".join(acc))

        return StreamingResponse(sse_encode(gen()), media_type="text/event-stream")

    # ── 非流式（带失败转移）──
    # 语义缓存（GPTCache，本地）：相近问题命中即直接返回上次答案，省一次大模型调用。
    # 安全降级：未开启/不可用/异常一律跳过，照常走下面的正常调用。只缓存“纯问答”，
    # 带工具/带 response_format 的请求不缓存（避免误命中改变行为）。
    _cacheable = bool(_user_msg) and not getattr(req, "tools", None) and not req.stream
    if _cacheable:
        try:
            hit = await run_in_threadpool(semcache.lookup, req.model, _user_msg)
        except Exception:  # noqa: BLE001
            hit = None
        if hit:
            await _log(
                model=req.model,
                route=router.resolve(req.model),
                u={},
                stream=0,
                status="cache_hit",
            )
            return JSONResponse(
                {
                    "id": "chatcmpl-cache",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": req.model,
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": hit},
                         "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                    "_cached": True,
                }
            )

    try:
        result, served, route = await chat_with_fallback(router, req)
    except ProviderError as e:
        await _log(
            model=req.model,
            route=router.resolve(req.model),
            u={},
            stream=0,
            status=f"error:{e.status_code}",
        )
        raise _public_provider_http_error(e) from e

    await _log(
        model=served,
        route=route,
        u=result.get("usage") or {},
        stream=0,
        status="ok",
    )
    _reply_text = (result.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    if _cacheable and _reply_text:  # 存入语义缓存（后台线程，不拖慢响应）；安全降级
        try:
            await run_in_threadpool(semcache.store, req.model, _user_msg, _reply_text)
        except Exception:  # noqa: BLE001
            pass
    _grow_memory(router, _user_msg, _reply_text)
    return JSONResponse(result)


_CHANNEL_RESULT_VERSION = 2
_CHANNEL_ATTRIBUTION_PROVIDER = "provider_attested"
_CHANNEL_ATTRIBUTION_LOCAL = "local_engine"
_CHANNEL_LOCAL_MODEL = "nachuan-engine"

_WEIXIN_IDEMPOTENT_RESPONSE_FIELDS = frozenset(
    {
        "reply",
        "model",
        "channel_result_version",
        "attribution_state",
        "turns",
        "usage",
        "agent_route",
        "orchestration_mode",
        "reviewed",
        "verified",
        "machine_verified",
        "outcome",
        "blocked",
        "images",
        "video",
        "video_task",
        "job_id",
        "task_id",
        "trace_id",
        "recovery_id",
        "notice_trace_id",
    }
)
_DURABLE_TURN_DEADLINE_SECONDS = 55.0
_DURABLE_TASK_STOP_GRACE_SECONDS = 2.0
_DURABLE_HEARTBEAT_MIN_INTERVAL_SECONDS = 3.0

_PUBLIC_AGENT_ROUTE_FIELDS = frozenset(
    {
        "label",
        "store",
        "reused_case_id",
        "pending_card_id",
        "stored_case_id",
        "store_blocked_reason",
    }
)
_PUBLIC_AGENT_ORCHESTRATION_FIELDS = frozenset(
    {
        "mode",
        "rounds",
        "escalated",
        "timed_out",
        "reviewed",
        "verified",
        "machine_verified",
        "outcome",
        "review_reason",
        "review_unavailable_reason",
    }
)


class _DurableTurnLeaseLost(HTTPException):
    """Fail closed when a durable Turn can no longer prove lease ownership."""

    def __init__(self, *, reason: str, storage_unavailable: bool = False) -> None:
        super().__init__(
            status_code=503 if storage_unavailable else 409,
            detail={
                "code": "durable_turn_lease_lost",
                "reason": reason,
                "retryable": True,
            },
            headers={"Retry-After": "2", "Cache-Control": "no-store"},
        )


def _weixin_idempotent_response(result: dict[str, Any]) -> dict[str, Any]:
    """Keep only bridge business output; omit user/session/memory source text."""

    return {
        key: value
        for key, value in result.items()
        if key in _WEIXIN_IDEMPOTENT_RESPONSE_FIELDS
    }


def _sanitize_agent_chat_route(value: object) -> dict[str, Any] | None:
    """Project channel routing state without provider identities or HMAC sidecars."""

    if not isinstance(value, dict):
        return None
    public = {
        key: item
        for key, item in value.items()
        if key in _PUBLIC_AGENT_ROUTE_FIELDS
        and isinstance(item, (str, int, bool))
        and not isinstance(item, float)
    }
    orchestration = value.get("orchestration")
    if isinstance(orchestration, dict):
        projected = {
            key: item
            for key, item in orchestration.items()
            if key in _PUBLIC_AGENT_ORCHESTRATION_FIELDS
            and (item is None or isinstance(item, (str, int, bool)))
            and not isinstance(item, float)
        }
        if projected:
            public["orchestration"] = projected
    return public or None


def _sanitize_agent_chat_result(result: dict[str, Any]) -> dict[str, Any]:
    """Remove process-local authorship material before persistence or return."""

    public = dict(result)
    route = _sanitize_agent_chat_route(public.get("agent_route"))
    if route is None:
        public.pop("agent_route", None)
    else:
        public["agent_route"] = route
    public.pop("final_route_receipt", None)
    public.pop("_route", None)
    return public


def _project_durable_channel_replay(value: object) -> dict[str, Any]:
    """Replay only gateway-minted v2 attribution; downgrade every legacy claim."""

    result = value if isinstance(value, dict) else {}
    public = _weixin_idempotent_response(_sanitize_agent_chat_result(result))
    version = result.get("channel_result_version")
    attribution = result.get("attribution_state")
    model = result.get("model")
    is_consistent_v2 = type(version) is int and version == _CHANNEL_RESULT_VERSION
    if attribution == _CHANNEL_ATTRIBUTION_PROVIDER:
        is_consistent_v2 = (
            is_consistent_v2
            and isinstance(model, str)
            and bool(model.strip())
            and model != _CHANNEL_LOCAL_MODEL
        )
    elif attribution == _CHANNEL_ATTRIBUTION_LOCAL:
        is_consistent_v2 = is_consistent_v2 and model == _CHANNEL_LOCAL_MODEL
    else:
        is_consistent_v2 = False
    if not is_consistent_v2:
        # Legacy rows predate the closed Agent result contract. A top-level
        # allowlist is insufficient because arbitrary receipt/HMAC material may
        # be nested inside usage, media arrays or trace fields. Preserve only
        # scalar business state and discard every legacy nested container.
        legacy_public: dict[str, Any] = {
            "reply": (
                public.get("reply")
                if isinstance(public.get("reply"), str)
                else "历史回复无法安全读取，请重新发送本轮消息。"
            ),
            "model": _CHANNEL_LOCAL_MODEL,
            "usage": {},
        }
        turns = public.get("turns")
        if type(turns) is int and 0 <= turns <= 1_000_000:
            legacy_public["turns"] = turns
        for field in ("orchestration_mode", "outcome"):
            item = public.get(field)
            if isinstance(item, str) and len(item.encode("utf-8")) <= 128:
                legacy_public[field] = item
        for field in ("reviewed", "verified", "machine_verified", "blocked"):
            item = public.get(field)
            if type(item) is bool:
                legacy_public[field] = item
        public = legacy_public
        attribution = _CHANNEL_ATTRIBUTION_LOCAL
    public["channel_result_version"] = _CHANNEL_RESULT_VERSION
    public["attribution_state"] = attribution
    return public


def _mint_durable_channel_response(result: dict[str, Any]) -> dict[str, Any]:
    """Mint v2 metadata only after the Agent contract and public sanitizer pass."""

    public = _weixin_idempotent_response(result)
    model = result.get("model")
    if model == _CHANNEL_LOCAL_MODEL:
        attribution = _CHANNEL_ATTRIBUTION_LOCAL
    elif (
        isinstance(model, str)
        and bool(model.strip())
        and result.get("actual_model") == model
    ):
        attribution = _CHANNEL_ATTRIBUTION_PROVIDER
    else:
        public["model"] = _CHANNEL_LOCAL_MODEL
        attribution = _CHANNEL_ATTRIBUTION_LOCAL
    public["channel_result_version"] = _CHANNEL_RESULT_VERSION
    public["attribution_state"] = attribution
    return public


def _durable_heartbeat_interval(store: WeixinIdempotencyStore) -> float:
    """Renew early enough to leave a bounded SQLite wait plus expiry margin."""

    return max(
        _DURABLE_HEARTBEAT_MIN_INTERVAL_SECONDS,
        float(store.lease_seconds) / 4.0,
    )


def _durable_renew_timeout(store: WeixinIdempotencyStore) -> float:
    lease_seconds = max(0.001, float(store.lease_seconds))
    sqlite_wait = max(0.0, float(getattr(store, "busy_timeout_ms", 0))) / 1000.0
    return max(0.05, min(lease_seconds / 4.0, sqlite_wait + 0.25))


async def _renew_weixin_idempotency_lease(
    store: WeixinIdempotencyStore,
    principal_hash: str,
    message_key: str,
    request_sha256: str,
    fencing_token: str,
    stop: asyncio.Event,
) -> None:
    """Keep a live request fenced; a crashed process naturally stops renewing."""

    interval = _durable_heartbeat_interval(store)
    while True:
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except TimeoutError:
            pass
        try:
            renewed = await asyncio.wait_for(
                run_in_threadpool(
                    store.renew,
                    principal_hash,
                    message_key,
                    request_sha256,
                    fencing_token,
                ),
                timeout=_durable_renew_timeout(store),
            )
        except TimeoutError as exc:
            # The underlying worker thread may finish later, but the business
            # task is cancelled immediately and every commit remains fenced.
            raise _DurableTurnLeaseLost(
                reason="heartbeat_unavailable", storage_unavailable=True
            ) from exc
        except WeixinIdempotencyUnavailable as exc:
            raise _DurableTurnLeaseLost(
                reason="heartbeat_unavailable", storage_unavailable=True
            ) from exc
        if not renewed:
            raise _DurableTurnLeaseLost(reason="heartbeat_fenced")


def _propagate_heartbeat_result(task: asyncio.Task[Any], *, clean_stop: bool) -> None:
    """Consume a heartbeat result without ever treating an error as success."""

    try:
        task.result()
    except _DurableTurnLeaseLost:
        raise
    except WeixinIdempotencyUnavailable as exc:
        raise _DurableTurnLeaseLost(
            reason="heartbeat_unavailable", storage_unavailable=True
        ) from exc
    except asyncio.CancelledError as exc:
        raise _DurableTurnLeaseLost(reason="heartbeat_cancelled") from exc
    except BaseException as exc:
        raise _DurableTurnLeaseLost(
            reason="heartbeat_error", storage_unavailable=True
        ) from exc
    if not clean_stop:
        raise _DurableTurnLeaseLost(reason="heartbeat_stopped")


def _consume_stopped_task(task: asyncio.Task[Any]) -> None:
    """Retrieve a detached cancelled task's result to avoid warning leakage."""

    try:
        task.result()
    except BaseException:
        # This callback is only attached after the request has already failed
        # closed and the task refused its bounded cancellation grace period.
        pass


async def _stop_durable_heartbeat(
    stop: asyncio.Event, task: asyncio.Task[Any]
) -> None:
    stop.set()
    done, _pending = await asyncio.wait(
        {task}, timeout=_DURABLE_TASK_STOP_GRACE_SECONDS
    )
    if task not in done:
        task.cancel()
        task.add_done_callback(_consume_stopped_task)
        raise _DurableTurnLeaseLost(
            reason="heartbeat_stop_timeout", storage_unavailable=True
        )
    _propagate_heartbeat_result(task, clean_stop=True)


async def _cancel_agent_task(task: asyncio.Task[Any]) -> None:
    if not task.done():
        task.cancel()
    done, _pending = await asyncio.wait(
        {task}, timeout=_DURABLE_TASK_STOP_GRACE_SECONDS
    )
    if task not in done:
        # Python cannot forcibly terminate an uncooperative coroutine. Keep the
        # HTTP path bounded and consume its eventual terminal result; the Turn
        # cannot commit without the fencing token. Report lease-lost rather than
        # releasing the claim for an overlapping retry while work is still live.
        task.add_done_callback(_consume_stopped_task)
        raise _DurableTurnLeaseLost(reason="agent_cancel_timeout")
    try:
        task.result()
    except BaseException:
        # The caller is already propagating the original provider/deadline/
        # lease exception. This consumes only the cancelled business task.
        pass


async def _renew_durable_turn_or_raise(
    store: WeixinIdempotencyStore,
    principal_hash: str,
    message_key: str,
    request_sha256: str,
    fencing_token: str,
) -> None:
    try:
        renewed = await run_in_threadpool(
            store.renew,
            principal_hash,
            message_key,
            request_sha256,
            fencing_token,
        )
    except WeixinIdempotencyUnavailable as exc:
        raise _DurableTurnLeaseLost(
            reason="lease_check_unavailable", storage_unavailable=True
        ) from exc
    if not renewed:
        raise _DurableTurnLeaseLost(reason="claim_fenced")


async def _await_durable_agent_call(
    agent_call: Any,
    heartbeat_task: asyncio.Task[Any],
    *,
    timeout_seconds: float,
) -> Any:
    """Race business work against both its hard deadline and lease heartbeat."""

    agent_task = asyncio.create_task(agent_call)
    try:
        done, _pending = await asyncio.wait(
            {agent_task, heartbeat_task},
            timeout=max(0.001, float(timeout_seconds)),
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Lease loss wins even if the provider result arrived in the same loop
        # turn; accepting the result would let two fencing owners commit.
        if heartbeat_task in done:
            _propagate_heartbeat_result(heartbeat_task, clean_stop=False)
        if agent_task in done:
            return agent_task.result()
        raise TimeoutError("durable Turn deadline exceeded")
    except BaseException:
        await _cancel_agent_task(agent_task)
        raise


def _select_agent_chat_model(router: Router, requested: object) -> str:
    """Resolve one concrete, verified, side-effect-free chat route.

    Channel adapters may supply an operator-selected model, but an omitted
    model is deliberately dynamic: it follows the live verified route table
    instead of a stale process default.  ``echo`` is a diagnostics provider,
    not a customer answer route, and execution backends are never eligible for
    an ordinary message-channel Turn.
    """

    explicit = str(requested or "").strip()

    def usable(model_id: str, route: object | None, row: Mapping[str, Any] | None = None) -> bool:
        if not model_id or model_id == "echo" or route is None:
            return False
        modality = str(
            getattr(route, "modality", "")
            or ((row or {}).get("modality") or "")
        ).strip().lower()
        if modality != "chat":
            return False
        if str(getattr(route, "exec_backend", "") or "").strip():
            return False
        return True

    if explicit:
        explicit_route = router.resolve(explicit)
        if usable(explicit, explicit_route):
            return explicit
        raise HTTPException(
            status_code=503,
            detail={"code": "requested_model_unavailable", "retryable": False},
            headers={"Cache-Control": "no-store"},
        )

    candidates: list[tuple[tuple[int, int, int], str]] = []
    try:
        rows = router.routes_info()
    except Exception as exc:  # noqa: BLE001 - readiness must fail closed
        raise HTTPException(
            status_code=503,
            detail={"code": "ready_no_model", "retryable": False},
            headers={"Cache-Control": "no-store"},
        ) from exc
    tier_order = {"cheap": 0, "free": 0, "default": 1, "premium": 2}
    for raw in rows:
        if not isinstance(raw, Mapping):
            continue
        model_id = str(raw.get("model") or "").strip()
        route = router.resolve(model_id) if model_id else None
        if not usable(model_id, route, raw):
            continue
        try:
            rank = int(raw.get("rank") or 0)
        except (TypeError, ValueError):
            rank = 0
        candidates.append(
            (
                (
                    tier_order.get(str(raw.get("tier") or "default").lower(), 1),
                    1 if bool(raw.get("flagship")) else 0,
                    rank if rank > 0 else 2**31 - 1,
                ),
                model_id,
            )
        )
    if not candidates:
        raise HTTPException(
            status_code=503,
            detail={"code": "ready_no_model", "retryable": False},
            headers={"Cache-Control": "no-store"},
        )
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][1]


_AGENT_CHAT_REQUEST_FIELDS = frozenset(
    {
        "message",
        "chat_id",
        "user_id",
        "channel",
        "model",
        "system",
        "video_async",
        "video_async_capacity_available",
        "idempotency_key",
    }
)
_AGENT_CHAT_CHANNELS = frozenset({"api", "desktop", "weixin", "feishu"})
_AGENT_CHAT_MESSAGE_MAX_BYTES = 2 * 1024 * 1024
_AGENT_CHAT_ID_MAX_BYTES = 512
_AGENT_CHAT_MODEL_MAX_BYTES = 512
_AGENT_CHAT_SYSTEM_MAX_BYTES = 32 * 1024


def _validate_agent_chat_text(
    value: Any,
    *,
    field: str,
    max_bytes: int,
    reject_controls: bool = False,
) -> str:
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail=f"{field} 必须是字符串")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"{field} 必须是有效 UTF-8 文本",
        ) from exc
    if len(encoded) > max_bytes:
        raise HTTPException(status_code=422, detail=f"{field} 过长")
    if reject_controls and any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in value
    ):
        raise HTTPException(status_code=422, detail=f"{field} 不得包含控制字符")
    return value


@app.post("/v1/agent/chat")
async def agent_chat_endpoint(
    request: Request,
    background: BackgroundTasks,
    api_key: str = Depends(require_bridge_or_api_key),
):
    """超级智能体对话；外部消息桥使用持久、带 fencing 的请求幂等。"""

    router: Router = app.state.router
    usage: UsageLogger = app.state.usage
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    if set(body) - _AGENT_CHAT_REQUEST_FIELDS:
        raise HTTPException(
            status_code=422,
            detail="agent chat 请求包含未知字段",
        )
    raw_channel = body.get("channel", "api")
    if not isinstance(raw_channel, str) or raw_channel not in _AGENT_CHAT_CHANNELS:
        raise HTTPException(
            status_code=422,
            detail="channel 必须是 api/desktop/weixin/feishu 之一",
        )
    requested_channel = raw_channel
    if api_key.startswith("bridge:") and api_key != f"bridge:{requested_channel}":
        raise HTTPException(status_code=403, detail="bridge credential channel mismatch")
    raw_message = body.get("message")
    if not isinstance(raw_message, str):
        raise HTTPException(status_code=422, detail="message 必须是字符串")
    message = raw_message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="需要 message")
    try:
        message_bytes = len(message.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise HTTPException(status_code=422, detail="message 必须是有效 UTF-8 文本") from exc
    if message_bytes > _AGENT_CHAT_MESSAGE_MAX_BYTES:
        raise HTTPException(status_code=422, detail="message 超过 2MiB")
    raw_chat_id = body.get("chat_id", "")
    chat_id_value = _validate_agent_chat_text(
        raw_chat_id,
        field="chat_id",
        max_bytes=_AGENT_CHAT_ID_MAX_BYTES,
        reject_controls=True,
    )
    raw_user_id = body.get("user_id", "")
    user_id = _validate_agent_chat_text(
        raw_user_id,
        field="user_id",
        max_bytes=_AGENT_CHAT_ID_MAX_BYTES,
        reject_controls=True,
    )
    chat_id = chat_id_value or user_id or "default"
    # Use the same canonical value for authorization, durable Turn routing and
    # identity partitioning.  Re-reading the raw mixed-case value here would
    # let a scoped bridge pass auth as "weixin" but bypass the durable path as
    # "WeIxIn".
    channel = requested_channel
    requested_model = (
        _validate_agent_chat_text(
            body["model"],
            field="model",
            max_bytes=_AGENT_CHAT_MODEL_MAX_BYTES,
        )
        if "model" in body
        else None
    )
    system = (
        _validate_agent_chat_text(
            body["system"],
            field="system",
            max_bytes=_AGENT_CHAT_SYSTEM_MAX_BYTES,
        )
        if "system" in body
        else None
    )
    raw_video_async = body.get("video_async", False)
    if type(raw_video_async) is not bool:
        raise HTTPException(status_code=422, detail="video_async 必须是布尔值")
    video_async = raw_video_async
    raw_video_capacity = body.get("video_async_capacity_available", True)
    if type(raw_video_capacity) is not bool:
        raise HTTPException(
            status_code=422,
            detail="video_async_capacity_available 必须是布尔值",
        )
    video_async_capacity_available = raw_video_capacity

    raw_idempotency_key = body.get("idempotency_key")
    idempotency_key = ""
    principal_hash = ""
    request_sha256 = ""
    turn_identity = ""
    fencing_token = ""
    store: WeixinIdempotencyStore | None = None
    heartbeat_stop: asyncio.Event | None = None
    heartbeat_task: asyncio.Task[Any] | None = None
    persisted_success = False
    turn_reservation_state = ""
    turn_provider_phase_entered = False
    turn_receipt_committed = False
    agent_conversations: ConversationStore | BufferedConversationStore = (
        app.state.conversations
    )

    if channel in {"weixin", "feishu"}:
        try:
            idempotency_key = validate_channel_idempotency_key(
                raw_idempotency_key, channel=channel
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"{channel} idempotency_key 格式无效",
            ) from exc
    elif "idempotency_key" in body:
        raise HTTPException(
            status_code=422,
            detail="idempotency_key 仅允许用于持久消息渠道",
        )

    durable_turn_deadline = (
        time.monotonic() + max(0.0, float(_DURABLE_TURN_DEADLINE_SECONDS))
        if channel in {"weixin", "feishu"}
        else None
    )

    # Validate the durable bridge envelope before consulting mutable model
    # readiness.  Otherwise an invalid/replayed channel request could be
    # misreported as a transient model outage.
    model = _select_agent_chat_model(router, requested_model)

    if channel in {"weixin", "feishu"}:
        try:
            # Authentication still uses the live runtime key, but durable Turn
            # identity uses the canonical channel/user/chat namespace.  A safe
            # supervisor key rotation therefore cannot bypass replay suppression.
            principal_hash = hash_channel_principal(
                channel=channel,
                user_id=user_id,
                chat_id=chat_id,
            )
            turn_identity = hash_turn_identity(principal_hash, idempotency_key)
            request_sha256 = hash_weixin_request(
                channel=channel,
                chat_id=chat_id,
                user_id=user_id,
                message=message,
                model=model,
                system=system,
                video_async=video_async,
            )
            # ``video_async_capacity_available`` is a transient bridge permit,
            # deliberately excluded from durable Turn identity.  The first
            # accepted claim freezes either the fast capacity refusal or the
            # task result; a false->true retry must replay, not semantic-conflict
            # or create a second provider job.
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"{channel} idempotency_key 格式无效",
            ) from exc
        store = app.state.weixin_idempotency
        try:
            claim = await run_in_threadpool(
                store.claim, principal_hash, idempotency_key, request_sha256
            )
        except WeixinIdempotencyUnavailable as exc:
            raise HTTPException(
                status_code=503,
                detail={"code": "idempotency_unavailable", "retryable": True},
                headers={"Retry-After": "2", "Cache-Control": "no-store"},
            ) from exc
        if claim.state == "conflict":
            raise HTTPException(
                status_code=409,
                detail={"code": "idempotency_semantic_conflict", "retryable": False},
                headers={"Cache-Control": "no-store"},
            )
        if claim.state == "processing":
            raise HTTPException(
                status_code=425,
                detail={"code": "idempotency_in_progress", "retryable": True},
                headers={
                    "Retry-After": str(max(1, min(claim.retry_after_seconds, 90))),
                    "Cache-Control": "no-store",
                },
            )
        if claim.state == "succeeded":
            return JSONResponse(
                _project_durable_channel_replay(claim.response),
                headers={
                    "Idempotency-Replayed": "true",
                    "Cache-Control": "no-store",
                },
            )
        claim_requires_recovery = claim.state == "recovery_required"
        fencing_token = claim.fencing_token
        try:
            recovered_turn = await run_in_threadpool(
                app.state.conversations.idempotent_result,
                turn_identity,
                request_sha256,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail={"code": "turn_semantic_conflict", "retryable": False},
                headers={"Cache-Control": "no-store"},
            ) from exc
        if recovered_turn is not None:
            recovered_turn = _project_durable_channel_replay(recovered_turn)
            try:
                recovered_persisted = await run_in_threadpool(
                    store.succeed,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    recovered_turn,
                )
            except (ValueError, WeixinIdempotencyUnavailable) as exc:
                raise HTTPException(
                    status_code=503,
                    detail={"code": "idempotency_recovery_failed", "retryable": True},
                    headers={"Retry-After": "2", "Cache-Control": "no-store"},
                ) from exc
            if not recovered_persisted:
                raise HTTPException(
                    status_code=409,
                    detail={"code": "idempotency_claim_fenced", "retryable": True},
                    headers={"Retry-After": "2", "Cache-Control": "no-store"},
                )
            return JSONResponse(
                recovered_turn,
                headers={
                    "Idempotency-Replayed": "true",
                    "Cache-Control": "no-store",
                },
            )
        provider_ledger = app.state.provider_call_ledger
        recovery_required = claim_requires_recovery
        if not recovery_required and bool(getattr(provider_ledger, "required", False)):
            try:
                recovery_required = await run_in_threadpool(
                    provider_ledger.turn_requires_operator_recovery,
                    turn_identity,
                    f"{channel}:agent_chat",
                )
            except ProviderCallLedgerUnavailable as exc:
                try:
                    released = await run_in_threadpool(
                        store.fail,
                        principal_hash,
                        idempotency_key,
                        request_sha256,
                        fencing_token,
                        error_code="provider_ledger_preflight_unavailable",
                    )
                except WeixinIdempotencyUnavailable as release_exc:
                    raise _DurableTurnLeaseLost(
                        reason="provider_ledger_preflight_unavailable",
                        storage_unavailable=True,
                    ) from release_exc
                if not released:
                    raise _DurableTurnLeaseLost(
                        reason="provider_ledger_preflight_fenced"
                    ) from exc
                raise HTTPException(
                    status_code=503,
                    detail={
                        "code": "provider_ledger_preflight_unavailable",
                        "retryable": True,
                    },
                    headers={"Retry-After": "2", "Cache-Control": "no-store"},
                ) from exc

        # Reserve the worst-case durable response bytes before any path can
        # enter a provider.  The replay ledger and the conversation receipt
        # live in separate SQLite files, so the reservation is also the
        # durable bridge between their two fencing state machines.
        try:
            turn_reservation_state = await run_in_threadpool(
                app.state.conversations.reserve_turn_receipt,
                turn_key=turn_identity,
                request_sha256=request_sha256,
            )
        except ValueError as exc:
            try:
                released = await run_in_threadpool(
                    store.fail,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    error_code="turn_semantic_conflict",
                )
            except WeixinIdempotencyUnavailable as release_exc:
                raise _DurableTurnLeaseLost(
                    reason="turn_conflict_release_unavailable",
                    storage_unavailable=True,
                ) from release_exc
            if not released:
                raise _DurableTurnLeaseLost(
                    reason="turn_conflict_release_fenced"
                ) from exc
            raise HTTPException(
                status_code=409,
                detail={"code": "turn_semantic_conflict", "retryable": False},
                headers={"Cache-Control": "no-store"},
            ) from exc
        except ConversationReceiptUnavailable as exc:
            try:
                released = await run_in_threadpool(
                    store.fail,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    error_code="turn_receipt_reservation_unavailable",
                )
            except WeixinIdempotencyUnavailable as release_exc:
                raise _DurableTurnLeaseLost(
                    reason="turn_reservation_release_unavailable",
                    storage_unavailable=True,
                ) from release_exc
            if not released:
                raise _DurableTurnLeaseLost(
                    reason="turn_reservation_release_fenced"
                ) from exc
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "turn_receipt_reservation_unavailable",
                    "retryable": True,
                },
                headers={"Retry-After": "2", "Cache-Control": "no-store"},
            ) from exc

        if turn_reservation_state == "committed":
            # A prior worker may have committed the conversation transaction
            # after our first replay read but before this reservation check.
            recovered_turn = await run_in_threadpool(
                app.state.conversations.idempotent_result,
                turn_identity,
                request_sha256,
            )
            if recovered_turn is None:
                raise _DurableTurnLeaseLost(
                    reason="turn_committed_result_missing",
                    storage_unavailable=True,
                )
            try:
                recovered_persisted = await run_in_threadpool(
                    store.succeed,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    recovered_turn,
                )
            except (ValueError, WeixinIdempotencyUnavailable) as exc:
                raise HTTPException(
                    status_code=503,
                    detail={"code": "idempotency_recovery_failed", "retryable": True},
                    headers={"Retry-After": "2", "Cache-Control": "no-store"},
                ) from exc
            if not recovered_persisted:
                raise _DurableTurnLeaseLost(reason="idempotency_claim_fenced")
            turn_receipt_committed = True
            return JSONResponse(
                recovered_turn,
                headers={
                    "Idempotency-Replayed": "true",
                    "Cache-Control": "no-store",
                },
            )
        if turn_reservation_state == "provider_started":
            turn_provider_phase_entered = True
            recovery_required = True
        elif turn_reservation_state != "reserved":
            raise _DurableTurnLeaseLost(
                reason="turn_reservation_state_invalid",
                storage_unavailable=True,
            )

        if recovery_required and turn_reservation_state == "reserved":
            try:
                turn_reservation_state = await run_in_threadpool(
                    app.state.conversations.enter_turn_provider_phase,
                    turn_key=turn_identity,
                    request_sha256=request_sha256,
                )
            except (ValueError, ConversationReceiptUnavailable) as exc:
                raise _DurableTurnLeaseLost(
                    reason="turn_recovery_fence_unavailable",
                    storage_unavailable=True,
                ) from exc
            if turn_reservation_state != "provider_started":
                raise _DurableTurnLeaseLost(reason="turn_recovery_fence_invalid")
            turn_provider_phase_entered = True
        if recovery_required:
            recovery_notice = {
                "reply": (
                    "纳川检测到上一轮模型调用可能已经产生费用，但回复未能安全落盘；"
                    "已停止自动重试以避免重复扣费。管理员确认前，请勿原样重发付费或"
                    "不可逆任务；普通对话可另起新问题。"
                    f"管理员可凭恢复编号 {turn_identity} 排查。"
                ),
                "model": _CHANNEL_LOCAL_MODEL,
                "channel_result_version": _CHANNEL_RESULT_VERSION,
                "attribution_state": _CHANNEL_ATTRIBUTION_LOCAL,
                "turns": 0,
                "usage": {},
                "orchestration_mode": "safety_recovery",
                "verified": False,
                "outcome": "provider_result_recovery_required",
                "blocked": True,
                "recovery_id": turn_identity,
                "notice_trace_id": str(request.state.trace_id),
            }
            try:
                recovery_notice = await run_in_threadpool(
                    app.state.conversations.commit_idempotent_turn,
                    turn_key=turn_identity,
                    request_sha256=request_sha256,
                    entries=[],
                    result=recovery_notice,
                    require_provider_started=True,
                )
                turn_receipt_committed = True
                recovery_persisted = await run_in_threadpool(
                    store.succeed,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    recovery_notice,
                )
            except (
                ValueError,
                ConversationReceiptUnavailable,
                WeixinIdempotencyUnavailable,
            ) as exc:
                try:
                    released = await run_in_threadpool(
                        store.fail,
                        principal_hash,
                        idempotency_key,
                        request_sha256,
                        fencing_token,
                        error_code="provider_recovery_notice_commit_failed",
                    )
                except WeixinIdempotencyUnavailable as release_exc:
                    raise _DurableTurnLeaseLost(
                        reason="provider_recovery_release_unavailable",
                        storage_unavailable=True,
                    ) from release_exc
                if not released:
                    raise _DurableTurnLeaseLost(
                        reason="provider_recovery_release_fenced"
                    ) from exc
                raise HTTPException(
                    status_code=503,
                    detail={
                        "code": "provider_recovery_notice_commit_failed",
                        "retryable": True,
                    },
                    headers={"Retry-After": "2", "Cache-Control": "no-store"},
                ) from exc
            if not recovery_persisted:
                raise _DurableTurnLeaseLost(
                    reason="provider_recovery_notice_fenced"
                )
            return JSONResponse(
                recovery_notice,
                headers={
                    "Idempotency-Replayed": "false",
                    "Cache-Control": "no-store",
                },
            )
        agent_conversations = BufferedConversationStore(app.state.conversations)

    started = time.time()
    try:
        try:
            if store is not None:
                if (
                    durable_turn_deadline is None
                    or time.monotonic() >= durable_turn_deadline
                ):
                    raise TimeoutError
                # The claim was just acquired, but recovery reads can still be
                # delayed. Revalidate immediately before entering agent_chat,
                # the first boundary that can call an upstream model or create
                # a provider job. Cancellation cannot retract a job an upstream
                # provider has already accepted; provider-side idempotency is
                # therefore still required for truly irreversible operations.
                await _renew_durable_turn_or_raise(
                    store,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                )
                if (
                    durable_turn_deadline is not None
                    and time.monotonic() >= durable_turn_deadline
                ):
                    # Still in the reversible ``reserved`` state: abandon it
                    # before writing provider_started, otherwise a retry would
                    # conservatively require operator recovery despite zero
                    # upstream call having been scheduled.
                    raise TimeoutError("durable Turn deadline exceeded")
                try:
                    turn_reservation_state = await run_in_threadpool(
                        app.state.conversations.enter_turn_provider_phase,
                        turn_key=turn_identity,
                        request_sha256=request_sha256,
                    )
                except ValueError as exc:
                    raise _DurableTurnLeaseLost(
                        reason="turn_provider_phase_conflict"
                    ) from exc
                except ConversationReceiptUnavailable as exc:
                    raise _DurableTurnLeaseLost(
                        reason="turn_provider_phase_unavailable",
                        storage_unavailable=True,
                    ) from exc
                if turn_reservation_state != "provider_started":
                    raise _DurableTurnLeaseLost(
                        reason="turn_provider_phase_fenced"
                    )
                turn_provider_phase_entered = True
                try:
                    entered_provider_phase = await run_in_threadpool(
                        store.enter_provider_phase,
                        principal_hash,
                        idempotency_key,
                        request_sha256,
                        fencing_token,
                    )
                except WeixinIdempotencyUnavailable as exc:
                    raise _DurableTurnLeaseLost(
                        reason="provider_phase_unavailable",
                        storage_unavailable=True,
                    ) from exc
                if not entered_provider_phase:
                    # The conversation DB has already recorded provider intent.
                    # If this owner still holds the outer token, convert its
                    # claim to an immediately recoverable failed record.  If it
                    # no longer owns the token, fail() is fenced and the live
                    # owner remains authoritative.
                    try:
                        released_after_gap = await run_in_threadpool(
                            store.fail,
                            principal_hash,
                            idempotency_key,
                            request_sha256,
                            fencing_token,
                            error_code="provider_phase_fenced",
                        )
                    except WeixinIdempotencyUnavailable as exc:
                        raise _DurableTurnLeaseLost(
                            reason="provider_phase_release_unavailable",
                            storage_unavailable=True,
                        ) from exc
                    if not released_after_gap:
                        raise _DurableTurnLeaseLost(
                            reason="provider_phase_fenced"
                        )
                    raise _DurableTurnLeaseLost(reason="provider_phase_fenced")
                heartbeat_stop = asyncio.Event()
                heartbeat_task = asyncio.create_task(
                    _renew_weixin_idempotency_lease(
                        store,
                        principal_hash,
                        idempotency_key,
                        request_sha256,
                        fencing_token,
                        heartbeat_stop,
                    )
                )
            author_token = set_agent_author_context(
                turn_identity or secrets.token_hex(32)
            )
            try:
                with bind_provider_call_scope(
                    turn_id=turn_identity or str(request.state.trace_id),
                    workflow_id=f"{channel}:agent_chat",
                    role="agent_chat",
                ):
                    agent_timeout_seconds = (
                        _DURABLE_TURN_DEADLINE_SECONDS
                        if durable_turn_deadline is None
                        else max(0.0, durable_turn_deadline - time.monotonic())
                    )
                    if heartbeat_task is not None and agent_timeout_seconds <= 0:
                        # Do not even construct/schedule Agent work after slow
                        # claim/recovery/reservation preflight consumed the
                        # shared Turn budget. The outer failure path safely
                        # abandons the pre-provider reservation and claim.
                        raise TimeoutError("durable Turn deadline exceeded")
                    agent_call = agent_chat(
                        router,
                        agent_conversations,
                        message=message,
                        chat_id=chat_id,
                        channel=channel,
                        user_id=user_id,
                        model=model,
                        model_locked=bool(str(requested_model or "").strip()),
                        system=system,
                        memory=app.state.memory,
                        cases=app.state.cases,
                        approvals=app.state.approvals,
                        guard=app.state.guard,
                        persona=get_settings().agent_persona,
                        video_async=video_async,
                        video_async_capacity_available=video_async_capacity_available,
                        kb=app.state.kb,
                    )
                    result = (
                        await _await_durable_agent_call(
                            agent_call,
                            heartbeat_task,
                            timeout_seconds=agent_timeout_seconds,
                        )
                        if heartbeat_task is not None
                        else await agent_call
                    )
                    try:
                        result = normalize_legacy_agent_result(result)
                    except AgentResultContractError as exc:
                        raise HTTPException(
                            status_code=502,
                            detail={
                                "code": "invalid_agent_result",
                                "retryable": False,
                            },
                            headers={"Cache-Control": "no-store"},
                        ) from exc
            finally:
                reset_agent_author_context(author_token)
        except ProviderError as exc:
            raise _public_provider_http_error(exc) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=504,
                detail={"code": "durable_turn_deadline_exceeded", "retryable": True},
                headers={"Retry-After": "2", "Cache-Control": "no-store"},
            ) from exc
        route = router.resolve(result["model"])
        u = result.get("usage") or {}
        result["trace_id"] = request.state.trace_id
        result = _sanitize_agent_chat_result(result)
        response_result = (
            _mint_durable_channel_response(result)
            if channel in {"weixin", "feishu"}
            else result
        )
        if store is not None:
            if heartbeat_task is None:
                raise RuntimeError("durable channel Turn lost its heartbeat task")
            if heartbeat_task.done():
                _propagate_heartbeat_result(heartbeat_task, clean_stop=False)
            # Renew immediately before the first local durable side effect. The
            # conversation receipt and replay ledger are separate SQLite files,
            # so this closes the practical stale-owner window but cannot make
            # their two commits one atomic transaction.
            await _renew_durable_turn_or_raise(
                store,
                principal_hash,
                idempotency_key,
                request_sha256,
                fencing_token,
            )
            if heartbeat_task.done():
                _propagate_heartbeat_result(heartbeat_task, clean_stop=False)
            if not isinstance(agent_conversations, BufferedConversationStore):
                raise RuntimeError(
                    "durable channel Turn must use a transactional conversation buffer"
                )
            response_result = await run_in_threadpool(
                agent_conversations.commit,
                turn_key=turn_identity,
                request_sha256=request_sha256,
                result=response_result,
                require_provider_started=True,
            )
            turn_receipt_committed = True
            heartbeat_to_stop = heartbeat_task
            stop_to_set = heartbeat_stop
            heartbeat_task = None
            heartbeat_stop = None
            if stop_to_set is None:
                raise RuntimeError("durable channel Turn lost its heartbeat stop event")
            await _stop_durable_heartbeat(stop_to_set, heartbeat_to_stop)
            try:
                persisted_success = await run_in_threadpool(
                    store.succeed,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    response_result,
                )
            except (ValueError, WeixinIdempotencyUnavailable) as exc:
                raise HTTPException(
                    status_code=503,
                    detail={"code": "idempotency_commit_failed", "retryable": True},
                    headers={"Retry-After": "2", "Cache-Control": "no-store"},
                ) from exc
            if not persisted_success:
                raise _DurableTurnLeaseLost(reason="commit_fenced")
        # Usage is itself a durable side effect. Log only after the Turn's
        # replay record is committed, so a fenced/failed attempt cannot double
        # count a retry.
        await _log_usage_best_effort(
            usage,
            api_key=api_key,
            virtual_model=result["model"],
            provider=route.provider.name if route else "agent",
            upstream_model=route.upstream_model if route else result["model"],
            tier=route.tier if route else "agent",
            prompt_tokens=int(u.get("prompt_tokens", 0) or 0),
            completion_tokens=int(u.get("completion_tokens", 0) or 0),
            total_tokens=int(u.get("total_tokens", 0) or 0),
            cost_usd=float(u.get("cost_usd", 0) or 0),
            stream=0,
            status="ok",
            latency_ms=int((time.time() - started) * 1000),
        )
        # Only schedule memory extraction after both the transactional Turn
        # receipt and the gateway replay ledger are durable.  A failed commit
        # therefore cannot enqueue duplicate extraction on retry.
        if user_id and not response_result.get("blocked"):
            extract_model = (
                "agnes-flash"
                if router.resolve("agnes-flash")
                else (pick_model(router, "cheap") or model)
            )
            background.add_task(
                _extract_and_store_scoped,
                ProviderCallContext(
                    trace_id=str(request.state.trace_id),
                    turn_id=turn_identity or str(request.state.trace_id),
                    workflow_id=f"{channel}:agent_chat",
                    role="memory.extract",
                ),
                router,
                app.state.memory,
                user_id=user_id,
                user_msg=message,
                assistant_msg=response_result.get("reply", ""),
                model=extract_model,
            )
        headers = {"Cache-Control": "no-store"}
        if store is not None:
            headers["Idempotency-Replayed"] = "false"
        return JSONResponse(response_result, headers=headers)
    except BaseException as exc:
        if heartbeat_task is not None:
            heartbeat_to_stop = heartbeat_task
            stop_to_set = heartbeat_stop
            heartbeat_task = None
            heartbeat_stop = None
            if stop_to_set is None:
                raise RuntimeError("durable heartbeat task has no stop event") from exc
            # Stop/consume the heartbeat before changing claim state. Otherwise
            # fail() can clear the token while a concurrent renewal interprets
            # that deliberate release as an unrelated lease loss.
            stop_error: BaseException | None = None
            try:
                await _stop_durable_heartbeat(stop_to_set, heartbeat_to_stop)
            except BaseException as caught_stop_error:
                stop_error = caught_stop_error
            if stop_error is not None:
                if hasattr(exc, "add_note"):
                    exc.add_note(
                        "durable heartbeat cleanup also failed; the claim will expire naturally"
                    )
                raise exc from stop_error
        if (
            store is not None
            and turn_reservation_state == "reserved"
            and not turn_provider_phase_entered
            and not turn_receipt_committed
        ):
            try:
                await run_in_threadpool(
                    app.state.conversations.abandon_turn_before_provider,
                    turn_key=turn_identity,
                    request_sha256=request_sha256,
                )
            except (ValueError, ConversationReceiptUnavailable) as abandon_exc:
                raise _DurableTurnLeaseLost(
                    reason="turn_reservation_abandon_unavailable",
                    storage_unavailable=True,
                ) from abandon_exc
        if (
            store is not None
            and fencing_token
            and not persisted_success
            and not isinstance(exc, (asyncio.CancelledError, _DurableTurnLeaseLost))
        ):
            try:
                released = await run_in_threadpool(
                    store.fail,
                    principal_hash,
                    idempotency_key,
                    request_sha256,
                    fencing_token,
                    error_code=type(exc).__name__,
                )
            except WeixinIdempotencyUnavailable as release_exc:
                raise _DurableTurnLeaseLost(
                    reason="failure_release_unavailable", storage_unavailable=True
                ) from release_exc
            if not released:
                raise _DurableTurnLeaseLost(reason="failure_release_fenced") from exc
        raise
    finally:
        if heartbeat_task is not None:
            if heartbeat_stop is None:
                raise RuntimeError("durable heartbeat task has no stop event")
            # Intentionally no return_exceptions=True: a renew failure is a
            # lease-lost terminal and must never be converted into success.
            await _stop_durable_heartbeat(heartbeat_stop, heartbeat_task)


@app.get("/v1/agent/memory")
async def list_memory(user_id: str, _: str = Depends(require_api_key)):
    """查看某用户已学到的长期记忆（供验证与“进化看板”）。"""
    return {"user_id": user_id, "memories": app.state.memory.all_for(user_id)}


def _normalized_mutation_id(value: Any, *, label: str, max_length: int = 256) -> str:
    """Canonicalize a destructive-operation target before capability binding."""
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail=f"{label} 必须是字符串")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized)
    ):
        raise HTTPException(status_code=422, detail=f"{label} 格式无效")
    return normalized


async def _destructive_request_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象") from exc
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    return body


def _destructive_user_id(body: dict[str, Any]) -> str:
    raw = body.get("user_id")
    if raw in (None, ""):
        raw = get_settings().agent_user_id or "owner"
    return _normalized_mutation_id(raw, label="user_id", max_length=128)


def _has_approval_id(body: dict[str, Any]) -> bool:
    return body.get("approval_id") not in (None, "", 0, "0")


def _snapshot_hash(rows: Any) -> tuple[str, int]:
    """Hash ordered SQLite rows without putting deleted content in approval rows."""
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        encoded = json.dumps(
            list(row), ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return digest.hexdigest(), count


def _memory_clear_spec(user_id: str) -> dict[str, Any]:
    store = app.state.memory
    # Include active and superseded records: clear() removes both. The content is
    # hashed locally and never copied into the approval payload/UI.
    with store._lock:  # noqa: SLF001 - same-process transactional snapshot
        rows = store._conn.execute(  # noqa: SLF001
            "SELECT id,text,kind,status,source,created_at,updated_at "
            "FROM user_memory WHERE user_id=? ORDER BY id",
            (user_id,),
        )
        state_sha256, records = _snapshot_hash(rows)
    return {
        "target": {"kind": "memory_user", "user_id": user_id},
        "snapshot": {"sha256": state_sha256, "records": records},
    }


@app.delete("/v1/agent/memory")
async def clear_memory_legacy(_: str = Depends(require_api_key)):
    """The legacy body-less DELETE cannot carry an exact one-time capability."""
    raise HTTPException(
        status_code=410,
        detail="请使用 POST /v1/agent/memory/clear 走一次性审批",
    )


@app.post("/v1/agent/memory/clear")
async def clear_memory_approved(request: Request, _: str = Depends(require_api_key)):
    """Clear one user's exact reviewed memory snapshot after one-time approval."""
    body = await _destructive_request_body(request)
    user_id = _destructive_user_id(body)
    spec = _memory_clear_spec(user_id)
    if not _has_approval_id(body) and spec["snapshot"]["records"] == 0:
        return {"ok": True, "user_id": user_id, "already_empty": True}
    task = f"清空长期记忆：{user_id}"
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=str(Path(get_settings().usage_db_path).parent.resolve()),
        user_id=user_id,
        scope="memory_clear",
        mode="full",
        require_explicit_capability=True,
        payload_extra=spec,
    )
    if held is not None:
        return held
    try:
        if _memory_clear_spec(user_id) != spec:
            raise HTTPException(status_code=409, detail="记忆已变化，请重新审批")
        app.state.memory.clear(user_id)
        if _memory_clear_spec(user_id)["snapshot"]["records"] != 0:
            raise RuntimeError("memory clear did not remove the reviewed target")
    except Exception:
        app.state.approvals.finish_action(approval_id, success=False)
        raise
    app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "user_id": user_id}


@app.get("/v1/agent/cases")
async def list_cases(user_id: str, _: str = Depends(require_api_key)):
    """查看某用户的“技能/案例库”（强模型解过、可被免费模型复用的难题）。"""
    return {"user_id": user_id, "cases": app.state.cases.all_for(user_id)}


# ── 知识库（IMA）：导入文档 / 列表 / 删除 / 据实带引用问答 ──
@app.get("/v1/kb/docs")
async def kb_list(user_id: str, _: str = Depends(require_api_key)):
    """列出某用户知识库的文档。"""
    return {"user_id": user_id, "docs": app.state.kb.list_documents(user_id)}


@app.post("/v1/kb/docs")
async def kb_import(request: Request, _: str = Depends(require_api_key)):
    """导入一篇文档到知识库：{user_id,title,text,source}。分块入库。"""
    body = await request.json()
    text = str(body.get("text") or "")
    if not text.strip():
        raise HTTPException(status_code=422, detail="需要 text 文本内容")
    return app.state.kb.add_document(
        str(body.get("user_id") or "owner"),
        str(body.get("title") or "未命名"),
        text,
        str(body.get("source") or ""),
    )


@app.delete("/v1/kb/docs/{doc_id}")
async def kb_delete_legacy(doc_id: int, _: str = Depends(require_api_key)):
    """The legacy body-less DELETE cannot carry an exact one-time capability."""
    del doc_id
    raise HTTPException(
        status_code=410,
        detail="请使用 POST /v1/kb/docs/{doc_id}/delete 走一次性审批",
    )


def _knowledge_delete_spec(user_id: str, doc_id: int) -> dict[str, Any]:
    kb = app.state.kb
    with kb._lock:  # noqa: SLF001 - exact same-process document snapshot
        doc = kb._conn.execute(  # noqa: SLF001
            "SELECT id,user_id,title,source,chunks,created_at "
            "FROM kb_docs WHERE user_id=? AND id=?",
            (user_id, doc_id),
        ).fetchone()
        if doc is None:
            state_sha256, records = _snapshot_hash([])
            exists = False
        else:
            chunk_rows = kb._conn.execute(  # noqa: SLF001
                "SELECT id,user_id,doc_id,title,text FROM kb_chunks "
                "WHERE user_id=? AND doc_id=? ORDER BY id",
                (user_id, doc_id),
            ).fetchall()
            state_sha256, records = _snapshot_hash([("doc", *doc), *chunk_rows])
            exists = True
    return {
        "target": {
            "kind": "knowledge_document",
            "user_id": user_id,
            "doc_id": doc_id,
        },
        "snapshot": {
            "sha256": state_sha256,
            "records": records,
            "exists": exists,
        },
    }


@app.post("/v1/kb/docs/{doc_id}/delete")
async def kb_delete_approved(
    doc_id: int, request: Request, _: str = Depends(require_api_key)
):
    """Delete the exact reviewed document and chunk snapshot once."""
    if doc_id <= 0:
        raise HTTPException(status_code=422, detail="doc_id 必须是正整数")
    body = await _destructive_request_body(request)
    user_id = _destructive_user_id(body)
    spec = _knowledge_delete_spec(user_id, doc_id)
    if not spec["snapshot"]["exists"] and not _has_approval_id(body):
        raise HTTPException(status_code=404, detail="知识库文档不存在")
    task = f"删除知识库文档：user={user_id}, doc_id={doc_id}"
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=str(Path(get_settings().usage_db_path).parent.resolve()),
        user_id=user_id,
        scope="knowledge_document_delete",
        mode="full",
        require_explicit_capability=True,
        payload_extra=spec,
    )
    if held is not None:
        return held
    try:
        if _knowledge_delete_spec(user_id, doc_id) != spec:
            raise HTTPException(status_code=409, detail="知识库文档已变化，请重新审批")
        deleted = app.state.kb.delete_document(user_id, doc_id)
        if not deleted or _knowledge_delete_spec(user_id, doc_id)["snapshot"]["exists"]:
            raise RuntimeError("knowledge document delete did not remove the reviewed target")
    except Exception:
        app.state.approvals.finish_action(approval_id, success=False)
        raise
    app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "user_id": user_id, "doc_id": doc_id}


@app.post("/v1/kb/query")
async def kb_query(request: Request, _: str = Depends(require_api_key)):
    """问知识库：检索相关分块 → 模型据实带引用回答。返回 {answer, sources}。"""
    body = await request.json()
    user_id = str(body.get("user_id") or "owner")
    query = str(body.get("query") or "").strip()
    if not query:
        raise HTTPException(status_code=422, detail="需要 query")
    router = app.state.router
    hits = app.state.kb.search(user_id, query, k=int(body.get("k") or 5))
    if not hits:
        return {"answer": "知识库里没找到相关内容。", "sources": []}
    model = "agnes-flash" if router.resolve("agnes-flash") else (pick_model(router, "cheap") or "echo")
    req = ChatCompletionRequest(
        model=model,
        messages=[
            ChatMessage(
                role="system",
                content=kb_context(hits)
                + "\n\n只依据以上资料回答用户问题，引用处标[编号]；资料里没有就说「知识库里没有」、别编。",
            ),
            ChatMessage(role="user", content=query),
        ],
    )
    try:
        res, served, _route = await chat_with_fallback(router, req)
        answer = (res.get("choices") or [{}])[0].get("message", {}).get("content", "")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail="知识库回答失败，请到诊断中心查看详情",
            headers={"Cache-Control": "no-store"},
        ) from exc
    sources = [{"doc_id": h["doc_id"], "title": h["title"], "score": h["score"]} for h in hits]
    return {"answer": answer, "sources": sources, "model": served, "usage": res.get("usage") or {}}


@app.post("/v1/intent")
async def intent_classify(request: Request, _: str = Depends(require_api_key)):
    """意图分类（#17）：{message} → {intent}。免费模型判，比正则准；任何端共享（#15）。"""
    body = await request.json()
    message = str(body.get("message") or "").strip()
    if not message:
        return {"intent": "chat"}
    intent = await classify_intent(app.state.router, message)
    return {"intent": intent}


@app.post("/v1/web/read")
async def web_read(request: Request, _: str = Depends(require_api_key)):
    """贴网页链接 → 抓正文 + 模型总结。body: {url, question?, model?}。视频链接请走 /v1/lapian/url。"""
    body = await request.json()
    raw = str(body.get("url") or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="需要 url")
    m = re.search(r"https?://[^\s，。、）)】」\"']+", raw)  # 从整段话里抠出真链接
    url = m.group(0) if m else raw
    try:
        return await read_and_summarize(
            app.state.router, url, question=str(body.get("question") or ""), model=str(body.get("model") or "")
        )
    except Exception as e:  # noqa: BLE001
        from gateway.providers.base import friendly_error

        raise HTTPException(status_code=502, detail=f"网页抓取失败：{friendly_error(e)}")


@app.post("/v1/workflows/daily-video/start")
async def daily_video_start(_: str = Depends(require_api_key)):
    """Disabled until an independently sandboxed, attested worker exists."""
    raise HTTPException(
        status_code=503,
        detail="日更 Python 启动器已关闭：需要独立低权限执行 worker 后才能启用",
    )


# ── 视频工作室（创作线·①②出方案+调教；③执行随后）──
@app.post("/v1/studio/plan")
async def studio_plan(request: Request, _: str = Depends(require_api_key)):
    """出/改分镜方案：{goal, feedback?, plan?} → {plan}。只出方案、不生成视频。"""
    body = await request.json()
    goal = str(body.get("goal") or "").strip()
    if not goal:
        raise HTTPException(status_code=422, detail="需要 goal（视频目标）")
    plan = await generate_plan(
        app.state.router, goal, str(body.get("feedback") or ""), body.get("plan")
    )
    return {"plan": plan}


@app.post("/v1/studio/execute")
async def studio_execute(request: Request, _: str = Depends(require_api_key)):
    """③ 按方案成片：{plan} → 起后台任务，返回 {job_id}（逐镜生成→拼接）。"""
    if not current_runtime_profile().allows(RuntimeCapability.STUDIO_EXECUTION):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭工作室执行；需要独立低权限 worker",
        )
    body = await request.json()
    plan = body.get("plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("shots"), list):
        raise HTTPException(status_code=422, detail="plan 格式无效")
    if not plan["shots"]:
        raise HTTPException(status_code=422, detail="需要 plan（含 shots）")
    if len(plan["shots"]) > 100 or len(json.dumps(plan, ensure_ascii=False)) > 256_000:
        raise HTTPException(status_code=422, detail="plan 超过 100 个镜头或 256KB 安全上限")
    out_dir = str(Path(get_settings().usage_db_path).parent / "studio")
    task = str(body.get("task") or f"执行视频方案：{str(plan.get('title') or '未命名')}")
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=out_dir,
        user_id=str(body.get("user_id") or get_settings().agent_user_id or "owner"),
        scope="studio_execute",
        mode="auto",
        require_explicit_capability=True,
        payload_extra={"plan": plan},
    )
    if held is not None:
        return held
    try:
        job_id = start_execution(app.state.router, plan, out_dir)
    except Exception:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return {"job_id": job_id}


@app.get("/v1/studio/execute/{job_id}")
async def studio_execute_status(job_id: str, _: str = Depends(require_api_key)):
    """轮询成片进度：{status, progress, total, msg, video, error}。完成后视频在 /v1/studio/video/{id}。"""
    return get_job(job_id)


@app.get("/v1/studio/video/{job_id}")
async def studio_video(job_id: str, _: str = Depends(require_api_key)):
    """取成片结果（mp4）。"""
    from fastapi.responses import FileResponse

    job = get_job(job_id)
    vid = job.get("video") or ""
    if job.get("status") != "done" or not vid or not Path(vid).exists():
        raise HTTPException(status_code=404, detail="还没成片或文件不存在")
    return FileResponse(vid, media_type="video/mp4", filename="video.mp4")


@app.get("/v1/approvals")
async def list_approvals(
    user_id: str,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """机主待审清单（P5 重大动作 + P6 技能卡入库）。前端据此弹「动作摘要 + 同意/换方案/取消 + 自定义输入」。"""
    return {"user_id": user_id, "pending": app.state.approvals.list_pending(user_id)}


@app.post("/v1/approvals/{approval_id}/resolve")
async def resolve_approval(
    approval_id: int,
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """裁决一条待审：decision=approve(同意)/reject(取消)/revise(换方案，note=机主自定义说明)。
    技能卡同意 → 正式进案例库（P6 闭环）；重大动作的裁决回传，调用方据此放行/改方案/作罢。"""
    body = await request.json()
    decision = str(body.get("decision") or "").lower()
    note = str(body.get("note") or "")
    rec = app.state.approvals.resolve(approval_id, decision, note)
    if rec is None:
        raise HTTPException(status_code=422, detail="decision 需为 approve/reject/revise，且待审项需存在")
    if rec.get("status") == "expired":
        raise HTTPException(status_code=409, detail="审批已过期，请重新发起动作")
    result: dict[str, Any] = {
        "ok": True, "id": approval_id, "status": rec["status"], "kind": rec["kind"], "note": rec.get("note", ""),
    }
    # 技能卡审核「同意」→ 正式入案例库（复盘→技能卡→待审→审核→案例库 闭环）
    if rec["kind"] == "skill_card" and rec["status"] == "approved":
        p = rec.get("payload") or {}
        result["case_id"] = app.state.cases.add(
            rec["user_id"], p.get("problem", ""), p.get("solution", ""), p.get("model", "user_approved")
        )
    return JSONResponse(result)


@app.post("/v1/sync/cases/push")
async def sync_cases_push(request: Request, _: str = Depends(require_api_key)):
    """跨设备同步：把一台机器学到的案例合并进本服务器的共享库（去重幂等，不重复堆）。"""
    body = await request.json()
    user_id = str(body.get("user_id") or "")
    added = app.state.cases.import_merge(user_id, body.get("items") or []) if user_id else 0
    return {"ok": True, "added": added}


@app.get("/v1/sync/cases/pull")
async def sync_cases_pull(user_id: str, _: str = Depends(require_api_key)):
    """跨设备同步：拉取共享库全部案例，调用方 import_merge 到本地（各机各存全份=容灾）。"""
    return {"user_id": user_id, "items": app.state.cases.export_all(user_id)}


# ── 跨设备云同步（Supabase）：记忆+案例+知识库，按 Supabase 账户隔离 ──────────────
@app.get("/v1/sync/status")
async def cloud_sync_status(_: str = Depends(require_api_key)):
    """同步状态（不回显任何密钥/token）：是否配置/登录、邮箱、上次同步时间。"""
    from orchestrator import cloud_sync

    return cloud_sync.status()


@app.post("/v1/sync/config")
async def cloud_sync_config(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """录入 Supabase 项目 URL + anon key（不回显、存本地 data/sync.json）。"""
    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="同步配置必须是 JSON 对象")
    url = body.get("url")
    anon_key = body.get("anon_key")
    if not isinstance(url, str) or not isinstance(anon_key, str):
        raise HTTPException(status_code=422, detail="url/anon_key 必须是字符串")
    if len(url) > 2048 or len(anon_key) > 16384:
        raise HTTPException(status_code=413, detail="同步配置超过长度限制")
    try:
        target = cloud_sync.validate_target(url, anon_key)
        cloud_sync.configure(target["url"], anon_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Supabase 目标不符合安全策略") from exc
    except (OSError, SecureStorageError) as exc:
        raise HTTPException(status_code=503, detail="同步配置未能安全持久化") from exc
    return cloud_sync.status()


@app.post("/v1/sync/signup")
async def cloud_sync_signup(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """Supabase 注册（商用：终端用户自助开账户）。"""
    from starlette.concurrency import run_in_threadpool

    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="注册参数必须是 JSON 对象")
    email = body.get("email")
    password = body.get("password")
    if (
        not isinstance(email, str)
        or not isinstance(password, str)
        or not email.strip()
        or not password
        or len(email) > 320
        or len(password) > 1024
    ):
        raise HTTPException(status_code=422, detail="邮箱或密码格式无效")
    return await run_in_threadpool(
        cloud_sync.signup, email.strip(), password
    )


@app.post("/v1/sync/login")
async def cloud_sync_login(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """Supabase 邮箱密码登录（拿 token、定账户）。"""
    from starlette.concurrency import run_in_threadpool

    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="登录参数必须是 JSON 对象")
    email = body.get("email")
    password = body.get("password")
    if (
        not isinstance(email, str)
        or not isinstance(password, str)
        or not email.strip()
        or not password
        or len(email) > 320
        or len(password) > 1024
    ):
        raise HTTPException(status_code=422, detail="邮箱或密码格式无效")
    return await run_in_threadpool(
        cloud_sync.login, email.strip(), password
    )


@app.post("/v1/sync/toggle")
async def cloud_sync_toggle(
    request: Request,
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """同步总开关。"""
    from orchestrator import cloud_sync

    body = await request.json()
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        raise HTTPException(status_code=422, detail="enabled 必须是布尔值")
    enabled = body["enabled"]
    current = cloud_sync.status()
    if enabled and not (current.get("configured") and current.get("logged_in")):
        raise HTTPException(status_code=409, detail="同步目标尚未配置并登录")
    try:
        cloud_sync.set_enabled(enabled)
    except (OSError, SecureStorageError) as exc:
        raise HTTPException(status_code=503, detail="同步开关未能安全持久化") from exc
    return cloud_sync.status()


@app.post("/v1/sync/run")
async def cloud_sync_run(
    _: str = Depends(require_api_key),
    __: str = Depends(require_approval_admin_key),
):
    """立即同步一次：四张表各 push 本地 + pull 远端合并。未就绪则安全跳过。"""
    from starlette.concurrency import run_in_threadpool

    from orchestrator import cloud_sync

    return await run_in_threadpool(cloud_sync.sync_all)


@app.post("/v1/agent/feedback")
async def agent_feedback(
    request: Request, credential: str = Depends(require_bridge_or_api_key)
):
    """反馈（Reflexion）：rating=up/down。👎+note→存教训(下次注入)；👍→上一轮提升为案例。"""
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
    requested_channel = str(body.get("channel") or "").strip().lower()
    if credential.startswith("bridge:") and credential != f"bridge:{requested_channel}":
        raise HTTPException(status_code=403, detail="bridge credential channel mismatch")
    user_id = str(body.get("user_id") or "")
    rating = str(body.get("rating") or "").lower()
    if not user_id or rating not in ("up", "down"):
        raise HTTPException(status_code=422, detail="需要 user_id 与 rating(up/down)")
    idempotency_key = body.get("idempotency_key")
    if requested_channel in {"feishu", "weixin"} and not isinstance(
        idempotency_key, str
    ):
        raise HTTPException(
            status_code=422,
            detail=f"{requested_channel} feedback requires idempotency_key",
        )
    if idempotency_key is not None:
        try:
            return await run_in_threadpool(
                record_feedback_once,
                memory=app.state.memory,
                cases=app.state.cases,
                conv=app.state.conversations,
                user_id=user_id,
                rating=rating,
                idempotency_key=idempotency_key,
                channel=requested_channel or "api",
                chat_id=str(body.get("chat_id") or ""),
                note=body.get("note"),
            )
        except ValueError as exc:
            status = 409 if "semantic conflict" in str(exc) else 422
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        except ConversationReceiptUnavailable as exc:
            raise HTTPException(
                status_code=503,
                detail="durable feedback receipt is unavailable",
            ) from exc
    return record_feedback(
        memory=app.state.memory,
        cases=app.state.cases,
        conv=app.state.conversations,
        user_id=user_id,
        rating=rating,
        channel=requested_channel or "api",
        chat_id=str(body.get("chat_id") or ""),
        note=body.get("note"),
    )


@app.post("/v1/agent/reflect")
async def agent_reflect(request: Request, _: str = Depends(require_api_key)):
    """反思：把某用户的零散记忆归纳为高层洞察(insight)。"""
    body = await request.json()
    user_id = str(body.get("user_id") or "")
    if not user_id:
        raise HTTPException(status_code=422, detail="需要 user_id")
    router: Router = app.state.router
    model = (
        "agnes-flash"
        if router.resolve("agnes-flash")
        else (pick_model(router, "cheap") or get_settings().bridge_model)
    )
    added = await reflect(router, app.state.memory, user_id=user_id, model=model)
    return {"user_id": user_id, "insights_added": added}


_READ_ONLY_AGENT_TOOLS = frozenset({
    "list_dir",
    "read_file",
    "list_models",
    "ask_model",
    "list_skills",
    "load_skill",
    "web_read",
    "kb_query",
    "translate",
})
_KNOWN_AGENT_TOOLS = frozenset(t["function"]["name"] for t in TOOLS)
_AUTO_AGENT_TOOLS = frozenset({
    *_READ_ONLY_AGENT_TOOLS,
    "write_file",
    "remember",
})


def _agent_mode(body: dict[str, Any], *, default: str = "plan") -> str:
    raw = str(body.get("mode") or default).strip().lower()
    aliases = {
        "plan": "plan",
        "read-only": "plan",
        "auto": "auto",
        "workspace-write": "auto",
        "acceptedits": "auto",
        "full": "full",
        "danger-full-access": "full",
        "bypasspermissions": "full",
    }
    mode = aliases.get(raw)
    if mode is None:
        raise HTTPException(status_code=422, detail="mode 只能是 plan / auto / full")
    return mode


def _agent_allow(body: dict[str, Any], mode: str) -> set[str] | None:
    """Parse a capability set without conflating an explicit [] with all tools."""
    if "allow" not in body or body.get("allow") is None:
        requested: set[str] | None = None
    else:
        raw = body.get("allow")
        if not isinstance(raw, list) or any(not isinstance(x, str) for x in raw):
            raise HTTPException(status_code=422, detail="allow 必须是工具名字符串数组")
        requested = {x.strip() for x in raw if x.strip()}
        unknown = requested - _KNOWN_AGENT_TOOLS
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"未知工具：{', '.join(sorted(unknown))}",
            )
    if mode == "plan":
        if requested is None:
            return set(_READ_ONLY_AGENT_TOOLS)
        unsafe = requested - _READ_ONLY_AGENT_TOOLS
        if unsafe:
            raise HTTPException(
                status_code=403,
                detail=f"plan 模式不授予可写/可提交工具：{', '.join(sorted(unsafe))}",
            )
    elif mode == "auto" and requested is None:
        # auto 缺省只给工作区文件写入 + 只读能力；shell、浏览器提交、安装器和媒体
        # 必须由客户端按任务显式申请，并进入 capability manifest。
        return set(_AUTO_AGENT_TOOLS)
    return requested


def _approved_action_record(body: dict[str, Any], *, scope: str) -> dict[str, Any] | None:
    """Load the approved server-side payload selected by ``approval_id``.

    The request body is intentionally not merged into this record. The subsequent
    ``claim_action`` call is still the atomic permission check; this helper only lets
    an endpoint reconstruct the exact immutable fields that were approved.
    """
    raw = body.get("approval_id")
    if raw in (None, "", 0, "0"):
        return None
    try:
        approval_id = int(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=403, detail="无效审批凭证")
    rec = app.state.approvals.approved_action_spec(approval_id, scope=scope)
    if rec is None:
        raise HTTPException(status_code=403, detail="审批凭证无效、未批准或范围不符")
    return rec


async def _action_capability(
    *,
    body: dict[str, Any],
    router: Router,
    task: str,
    workdir: str,
    user_id: str,
    scope: str,
    mode: str,
    summary: str = "",
    soft_check: bool = False,
    enforce_task_risk: bool = True,
    require_explicit_capability: bool = False,
    payload_extra: dict[str, Any] | None = None,
) -> tuple[int, JSONResponse | None]:
    """Claim an exact one-time action capability or return a hold response."""
    try:
        approval_id = int(body.get("approval_id") or 0)
    except (TypeError, ValueError):
        raise HTTPException(status_code=403, detail="无效审批凭证")
    if approval_id:
        claimed = app.state.approvals.claim_action(
            approval_id,
            user_id=user_id,
            task=task,
            workdir=workdir,
            scope=scope,
            mode=mode,
            manifest=payload_extra or {},
        )
        if not claimed:
            raise HTTPException(status_code=403, detail="审批凭证无效、已使用、范围不符或与任务不匹配")
        return approval_id, None

    hard = (enforce_task_risk and needs_approval(task)) or mode == "full"
    delegated = mode == "auto"
    soft, soft_reason = (False, "")
    if soft_check and not hard and not delegated:
        soft, soft_reason = await should_escalate(router, task)
    if not (hard or soft or require_explicit_capability):
        return 0, None

    display = (summary or task).strip()[:80]
    payload = {
        **(payload_extra or {}),
        "scope": scope,
        "task": task,
        "workdir": workdir,
        "mode": mode,
    }
    aid = app.state.approvals.create(
        user_id,
        "action",
        (soft_reason if soft and soft_reason else display)[:80],
        payload,
    )
    return 0, JSONResponse({
        "needs_approval": True,
        "approval_id": aid,
        "summary": soft_reason if soft and soft_reason else display,
        "risk": "high" if hard else ("action" if require_explicit_capability else "review"),
        "by": "rule" if hard else ("capability" if require_explicit_capability else "model"),
        "scope": scope,
    })


async def _run_agent_exec(
    router: Router,
    task: str,
    *,
    backend: str = "auto",
    mode: str = "",
    workdir: str,
    model_override: Any = None,
) -> dict:
    """Permanent gateway-side stop until an OS-isolated worker is configured."""
    # 本机 CLI 的 read-only/plan 只约束写入，不构成凭据隔离：它仍以网关
    # 的 Windows 用户身份运行，可以读取同一用户可读的 ACL/DPAPI 配置与登录资料。
    # 在独立低权限账户/AppContainer/容器 worker + broker 尚未实现前，任何模式
    # （包括 plan）都必须 fail-closed；最小 env 和一次性审批不能替代 OS 边界。
    raise ProviderError(
        "本机 CLI 执行已关闭：尚未配置与网关凭据隔离的低权限执行 worker",
        status_code=503,
    )


@app.post("/v1/agent/exec")
async def agent_exec_endpoint(request: Request, _: str = Depends(require_api_key)):
    """Native host execution is unavailable inside the gateway process."""
    # 在解析任务、创建审批前即拒绝，避免给不可执行的宿主 CLI 签发 capability。
    raise HTTPException(
        status_code=503,
        detail="本机 CLI 执行已关闭：需要独立低权限执行 worker 后才能启用",
    )
    router: Router = app.state.router
    body = await request.json()
    task = (body.get("task") or "").strip()
    if not task:
        raise HTTPException(status_code=422, detail="需要 task")
    s = get_settings()
    workdir = str(body.get("workdir") or s.agent_exec_workdir or str(PROJECT_ROOT))
    uid = str(body.get("user_id") or s.agent_user_id or "owner")
    # API 缺省是只读 plan；auto/full 任何可写执行都必须消费服务端一次性 capability。
    _mode = _agent_mode(body)
    _instr = str(body.get("instruction") or "").strip()
    if not _instr and "【现在的指令】" in task:
        _instr = task.split("【现在的指令】", 1)[1].strip()
    _approval_id, held = await _action_capability(
        body=body,
        router=router,
        task=task,
        workdir=workdir,
        user_id=uid,
        scope="agent_exec",
        mode=_mode,
        summary=_instr,
        soft_check=True,
        require_explicit_capability=_mode != "plan",
        payload_extra={
            "backend": body.get("backend"),
            "model": body.get("model"),
        },
    )
    if held is not None:
        return held
    _claimed = bool(_approval_id)
    try:
        result = await _run_agent_exec(
            router,
            task,
            backend=str(body.get("backend") or "auto").lower(),
            mode=_mode,
            workdir=workdir,
            model_override=body.get("model"),
        )
    except ProviderError as e:
        if _claimed:
            app.state.approvals.finish_action(_approval_id, success=False)
        raise _public_provider_http_error(e) from e
    except Exception:
        if _claimed:
            app.state.approvals.finish_action(_approval_id, success=False)
        raise
    if _claimed:
        app.state.approvals.finish_action(_approval_id, success=True)
    return result


_JOBS: set = set()


def _make_step_executor(router: Router, *, workdir: str, backend: str, mode: str):
    """每步执行器：action→当前启用工具执行，reason→模型思考。"""

    async def executor(step: dict) -> str:
        if step.get("kind") == "reason":
            m = get_settings().bridge_model
            prompt = f"任务步骤：{step.get('title', '')}\n{step.get('detail', '')}\n请完成这一步，直接给结论。"
            req = ChatCompletionRequest(model=m, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
            res, _s, _r = await chat_with_fallback(router, req)
            return ((res.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        task = f"{step.get('title', '')}。{step.get('detail', '')}".strip("。 ")
        res = await _run_agent_exec(router, task, backend=backend, mode=mode, workdir=workdir)
        return str(res.get("result") or res.get("reply") or res.get("stdout") or "")[:4000]

    return executor


def _spawn_job(ledger: TaskLedger, jid: str, executor) -> None:
    pool = get_background_job_pool()
    lease = pool.try_acquire(kind="agent_job", external_ids=(jid,))
    if lease is None:
        raise BackgroundJobLimitExceeded("background agent-job capacity reached")

    async def tracked() -> None:
        try:
            await run_job(ledger, jid, executor)
        finally:
            pool.release(lease)

    try:
        t = asyncio.create_task(tracked())
    except Exception:
        pool.release(lease)
        raise
    _JOBS.add(t)
    t.add_done_callback(_JOBS.discard)


@app.post("/v1/agent/job")
async def create_job_endpoint(request: Request, _: str = Depends(require_api_key)):
    """执行脊柱：把一个目标自动分解成多步、逐步执行、可断点续跑。后台跑，立即返回 job_id+步骤；GET 轮询进度。"""
    raise HTTPException(
        status_code=503,
        detail="本机 CLI 任务执行已关闭：需要独立低权限执行 worker 后才能启用",
    )
    router: Router = app.state.router
    body = await request.json()
    s = get_settings()
    approved = _approved_action_record(body, scope="agent_job")
    if approved is not None:
        if approved.get("status") == "revise":
            raise HTTPException(
                status_code=409,
                detail="换方案会改变冻结步骤；请带补充要求重新发起并审批一份新计划",
            )
        # approval_id selects the complete server-side authority. Every other body
        # field is untrusted compatibility noise and is deliberately ignored.
        payload = approved.get("payload") or {}
        try:
            spec = validate_execution_spec(payload.get("execution_spec"))
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=403,
                detail="审批记录缺少可验证的冻结执行规范，请重新发起任务",
            )
        uid = str(approved.get("user_id") or "owner")
        claim_goal = str(spec["goal"])
    else:
        goal = str(body.get("goal") or "").strip()
        if not goal:
            raise HTTPException(status_code=422, detail="需要 goal")
        workdir = str(body.get("workdir") or s.agent_exec_workdir or str(PROJECT_ROOT))
        mode = _agent_mode(body)
        uid = str(body.get("user_id") or "owner")
        # Plan exactly once. This output is persisted in the approval payload and is
        # never regenerated after approval, even if the planner is non-deterministic.
        steps = body.get("steps") or await plan_job(router, goal)
        if not steps:
            raise HTTPException(status_code=502, detail="任务分解失败，换个说法或自带 steps")
        try:
            spec = freeze_execution_spec(
                goal=goal,
                steps=steps,
                workdir=workdir,
                backend=str(body.get("backend") or "auto"),
                mode=mode,
            )
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        claim_goal = str(spec["goal"])

    goal = str(spec["goal"])
    steps = list(spec["steps"])
    workdir = str(spec["workdir"])
    backend = str(spec["backend"])
    mode = str(spec["mode"])
    frozen_manifest = {
        "steps": steps,
        "backend": backend,
        "execution_spec": spec,
    }
    approval_id, held = await _action_capability(
        body=body,
        router=router,
        task=claim_goal,
        workdir=workdir,
        user_id=uid,
        scope="agent_job",
        mode=mode,
        enforce_task_risk=mode != "plan",
        require_explicit_capability=mode != "plan",
        payload_extra=frozen_manifest,
    )
    if held is not None:
        return held
    ledger: TaskLedger = app.state.ledger
    jid = ""
    try:
        jid = ledger.create_job(goal, steps, user_id=uid, execution_spec=spec)
        _spawn_job(
            ledger,
            jid,
            _make_step_executor(
                router,
                workdir=workdir,
                backend=backend,
                mode=mode,
            ),
        )
    except Exception:
        if jid:
            ledger.fail_unclaimed_job(jid)
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return {"job_id": jid, **ledger.to_dict(jid)}


@app.get("/v1/agent/job/{job_id}")
async def job_status_endpoint(job_id: str, _: str = Depends(require_api_key)):
    """查任务进度（轮询）：含每步 status/output 与 progress。"""
    d = app.state.ledger.to_dict(job_id)
    if not d:
        raise HTTPException(status_code=404, detail="无此任务")
    return d


@app.post("/v1/agent/job/{job_id}/resume")
async def job_resume_endpoint(job_id: str, request: Request, _: str = Depends(require_api_key)):
    """断点续跑：把崩溃/失败的步骤复位，从断点接着跑（done 步骤跳过）。"""
    raise HTTPException(
        status_code=503,
        detail="本机 CLI 任务执行已关闭：需要独立低权限执行 worker 后才能启用",
    )
    ledger: TaskLedger = app.state.ledger
    job = ledger.to_dict(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="无此任务")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    spec = ledger.get_execution_spec(job_id)
    if spec is None:
        # Legacy jobs have no trustworthy record of the originally approved
        # workdir/backend/mode. Fail closed instead of elevating a new request body
        # into execution authority.
        raise HTTPException(
            status_code=409,
            detail="任务缺少可验证的冻结执行规范，请新建任务",
        )
    approved = _approved_action_record(body, scope="agent_job_resume")
    if approved is not None and approved.get("status") == "revise":
        raise HTTPException(
            status_code=409,
            detail="恢复任务不能用换方案修改已冻结执行规范；请新建任务",
        )
    goal = str(spec["goal"])
    workdir = str(spec["workdir"])
    backend = str(spec["backend"])
    mode = str(spec["mode"])
    uid = str(job.get("user_id") or "owner")
    claim_goal = goal
    frozen_manifest = {
        "job_id": job_id,
        "backend": backend,
        "execution_spec": spec,
    }
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=claim_goal,
        workdir=workdir,
        user_id=uid,
        scope="agent_job_resume",
        mode=mode,
        enforce_task_risk=mode != "plan",
        require_explicit_capability=mode != "plan",
        payload_extra=frozen_manifest,
    )
    if held is not None:
        return held
    try:
        _spawn_job(
            ledger,
            job_id,
            _make_step_executor(
                app.state.router,
                workdir=workdir,
                backend=backend,
                mode=mode,
            ),
        )
    except Exception:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return ledger.to_dict(job_id)


def _agent_run_spec_digest(spec: dict[str, Any]) -> str:
    payload = {k: v for k, v in spec.items() if k != "sha256"}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _freeze_agent_run_spec(
    *,
    task: str,
    workdir: str,
    mode: str,
    model: Any,
    allow: set[str] | None,
    max_steps: int,
    orchestrate: bool,
    deep: bool,
    history: list[Any],
    conversation_id: str,
) -> dict[str, Any]:
    """Canonical execution context shown to approval and replayed server-side."""

    if not task or len(task) > 32_000:
        raise HTTPException(status_code=422, detail="task 为空或超过 32KB")
    try:
        resolved = resolve_workspace(workdir)
    except WorkspaceBoundaryError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if not isinstance(history, list) or len(history) > 64:
        raise HTTPException(status_code=422, detail="history 最多 64 条")
    conversation_id = str(conversation_id or "")
    if len(conversation_id) > 160 or any(ord(ch) < 32 for ch in conversation_id):
        raise HTTPException(status_code=422, detail="conversation_id 无效")
    spec: dict[str, Any] = {
        "schema": 1,
        "task": task,
        "workdir": str(resolved),
        "mode": mode,
        "model": model if isinstance(model, str) and model else None,
        "allow": sorted(allow) if allow is not None else None,
        "max_steps": max(4, min(100, int(max_steps))),
        "orchestrate": bool(orchestrate),
        "deep": bool(deep),
        "history": history,
        "conversation_id": conversation_id,
    }
    try:
        encoded = json.dumps(spec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="history 必须是 JSON 可序列化数据") from exc
    if len(encoded.encode("utf-8")) > 512_000:
        raise HTTPException(status_code=422, detail="Agent 执行上下文超过 512KB")
    # Round-trip removes custom mapping/list subclasses before persistence.
    spec = json.loads(encoded)
    spec["sha256"] = _agent_run_spec_digest(spec)
    return spec


def _validate_agent_run_spec(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise HTTPException(status_code=403, detail="审批记录缺少冻结 Agent 执行规范")
    digest = str(value.get("sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or not secrets.compare_digest(
        digest, _agent_run_spec_digest(value)
    ):
        raise HTTPException(status_code=403, detail="冻结 Agent 执行规范校验失败")
    if (
        value.get("mode") not in {"plan", "auto", "full"}
        or not isinstance(value.get("history"), list)
        or not isinstance(value.get("allow"), (list, type(None)))
        or not isinstance(value.get("task"), str)
        or not isinstance(value.get("workdir"), str)
    ):
        raise HTTPException(status_code=403, detail="冻结 Agent 执行规范字段无效")
    try:
        current_workdir = resolve_workspace(str(value["workdir"]))
    except WorkspaceBoundaryError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if os.path.normcase(str(current_workdir)) != os.path.normcase(str(value["workdir"])):
        raise HTTPException(status_code=403, detail="冻结 workdir 的真实路径已变化")
    return json.loads(json.dumps(value, ensure_ascii=False))


_AGENT_STREAM_DRAIN_TIMEOUT_SECONDS = 2.0
_AGENT_STREAM_DRAINING_TASKS: set[asyncio.Task[Any]] = set()
_AGENT_STREAM_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}")
_AGENT_STREAM_TASK_ID_RE = re.compile(
    r"(?:nvt1_[0-9a-f]{64}|studio:[0-9a-f]{12})"
)


def _agent_stream_token(
    value: Any,
    *,
    pattern: re.Pattern[str],
    fallback: str = "",
) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = value.strip()
    if normalized != value or pattern.fullmatch(normalized) is None:
        return fallback
    if normalized.casefold().startswith(("sk-", "key-", "token-", "bearer-")):
        return fallback
    return normalized


def _agent_stream_model(
    value: Any,
    *,
    allowed_models: frozenset[str],
    fallback: str = "unknown",
) -> str:
    model = _agent_stream_token(
        value,
        pattern=_AGENT_STREAM_MODEL_RE,
        fallback="",
    )
    return model if model in allowed_models else fallback


def _agent_stream_model_allowlist(router: Any) -> frozenset[str]:
    allowed = {"nachuan-engine"}
    try:
        rows = router.list_models()
    except Exception:  # noqa: BLE001 - a diagnostic projection grants no identity
        rows = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            model = _agent_stream_token(
                row.get("id"),
                pattern=_AGENT_STREAM_MODEL_RE,
                fallback="",
            )
            if model:
                allowed.add(model)
    return frozenset(allowed)


def _public_agent_stream_event(
    value: Any,
    *,
    allowed_models: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    """Project internal progress onto a closed, non-secret SSE contract."""

    if not isinstance(value, Mapping):
        return None
    kind = value.get("type")
    if kind == "route":
        difficulty = value.get("difficulty")
        return {
            "type": "route",
            "model": _agent_stream_model(
                value.get("model"), allowed_models=allowed_models
            ),
            "complex": value.get("complex") is True,
            "difficulty": (
                difficulty
                if difficulty in {"easy", "normal", "hard", "simple", "complex"}
                else ""
            ),
        }
    if kind == "plan":
        return {"type": "plan", "plan": "已生成受控执行计划"}
    if kind == "step":
        return {"type": "step", "log": "已完成一个受控步骤"}
    if kind == "verify":
        verified = value.get("verified") is True
        reviewed = value.get("reviewed") is True
        verdict = (
            "机器验证通过"
            if verified
            else ("模型复审通过，尚无机器证据" if reviewed else "尚未通过验收")
        )
        return {
            "type": "verify",
            "verified": verified,
            "reviewed": reviewed,
            "verdict": verdict,
        }
    if kind == "replan":
        return {
            "type": "replan",
            "model": _agent_stream_model(
                value.get("model"), allowed_models=allowed_models
            ),
            "plan": "已根据验收结果重新规划",
        }
    if kind == "escalate":
        return {
            "type": "escalate",
            "from": _agent_stream_model(
                value.get("from"), allowed_models=allowed_models
            ),
            "to": _agent_stream_model(
                value.get("to"), allowed_models=allowed_models
            ),
        }
    if kind == "done":
        outcome = value.get("outcome")
        return {
            "type": "done",
            "verified": value.get("verified") is True,
            "reviewed": value.get("reviewed") is True,
            "model": _agent_stream_model(
                value.get("model"), allowed_models=allowed_models
            ),
            "outcome": outcome if outcome in AGENT_TERMINAL_OUTCOMES else "failed",
        }
    if kind == "pending_video":
        task_id = _agent_stream_token(
            value.get("task_id"), pattern=_AGENT_STREAM_TASK_ID_RE
        )
        if not task_id:
            return None
        return {
            "type": "pending_video",
            "task_id": task_id,
            "model": _agent_stream_model(
                value.get("model"), allowed_models=allowed_models
            ),
        }
    # Internal node/dag/cast/think/work/init/summary/verify_run events contain
    # free-form model, tool, path, or exception text.  They are intentionally
    # not part of the authenticated public progress protocol.
    return None


def _consume_agent_stream_task(task: asyncio.Task[Any]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 - public/log output must not expose the cause
        _REQUEST_LOG.error("agent stream producer cleanup failed")


async def _cancel_and_drain_agent_stream_task(task: asyncio.Task[Any]) -> bool:
    """Cancel a producer and wait for its compensation before closing SSE."""

    if not task.done():
        task.cancel()
    done, pending = await asyncio.wait(
        {task}, timeout=_AGENT_STREAM_DRAIN_TIMEOUT_SECONDS
    )
    if done:
        _consume_agent_stream_task(task)
        return True

    # A cancellation-resistant provider/tool must stay strongly referenced and
    # be drained by the application's finite background registry on shutdown.
    registry = getattr(app.state, "background_tasks", None)
    if isinstance(registry, set):
        registry.add(task)
    _AGENT_STREAM_DRAINING_TASKS.add(task)

    def finish_late(done_task: asyncio.Task[Any]) -> None:
        _AGENT_STREAM_DRAINING_TASKS.discard(done_task)
        if isinstance(registry, set):
            registry.discard(done_task)
        _consume_agent_stream_task(done_task)

    task.add_done_callback(finish_late)
    return False


@app.post("/v1/agent/run")
async def agent_run_endpoint(request: Request, api_key: str = Depends(require_api_key)):
    """通用 Agent 循环（model-agnostic）：任何会 function-calling 的模型用工具（浏览器/文件/命令）完成任务。

    入参：task（必填）、model（默认 bridge_model，可填 agnes-flash/glm/gpt 等任意）、workdir、
    allow（工具名子集，如只给浏览器）、max_steps。浏览器工具驱动 app 右栏内置 webview（需 app 开着）。
    """
    if not current_runtime_profile().allows(
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION
    ):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭受控 Agent 执行；需要独立低权限 worker",
        )

    import os as _os

    body = await request.json()
    s = get_settings()
    approved = _approved_action_record(body, scope="agent_run")
    if approved is not None:
        if approved.get("status") == "revise":
            raise HTTPException(status_code=409, detail="补充要求会改变执行上下文，请重新发起审批")
        spec = _validate_agent_run_spec((approved.get("payload") or {}).get("execution_spec"))
        uid = str(approved.get("user_id") or "owner")
    else:
        task = (body.get("task") or "").strip()
        if not task:
            raise HTTPException(status_code=422, detail="需要 task")
        if body.get("workdir"):
            workdir = str(body["workdir"])
        else:
            workdir = _resolve_workdir(task, str(workspace_root()))
        run_mode = _agent_mode(body)
        allow = _agent_allow(body, run_mode)
        model = body.get("model") or None
        deep = False
        if isinstance(model, str) and model in VIRTUAL_FLEET:
            deep = VIRTUAL_FLEET[model] == "conductor"
            model = None
        try:
            max_steps = int(body.get("max_steps") or 50)
        except (TypeError, ValueError):
            max_steps = 50
        orchestrate = bool(body.get("orchestrate", True))
        conversation_id = str(body.get("conversation_id") or "")
        history = body.get("history") or []
        if not isinstance(history, list):
            raise HTTPException(status_code=422, detail="history 必须是数组")
        history = await conv_summary.rolling_compress(
            app.state.router, conversation_id, list(history)
        )
        try:
            _note, _ = memory_system_note(app.state.memory, s.agent_user_id or "owner", task)
            if _note:
                history = [{"role": "system", "content": _note}] + list(history or [])
        except Exception:  # noqa: BLE001
            pass
        spec = _freeze_agent_run_spec(
            task=task,
            workdir=workdir,
            mode=run_mode,
            model=model,
            allow=allow,
            max_steps=max_steps,
            orchestrate=orchestrate,
            deep=deep,
            history=list(history or []),
            conversation_id=conversation_id,
        )
        uid = str(body.get("user_id") or s.agent_user_id or "owner")

    task = str(spec["task"])
    workdir = str(spec["workdir"])
    run_mode = str(spec["mode"])
    allow = set(spec["allow"]) if spec.get("allow") is not None else None
    model = spec.get("model") or None
    deep = bool(spec.get("deep"))
    max_steps = int(spec["max_steps"])
    orchestrate = bool(spec["orchestrate"])
    history = list(spec.get("history") or [])
    conversation_id = str(spec.get("conversation_id") or "")
    if body.get("approval_id") and bool(body.get("stream")):
        raise HTTPException(status_code=422, detail="审批后的执行请使用非流式请求，以确保一次性凭证可靠收口")
    # 长任务 harness 只在**显式指向了具体工作目录**时开（不是 home 兜底）——那才是"长项目"场景；
    # 纯聊天/无目标的随手活不开，免得往 home 塞 .纳川 状态文件。
    _harness_on = bool(workdir)
    # 显式 model → 编排器尊重之；缺省(None) → 按复杂度自动路由（不再默认便宜 bridge_model）。
    _approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=workdir,
        user_id=uid,
        scope="agent_run",
        mode=run_mode,
        soft_check=False,
        enforce_task_risk=run_mode != "plan",
        require_explicit_capability=(
            run_mode != "plan"
            and (allow is None or not allow.issubset(_READ_ONLY_AGENT_TOOLS))
        ),
        payload_extra={"execution_spec": spec},
    )
    if held is not None:
        return held
    _claimed = bool(_approval_id)
    _inject_principal = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    _author_context = secrets.token_hex(32)
    _write_capable = allow is None or not allow.issubset(_READ_ONLY_AGENT_TOOLS)
    # ── 流式（Phase D）：stream=true 时把编排器的 on_event 进度事件桥接成 SSE，
    #    让前端边做边显示（route/plan/step/verify/replan/escalate/done + 末尾 result/error）。
    #    默认（无 stream）保持原非流式行为，调用方不破。仅编排路径支持流式（扁平循环无事件）。
    if bool(body.get("stream")) and orchestrate:
        stream_model_allowlist = _agent_stream_model_allowlist(app.state.router)

        async def _event_stream():
            queue: asyncio.Queue = asyncio.Queue()

            async def on_event(ev):
                public_event = _public_agent_stream_event(
                    ev,
                    allowed_models=stream_model_allowlist,
                )
                if public_event is not None:
                    await queue.put(public_event)

            async def runner():
                # 运行中插话注入：按 conversation_id 注册队列 + contextvar（深层 run_tool_agent 直接读，
                # 用户任务跑着时 /v1/agent/inject 塞话 → agent 下一步吸收，不打断不排队）。
                _conv = conversation_id
                _tok = steer.conv_id_var.set(_conv)
                _principal_tok = steer.principal_var.set(_inject_principal)
                _author_tok = set_agent_author_context(_author_context)
                _registered = False
                try:
                    steer.register(_conv, _inject_principal, writable=_write_capable)
                    _registered = True
                    if deep:
                        res = await run_conductor_agent(
                            app.state.router, task, workdir=workdir,
                            max_steps=max_steps, allow=allow, history=history, on_event=on_event,
                        )
                    else:
                        res = await run_orchestrated_agent(
                            app.state.router, task, workdir=workdir, model=model,
                            max_steps=max_steps, allow=allow, history=history, on_event=on_event,
                            harness=_harness_on,
                        )
                    try:
                        res = normalize_legacy_agent_result(res)
                    except AgentResultContractError:
                        await queue.put({
                            "type": "error",
                            "code": "invalid_agent_result",
                            "message": "Agent 返回了无效的终态结果",
                        })
                        return
                    _grow_from_terminal_agent_result(app.state.router, task, res)
                    await queue.put(
                        {
                            "type": "result",
                            "result": project_public_agent_result(
                                res,
                                file_change_validator=undo_receipts.verify_projection,
                            ),
                        }
                    )
                except Exception:  # noqa: BLE001
                    await queue.put({
                        "type": "error",
                        "code": "agent_execution_failed",
                        "message": "Agent 执行失败，请稍后重试",
                    })
                finally:
                    if _registered:
                        steer.unregister(_conv, _inject_principal)
                    steer.conv_id_var.reset(_tok)
                    steer.principal_var.reset(_principal_tok)
                    reset_agent_author_context(_author_tok)
                    await queue.put(None)  # 哨兵：结束流

            t = asyncio.create_task(runner())
            _start = time.monotonic()
            _last_real = _start  # 最后一次"真事件/真进展"的时间（心跳不算）
            # 流式侧只兜"彻底没动静"（10 分钟无真事件判卡死）；**总时长天花板在 agent 循环内部**
            # （tool_agent wall_deadline，默认 45 分钟、NACHUAN_AGENT_WALL_MIN 可调）——
            # 步数闸+停滞检测认不出"慢速空转"（机主实测 422 分钟失控），墙钟才是可靠总闸。
            _STALL_CAP = 10 * 60
            try:
                while True:
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=25.0)
                    except asyncio.TimeoutError:
                        # 25s 没真事件 → 发心跳保活（前端 feed() 重置空转计时、不显示）；
                        # 但若"很久没有任何真进展"→ 判卡死停（不按总时长砍：在推进就随便跑多久）。
                        if time.monotonic() - _last_real > _STALL_CAP:
                            if not t.done():
                                t.cancel()
                            yield {"type": "error",
                                   "message": f"任务已 {_STALL_CAP // 60} 分钟没有任何进展，判定卡住、已停止（可重试或换个模型）。"}
                            break
                        yield {"type": "heartbeat", "elapsed": int(time.monotonic() - _start)}
                        continue
                    _last_real = time.monotonic()  # 收到真事件 → 刷新"最后进展时间"
                    if ev is None:
                        break
                    yield ev
            finally:
                await _cancel_and_drain_agent_stream_task(t)

        return StreamingResponse(
            sse_encode(_event_stream()),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    def _grew(res: dict[str, Any]) -> dict[str, Any]:
        """④成长回写：编排/循环结束后从 (task, reply) 抽取存长期记忆（吞异常，失败不影响返回）。"""
        try:
            res = normalize_legacy_agent_result(res)
        except AgentResultContractError as exc:
            raise HTTPException(
                status_code=502,
                detail={"code": "invalid_agent_result", "retryable": False},
                headers={"Cache-Control": "no-store"},
            ) from exc
        _grow_from_terminal_agent_result(app.state.router, task, res)
        return project_public_agent_result(
            res,
            file_change_validator=undo_receipts.verify_projection,
        )

    async def _execute_agent_once() -> dict[str, Any]:
        if orchestrate:
            # 编排型 super-agent：路由→(复杂则)规划→带工具执行→跨厂验证→不过升级重跑。
            if deep:  # 舰队 ultra 号 → Conductor 深编排（工作流 DAG）
                return _grew(await run_conductor_agent(
                    app.state.router,
                    task,
                    workdir=workdir,
                    max_steps=max_steps,
                    allow=allow,
                    history=history,
                ))
            else:
                return _grew(await run_orchestrated_agent(
                    app.state.router,
                    task,
                    workdir=workdir,
                    model=model,
                    max_steps=max_steps,
                    allow=allow,
                    history=history,
                    harness=_harness_on,
                ))
        else:
            return _grew(await run_tool_agent(
                app.state.router,
                model or s.bridge_model,
                task,
                workdir=workdir,
                allow=allow,
                max_steps=max_steps,
                history=history,
            ))

    _author_tok = set_agent_author_context(_author_context)
    try:
        result = await _execute_agent_once()
    except Exception:
        if _claimed:
            app.state.approvals.finish_action(_approval_id, success=False)
        raise
    finally:
        reset_agent_author_context(_author_tok)
    if _claimed:
        app.state.approvals.finish_action(_approval_id, success=True)
    return result


@app.post("/v1/agent/inject")
async def agent_inject_endpoint(request: Request, api_key: str = Depends(require_api_key)):
    """运行中插话（steering）：agent 长任务跑着时把用户的话注入循环——任务不打断、
    下一步动作前吸收（机主定案：插话=补充信息，不是砍任务）。
    返回 {injected}：false=该对话当前没有运行中任务，前端应走普通发送/排队。"""
    if not current_runtime_profile().allows(
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION
    ):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭受控 Agent 执行；需要独立低权限 worker",
        )
    body = await request.json()
    principal = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    ok = steer.push(
        str(body.get("conversation_id") or ""),
        str(body.get("message") or ""),
        principal,
    )
    return {"injected": ok}


@app.post("/v1/agent/undo")
async def agent_undo_endpoint(request: Request, _: str = Depends(require_api_key)):
    """Consume a server-issued one-time receipt and restore its exact pre-image."""
    if not current_runtime_profile().allows(
        RuntimeCapability.CONTROLLED_AGENT_EXECUTION
    ):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭受控 Agent 执行；需要独立低权限 worker",
        )
    body = await request.json()
    receipt = str(body.get("receipt") or "")
    if not receipt:
        # Legacy path/content was an authenticated arbitrary-write primitive.
        raise HTTPException(status_code=410, detail="旧版任意路径撤销接口已停用；需要服务端签发的 receipt")
    content = str(body.get("content") or "")
    try:
        result = undo_receipts.restore(receipt, content)
    except UndoReceiptError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"ok": True, **result}


@app.post("/v1/audio/transcriptions")
async def transcribe_audio(
    request: Request,
    language: str | None = None,
    _: str = Depends(require_bridge_or_api_key),
):
    """语音转文字（D1·本地 faster-whisper，免费离线）。请求体=音频字节；?language=zh 可选（默认自动）。"""
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="需要音频数据（请求体）")
    try:
        text = await run_in_threadpool(audio_mod.transcribe, data, language)
    except AudioUnavailable:
        raise HTTPException(
            status_code=503,
            detail="语音转写暂不可用；请检查本地模型与已锁定语音引擎",
        )
    return {"text": text}


@app.get("/v1/audio/model")
async def get_audio_model(_: str = Depends(require_api_key)):
    """当前语音转写模型档 + 可选项。"""
    return {"model": audio_mod.current_model_name(), "options": list(audio_mod.WHISPER_MODELS)}


@app.post("/v1/audio/model")
async def set_audio_model(request: Request, _: str = Depends(require_api_key)):
    """切换语音转写模型档（tiny 最快 / base 均衡 / small 最准）。切完后台预热新档。"""
    body = await request.json()
    name = str(body.get("model") or "")
    if not audio_mod.set_model(name):
        raise HTTPException(
            status_code=422, detail=f"无效档位；可选：{', '.join(audio_mod.WHISPER_MODELS)}"
        )
    import threading

    threading.Thread(target=audio_mod.warm, daemon=True).start()
    return {"model": audio_mod.current_model_name()}


@app.post("/v1/translate")
async def translate_endpoint(request: Request, _: str = Depends(require_api_key)):
    """实时翻译（D2·走自家免费模型）。入参 text、target(语种码/名)；model 可选（默认免费 Agnes）。"""
    router: Router = app.state.router
    body = await request.json()
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="需要 text")
    target = str(body.get("target") or body.get("target_lang") or "en")
    model = str(
        body.get("model")
        or ("agnes-flash" if router.resolve("agnes-flash") else (pick_model(router, "cheap") or get_settings().bridge_model))
    )
    try:
        return JSONResponse(await translate(router, text=text, target=target, model=model))
    except ProviderError as e:
        raise _public_provider_http_error(e) from e


_CHANNEL_VISION_DEFAULT_QUESTION = (
    "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。"
)
_CHANNEL_VISION_RESULT_RESERVATION_BYTES = 1024 * 1024
_CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES = 8 * 1024 * 1024
_CHANNEL_MEDIA_HEARTBEAT_MAX_INTERVAL_SECONDS = 30.0
_BRIDGE_CHANNEL_CREDENTIALS = frozenset({"bridge:feishu", "bridge:weixin"})


def _decode_bridge_channel_media(
    data: bytes,
    *,
    credential: str,
    operation: str,
    expected_params: dict[str, Any],
) -> ChannelMediaFrame | None:
    if credential not in _BRIDGE_CHANNEL_CREDENTIALS:
        return None
    try:
        frame = decode_channel_media_frame(data)
    except ChannelMediaFrameError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_channel_media_frame", "retryable": False},
        ) from exc
    if credential != f"bridge:{frame.channel}":
        raise HTTPException(
            status_code=403,
            detail={"code": "channel_media_credential_mismatch", "retryable": False},
        )
    if frame.operation != operation or frame.params != expected_params:
        raise HTTPException(
            status_code=422,
            detail={"code": "channel_media_semantic_mismatch", "retryable": False},
        )
    return frame


async def _claim_bridge_channel_media(
    frame: ChannelMediaFrame,
    *,
    max_success_bytes: int,
) -> tuple[DurableChannelMediaRequestStore, DurableMediaRequestClaim]:
    await _refresh_waiting_channel_media_authority()
    store = getattr(app.state, "channel_media_requests", None)
    if not isinstance(store, DurableChannelMediaRequestStore):
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_store_unavailable", "retryable": True},
        )
    identity = recompute_channel_media_identity(frame)
    try:
        claim = await run_in_threadpool(
            store.claim,
            channel=frame.channel,
            operation=frame.operation,
            message_key=frame.message_key,
            principal_hash=identity.principal_hash,
            request_sha256=identity.request_sha256,
            max_success_bytes=max_success_bytes,
        )
    except (OSError, DurableMediaRequestUnavailable) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_store_unavailable", "retryable": True},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_channel_media_identity", "retryable": False},
        ) from exc
    if claim.state == "conflict":
        raise HTTPException(
            status_code=409,
            detail={"code": "channel_media_idempotency_conflict", "retryable": False},
        )
    if claim.state == "processing":
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_in_progress", "retryable": True},
            headers={"Retry-After": str(max(1, claim.retry_after_seconds))},
        )
    if claim.state == "recovery_required":
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_recovery_required", "retryable": False},
        )
    if claim.state == "result_expired":
        raise HTTPException(
            status_code=410,
            detail={"code": "channel_media_result_expired", "retryable": False},
        )
    if claim.state not in {"claimed", "succeeded"}:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_state_invalid", "retryable": False},
        )
    return store, claim


async def _enter_channel_media_provider_phase(
    store: DurableChannelMediaRequestStore,
    claim: DurableMediaRequestClaim,
    *,
    max_success_bytes: int,
) -> None:
    async def assert_packaged_provider_authority() -> None:
        authority = getattr(app.state, "channel_media_authority", None)
        if not isinstance(authority, Mapping) or not bool(
            authority.get("packaged")
        ):
            return
        controller = getattr(
            app.state, "channel_media_installation_control", None
        )
        if controller is None:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "channel_media_authority_unavailable",
                    "retryable": False,
                },
            )
        try:
            observed = await run_in_threadpool(
                controller.assert_provider_dispatch_ready
            )
            attached_store = controller.store
        except Exception as exc:  # noqa: BLE001 -- provider seam is fail-closed
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "channel_media_authority_unavailable",
                    "retryable": False,
                },
            ) from exc
        paid_installation_id = getattr(
            app.state, "paid_media_installation_id", None
        )
        paid_epoch = getattr(app.state, "paid_media_epoch", None)
        if (
            observed.mode != "ready"
            or not bool(observed.provider_dispatch_ready)
            or observed.installation_id != paid_installation_id
            or observed.epoch != paid_epoch
            or attached_store is not store
        ):
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "channel_media_authority_unavailable",
                    "retryable": False,
                },
            )

    await assert_packaged_provider_authority()
    try:
        entered = await run_in_threadpool(
            store.enter_provider_phase,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            max_success_bytes=max_success_bytes,
        )
    except DurableMediaRequestUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_fence_unavailable", "retryable": True},
        ) from exc
    if not entered:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_fence_lost", "retryable": True},
        )
    # The local mutation advances Root through the controller hook.  Re-prove
    # the resulting exact snapshot at the final seam before network dispatch.
    await assert_packaged_provider_authority()


async def _abandon_channel_media_pre_provider(
    store: DurableChannelMediaRequestStore,
    claim: DurableMediaRequestClaim,
) -> None:
    try:
        abandoned = await run_in_threadpool(
            store.abandon_pre_provider,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
    except DurableMediaRequestUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_abandon_unavailable", "retryable": True},
        ) from exc
    if not abandoned:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_abandon_conflict", "retryable": True},
        )


async def _persist_channel_media_success(
    store: DurableChannelMediaRequestStore,
    claim: DurableMediaRequestClaim,
    response: dict[str, Any],
) -> dict[str, Any]:
    try:
        persisted = await run_in_threadpool(
            store.succeed,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            response=response,
        )
    except (DurableMediaRequestUnavailable, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_receipt_unavailable", "retryable": False},
        ) from exc
    if not persisted:
        raise HTTPException(
            status_code=503,
            detail={"code": "channel_media_receipt_lost", "retryable": False},
        )
    return response


async def _channel_media_heartbeat_loop(
    store: DurableChannelMediaRequestStore,
    claim: DurableMediaRequestClaim,
    lost: asyncio.Event,
) -> None:
    interval = max(
        0.001,
        min(
            _CHANNEL_MEDIA_HEARTBEAT_MAX_INTERVAL_SECONDS,
            store.lease_seconds / 3.0,
        ),
    )
    while True:
        await asyncio.sleep(interval)
        try:
            owned = await run_in_threadpool(
                store.heartbeat,
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 -- any uncertain lease is a lost fence
            owned = False
        if not owned:
            lost.set()
            return


async def _await_channel_media_provider(
    store: DurableChannelMediaRequestStore,
    claim: DurableMediaRequestClaim,
    provider_call: Any,
) -> Any:
    lost = asyncio.Event()
    provider_task = asyncio.create_task(provider_call)
    heartbeat_task = asyncio.create_task(
        _channel_media_heartbeat_loop(store, claim, lost)
    )
    lost_task = asyncio.create_task(lost.wait())
    try:
        done, _pending = await asyncio.wait(
            {provider_task, lost_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if lost_task in done and lost_task.result():
            provider_task.cancel()
            await asyncio.gather(provider_task, return_exceptions=True)
            raise HTTPException(
                status_code=503,
                detail={"code": "channel_media_lease_lost", "retryable": False},
            )
        return await provider_task
    finally:
        if not provider_task.done():
            provider_task.cancel()
        await asyncio.gather(provider_task, return_exceptions=True)
        heartbeat_task.cancel()
        lost_task.cancel()
        await asyncio.gather(heartbeat_task, lost_task, return_exceptions=True)


@app.post("/v1/vision")
async def vision_endpoint(
    request: Request,
    question: str | None = None,
    model: str | None = None,
    credential: str = Depends(require_bridge_or_api_key),
):
    """看图理解 / OCR（#28）：API raw bytes；bridge uses a sealed durable frame."""
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="需要图片数据（请求体）")
    normalized_question = question or _CHANNEL_VISION_DEFAULT_QUESTION
    frame = _decode_bridge_channel_media(
        data,
        credential=credential,
        operation="vision.describe",
        expected_params={"question": normalized_question, "model": model or ""},
    )
    if frame is None:
        text = await describe_image(
            app.state.router,
            data,
            question=normalized_question,
            model=model,
        )
        if not text:
            raise HTTPException(status_code=503, detail="没有可用的视觉模型，或识别失败")
        return {"text": text}

    store, claim = await _claim_bridge_channel_media(
        frame,
        max_success_bytes=_CHANNEL_VISION_RESULT_RESERVATION_BYTES,
    )
    if claim.state == "succeeded":
        if not isinstance(claim.response, dict):
            raise HTTPException(
                status_code=503,
                detail={"code": "channel_media_receipt_corrupt", "retryable": False},
            )
        return claim.response
    try:
        selected_model = pick_vision_model(app.state.router, model)
    except BaseException:
        await _abandon_channel_media_pre_provider(store, claim)
        raise
    if not selected_model:
        await _abandon_channel_media_pre_provider(store, claim)
        raise HTTPException(status_code=503, detail="没有可用的视觉模型，或识别失败")
    await _enter_channel_media_provider_phase(
        store,
        claim,
        max_success_bytes=_CHANNEL_VISION_RESULT_RESERVATION_BYTES,
    )
    with bind_provider_call_scope(
        turn_id=claim.turn_id,
        workflow_id=f"{frame.channel}:vision.describe",
        role="channel-media",
    ):
        text = await _await_channel_media_provider(
            store,
            claim,
            describe_image(
                app.state.router,
                frame.raw,
                question=normalized_question,
                model=selected_model,
            ),
        )
    if not text:
        raise HTTPException(status_code=503, detail="没有可用的视觉模型，或识别失败")
    return await _persist_channel_media_success(store, claim, {"text": text})


@app.post("/v1/lapian")
async def lapian_endpoint(
    request: Request,
    vision_model: str = "agnes-flash",
    synth_model: str | None = None,
    max_frames: int = 40,
    with_audio: bool = True,
    credential: str = Depends(require_bridge_or_api_key),
):
    """拉片（#29）：请求体=视频字节 → 抽帧+逐帧看图(+台词转写) → 拉片报告+复现SOP。

    ?vision_model=（默认 agnes-flash 免费快；难片可 gpt-5.4）&synth_model=&max_frames=&with_audio=
    """
    import os
    import tempfile

    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="需要视频数据（请求体）")
    frame = _decode_bridge_channel_media(
        data,
        credential=credential,
        operation="lapian.analyze",
        expected_params={
            "vision_model": vision_model,
            "synth_model": synth_model or "",
            "max_frames": max_frames,
            "with_audio": with_audio,
        },
    )
    store: DurableChannelMediaRequestStore | None = None
    claim: DurableMediaRequestClaim | None = None
    payload = data
    if frame is not None:
        store, claim = await _claim_bridge_channel_media(
            frame,
            max_success_bytes=_CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES,
        )
        if claim.state == "succeeded":
            if not isinstance(claim.response, dict):
                raise HTTPException(
                    status_code=503,
                    detail={"code": "channel_media_receipt_corrupt", "retryable": False},
                )
            return claim.response
        payload = frame.raw
        try:
            selected_vision_model = pick_vision_model(app.state.router, vision_model)
        except BaseException:
            await _abandon_channel_media_pre_provider(store, claim)
            raise
        if not selected_vision_model:
            await _abandon_channel_media_pre_provider(store, claim)
            raise HTTPException(
                status_code=503,
                detail={"code": "channel_media_vision_unavailable", "retryable": True},
            )
        vision_model = selected_vision_model
    fd, path = tempfile.mkstemp(suffix=".mp4", prefix="lapian_in_")
    os.close(fd)
    provider_started = False
    preprovider_abandoned = False
    heartbeat_lost = asyncio.Event()
    heartbeat_task: asyncio.Task[None] | None = None

    async def before_provider() -> None:
        nonlocal heartbeat_task, provider_started
        if provider_started or store is None or claim is None:
            return
        await _enter_channel_media_provider_phase(
            store,
            claim,
            max_success_bytes=_CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES,
        )
        provider_started = True
        heartbeat_task = asyncio.create_task(
            _channel_media_heartbeat_loop(store, claim, heartbeat_lost)
        )

    async def abandon_before_provider() -> None:
        nonlocal preprovider_abandoned
        if (
            preprovider_abandoned
            or provider_started
            or store is None
            or claim is None
        ):
            return
        await _abandon_channel_media_pre_provider(store, claim)
        preprovider_abandoned = True

    try:
        with open(path, "wb") as f:
            f.write(payload)
        scope = (
            bind_provider_call_scope(
                turn_id=claim.turn_id,
                workflow_id=f"{frame.channel}:lapian.analyze",
                role="channel-media",
            )
            if frame is not None and claim is not None
            else bind_provider_call_scope()
        )
        with scope:
            run_task = asyncio.create_task(
                run_lapian(
                    app.state.router,
                    path,
                    vision_model=vision_model,
                    synth_model=synth_model,
                    max_frames=max_frames,
                    with_audio=with_audio,
                    before_provider=before_provider if frame is not None else None,
                )
            )
            lost_task = asyncio.create_task(heartbeat_lost.wait())
            try:
                done, _pending = await asyncio.wait(
                    {run_task, lost_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if lost_task in done and lost_task.result():
                    run_task.cancel()
                    await asyncio.gather(run_task, return_exceptions=True)
                    raise HTTPException(
                        status_code=503,
                        detail={
                            "code": "channel_media_lease_lost",
                            "retryable": False,
                        },
                    )
                res = await run_task
            finally:
                if not run_task.done():
                    run_task.cancel()
                await asyncio.gather(run_task, return_exceptions=True)
                lost_task.cancel()
                if heartbeat_task is not None:
                    heartbeat_task.cancel()
                    await asyncio.gather(heartbeat_task, return_exceptions=True)
                await asyncio.gather(lost_task, return_exceptions=True)
        if res.get("error"):
            await abandon_before_provider()
            status = 503 if res.get("unavailable") is True and res.get("status_code") == 503 else 502
            raise HTTPException(status_code=status, detail=res["error"])
        if store is not None and claim is not None:
            if not provider_started:
                await abandon_before_provider()
                raise HTTPException(
                    status_code=503,
                    detail={"code": "channel_media_provider_fence_missing", "retryable": True},
                )
            return await _persist_channel_media_success(store, claim, res)
        return res
    except BaseException:
        await abandon_before_provider()
        raise
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


_LAPIAN_OFFICIAL_HOSTS = frozenset({
    "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
    "bilibili.com", "www.bilibili.com", "b23.tv",
    "douyin.com", "www.douyin.com", "v.douyin.com", "iesdouyin.com",
    "vimeo.com", "www.vimeo.com", "player.vimeo.com",
    "ixigua.com", "www.ixigua.com",
    "kuaishou.com", "www.kuaishou.com", "v.kuaishou.com",
    "xiaohongshu.com", "www.xiaohongshu.com", "xhslink.com",
    "weibo.com", "www.weibo.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
})
_LAPIAN_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
_LAPIAN_YTDLP_RISK_ENV = "NACHUAN_ENABLE_UNPINNED_YTDLP"
_LAPIAN_YTDLP_RISK_ACCEPT = "I_ACCEPT_UNPINNED_YTDLP_NETWORK"


def _lapian_ytdlp_enabled() -> bool:
    """Fail closed unless an operator accepts yt-dlp's unpinned network boundary."""

    if not current_runtime_profile().allows(RuntimeCapability.PLUGIN_AUTO_DISCOVERY):
        return False
    return os.getenv(_LAPIAN_YTDLP_RISK_ENV, "") == _LAPIAN_YTDLP_RISK_ACCEPT


def _safe_lapian_url(url: str) -> bool:
    """Accept only exact, reviewed HTTPS origins before the explicit risk opt-in."""

    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or "\\" in parsed.netloc
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)
        ):
            return False
        if parsed.port not in (None, 443):
            return False
        host = parsed.hostname.lower()
        if host not in _LAPIAN_OFFICIAL_HOSTS:
            return False
    except (UnicodeError, ValueError):
        return False
    # This is intentionally only a pre-check: yt-dlp resolves and follows its
    # own extractor/CDN URLs, hence the separate, loudly named development opt-in.
    return is_public_http_url(url)


def _attested_ytdlp_ffmpeg_location() -> str:
    """Require independently attested ffmpeg and ffprobe in one closed directory."""

    ffmpeg = require_media_binary("ffmpeg")
    ffprobe = require_media_binary("ffprobe")
    ffmpeg_dir = os.path.normcase(os.path.abspath(os.path.dirname(ffmpeg.path)))
    ffprobe_dir = os.path.normcase(os.path.abspath(os.path.dirname(ffprobe.path)))
    if ffmpeg_dir != ffprobe_dir:
        raise MediaBinaryUnavailable(
            "yt-dlp 不可用：经认证的 ffmpeg 与 ffprobe 必须位于同一目录"
        )
    return ffmpeg_dir


def _ytdlp_download(url: str, out_tmpl: str) -> tuple[str, str]:
    """Development-only unpinned download with plugins and executable discovery off."""
    import glob

    if not _safe_lapian_url(url):
        return "", "仅允许固定官方站点的公网 HTTPS 视频 URL（仅默认 443 端口）"
    if not _lapian_ytdlp_enabled():
        return "", (
            "网址拉片默认关闭；仅开发环境可显式设置 "
            f"{_LAPIAN_YTDLP_RISK_ENV}={_LAPIAN_YTDLP_RISK_ACCEPT} 接受未固定网络风险"
        )
    ffmpeg_location = _attested_ytdlp_ffmpeg_location()
    # yt-dlp checks this environment variable while importing its plugin layer.
    # Assign the exact disabling value before the first import, never inherit an
    # operator-provided empty value.
    os.environ["YTDLP_NO_PLUGINS"] = "1"
    try:
        import yt_dlp
    except ImportError:
        return "", "未安装 yt-dlp"
    base = {
        "outtmpl": out_tmpl, "quiet": True, "no_warnings": True,
        "format": "mp4[height<=720]/best[height<=720]/best",
        "merge_output_format": "mp4", "noplaylist": True,
        "max_filesize": _LAPIAN_MAX_DOWNLOAD_BYTES,
        "socket_timeout": 20,
        "retries": 2,
        "fragment_retries": 2,
        "js_runtimes": {},
        "remote_components": set(),
        "cachedir": False,
        "external_downloader": {},
        "external_downloader_args": {},
        "ffmpeg_location": ffmpeg_location,
    }
    err = ""
    try:
        with yt_dlp.YoutubeDL(base) as ydl:
            ydl.download([url])
    except Exception as exc:  # noqa: BLE001
        err = str(exc)[:300]
    files = glob.glob(out_tmpl.replace("%(ext)s", "*"))
    if files:
        try:
            if os.path.getsize(files[0]) > _LAPIAN_MAX_DOWNLOAD_BYTES:
                return "", "视频超过 512MB 安全上限"
        except OSError:
            return "", "下载结果不可读"
    return (files[0] if files else "", err)


async def lapian_url_report(
    router: Any,
    url: str,
    *,
    vision_model: str = "agnes-flash",
    synth_model: Any = None,
    max_frames: int = 40,
    with_audio: bool = True,
) -> dict[str, Any]:
    """拉片·网址版内部函数：抠链接 → yt-dlp 下载 → run_lapian 出报告。

    抽出供 /v1/lapian/url 端点与 tool_agent 的 lapian 工具共用。返回 run_lapian 结果 dict
    （含 report/analyses…）或 {error}；下载失败也走 {error}，绝不抛（工具调用方友好化）。
    """
    import os as _os
    import re as _re
    import shutil
    import tempfile

    url = str(url or "").strip()
    if not url:
        return {"error": "需要 url"}
    # 容错：用户常直接粘贴分享口令文本（如抖音「5.89 复制打开抖音…https://v.douyin.com/xxx kcN:/ w@F.hB」），
    # 从中抠出第一个真链接喂给 yt-dlp，否则整段被当 URL 报 "is not a valid URL"。
    _m = _re.search(r"https?://[^\s，。、）)\]】「」'\"]+", url)
    if _m:
        url = _m.group(0).rstrip("，。、）)】],.;")
    if not _safe_lapian_url(url):
        return {
            "error": "仅允许固定官方站点的公网 HTTPS 视频 URL（仅默认 443 端口）",
            "unsafe_url": True,
        }
    if not _lapian_ytdlp_enabled():
        return {
            "error": (
                "网址拉片默认关闭；仅开发环境可显式设置 "
                f"{_LAPIAN_YTDLP_RISK_ENV}={_LAPIAN_YTDLP_RISK_ACCEPT} "
                "接受 yt-dlp 未固定网络风险"
            ),
            "unavailable": True,
            "status_code": 503,
        }
    max_frames = max(1, min(80, int(max_frames)))
    tmpdir = tempfile.mkdtemp(prefix="lapian_url_")
    try:
        try:
            path, dl_err = await run_in_threadpool(
                _ytdlp_download,
                url,
                _os.path.join(tmpdir, "v.%(ext)s"),
            )
        except MediaBinaryUnavailable as exc:
            return {
                "error": str(exc),
                "unavailable": True,
                "status_code": 503,
            }
        if not path:
            return {"error": "下载失败：" + (dl_err or "网址不支持/网络/需登录")}
        return await run_lapian(
            router, path,
            vision_model=vision_model,
            synth_model=synth_model,
            max_frames=max_frames,
            with_audio=with_audio,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/v1/lapian/url")
async def lapian_url_endpoint(request: Request, _: str = Depends(require_api_key)):
    """拉片·网址版：默认关闭；显式开发风险开关后仅接受固定官方 HTTPS URL。"""
    body = await request.json()
    url = str(body.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=422, detail="需要 url")
    res = await lapian_url_report(
        app.state.router, url,
        vision_model=str(body.get("vision_model") or "agnes-flash"),
        synth_model=body.get("synth_model"),
        max_frames=max(1, min(80, int(body.get("max_frames") or 40))),
        with_audio=bool(body.get("with_audio", True)),
    )
    if res.get("error"):
        if res.get("unsafe_url"):
            status = 422
        elif res.get("unavailable") is True and res.get("status_code") == 503:
            status = 503
        else:
            status = 502
        raise HTTPException(status_code=status, detail=res["error"])
    return res


@app.get("/v1/mcp")
async def mcp_list(_: str = Depends(require_api_key)):
    """List MCP definitions without exposing plaintext legacy env values."""
    servers = mcp_registry.public_servers()
    raw = mcp_registry.list_servers()
    status = {name: mcp_registry.probe(spec) for name, spec in raw.items()}
    return {
        "enabled": mcp_registry.verified_mcp_enabled(),
        "mcpServers": servers,
        "status": status,
    }


@app.get("/v1/mcp/presets")
async def mcp_presets(_: str = Depends(require_api_key)):
    """常用 MCP server 预设（#20）：一键挂载，附本机运行时是否就绪。"""
    return {
        "presets": [
            {
                **p,
                # Historical presets depended on mutable npx/uvx resolution and
                # remain documentation-only until an operator supplies a
                # reviewed local binary and its digest.
                "available": False,
                "audited": False,
            }
            for p in mcp_registry.PRESETS
        ]
    }


@app.post("/v1/mcp")
async def mcp_add(request: Request, _: str = Depends(require_api_key)):
    """Register one hash-attested local MCP executable after exact approval."""
    if not current_runtime_profile().allows(RuntimeCapability.MCP_PLUGIN_REGISTRY):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭 MCP 注册表；需要独立低权限 worker",
        )
    if not mcp_registry.verified_mcp_enabled():
        raise HTTPException(
            status_code=403,
            detail="可信 MCP 默认关闭；运维验收本地二进制后方可启用",
        )
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="需要 name")
    command = str(body.get("command") or "").strip()
    args = [str(v) for v in (body.get("args") or [])]
    sha256 = str(body.get("sha256") or "").strip().lower()
    if not command or body.get("url"):
        raise HTTPException(status_code=422, detail="只允许登记哈希证明的本地 stdio MCP")
    if body.get("env"):
        raise HTTPException(status_code=422, detail="禁止把 MCP 密钥作为明文 env 保存")
    candidate = {"command": command, "args": args, "sha256": sha256}
    attestation = mcp_registry.probe(candidate)
    if not attestation.get("ok"):
        raise HTTPException(
            status_code=422,
            detail=str(attestation.get("detail") or "MCP 证明无效"),
        )
    task = str(body.get("task") or f"登记并启用哈希证明 MCP：{name}")
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=str(PROJECT_ROOT),
        user_id=str(body.get("user_id") or get_settings().agent_user_id or "owner"),
        scope="mcp_add",
        mode="full",
        require_explicit_capability=True,
        payload_extra={
            "name": name,
            "command": command,
            "args": args,
            "sha256": sha256,
        },
    )
    if held is not None:
        return held
    try:
        servers = mcp_registry.add_server(
            name, command=command, args=args, sha256=sha256
        )
    except ValueError as exc:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "mcpServers": servers, "probe": mcp_registry.probe(servers.get(name, {}))}


@app.delete("/v1/mcp/{name}")
async def mcp_remove(name: str, _: str = Depends(require_api_key)):
    """Legacy mutation contract had no approval body; use the scoped POST route."""
    del name
    raise HTTPException(status_code=410, detail="请使用 POST /v1/mcp/{name}/remove 走一次性审批")


@app.post("/v1/mcp/{name}/remove")
async def mcp_remove_approved(name: str, request: Request, _: str = Depends(require_api_key)):
    if not current_runtime_profile().allows(RuntimeCapability.MCP_PLUGIN_REGISTRY):
        raise HTTPException(
            status_code=503,
            detail="当前运行配置已关闭 MCP 注册表；需要独立低权限 worker",
        )
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    current = mcp_registry.list_servers().get(name)
    if not isinstance(current, dict):
        raise HTTPException(status_code=404, detail="MCP server 不存在")
    task = str(body.get("task") or f"移除 MCP：{name}")
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=str(PROJECT_ROOT),
        user_id=str(body.get("user_id") or get_settings().agent_user_id or "owner"),
        scope="mcp_remove",
        mode="full",
        require_explicit_capability=True,
        payload_extra={"name": name, "spec": current},
    )
    if held is not None:
        return held
    try:
        servers = mcp_registry.remove_server(name)
    except Exception:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "mcpServers": servers}


def _media_http_error(
    status_code: int,
    *,
    code: str,
    message: str,
    retryable: bool,
    headers: dict[str, str] | None = None,
) -> HTTPException:
    safe_headers = {"Cache-Control": "no-store"}
    if headers:
        safe_headers.update(headers)
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message, "retryable": retryable},
        headers=safe_headers,
    )


def _safe_media_provider_status(value: object) -> int:
    try:
        status_code = int(value)
    except (TypeError, ValueError, OverflowError):
        return 502
    return status_code if 400 <= status_code <= 599 else 502


def _media_provider_poll_retryable(status_code: int) -> bool:
    """Only transient HTTP classes may invite another idempotent provider GET."""

    return status_code in {408, 429} or 500 <= status_code <= 599


def _invalid_media_idempotency_key_error() -> HTTPException:
    return _media_http_error(
        422,
        code="invalid_idempotency_key",
        message="A stable Idempotency-Key is required for paid media creation.",
        retryable=False,
    )


def _required_media_idempotency_key(value: object) -> str:
    try:
        return validate_media_idempotency_key(value)
    except ValueError as exc:
        raise _invalid_media_idempotency_key_error() from exc


_PAID_ACTIVATION_RECONCILE_LOCK = threading.Lock()
_CHANNEL_ACTIVATION_RECONCILE_LOCK = threading.Lock()


def _paid_media_control_pair_identity_is_consistent(
    gateway_state: Any,
    asset_state: Any,
    installation_id: object,
    epoch: object,
) -> bool:
    """Compare only the closed installation/epoch identity shared by both stores."""

    return (
        isinstance(installation_id, str)
        and re.fullmatch(r"[0-9a-f]{64}", installation_id) is not None
        and not isinstance(epoch, bool)
        and isinstance(epoch, int)
        and epoch >= 1
        and getattr(gateway_state, "installation_id", None) == installation_id
        and getattr(gateway_state, "epoch", None) == epoch
        and getattr(asset_state, "installation_id", None) == installation_id
        and getattr(asset_state, "epoch", None) == epoch
    )


def _reconcile_waiting_paid_media_authority(
    control: Any,
    asset_control: Any,
) -> tuple[Any, Any, Any | None, Any | None]:
    """Singleflight both Root-v4 controllers entirely off the event loop."""

    with _PAID_ACTIVATION_RECONCILE_LOCK:
        gateway_state = control.state
        asset_state = asset_control.state
        if gateway_state.mode == "provisioned_not_active":
            gateway_state = control.reconcile_startup()
        if asset_state.mode == "provisioned_not_active":
            asset_state = asset_control.reconcile_startup()
        if (
            gateway_state.mode == "provisioned_not_active"
            or asset_state.mode == "provisioned_not_active"
        ):
            return gateway_state, asset_state, None, None
        if gateway_state.mode not in {"ready", "manual_only"}:
            raise GatewayInstallationControlUnavailable(
                "gateway controller is not read capable"
            )
        if asset_state.mode not in {"ready", "manual_only"}:
            raise AssetInstallationControlUnavailable(
                "asset controller is not read capable"
            )
        return gateway_state, asset_state, control.store, asset_control.store


async def _refresh_waiting_paid_media_authority() -> None:
    """Reconcile a same-process Desktop bind without creating any authority."""

    if (
        getattr(app.state, "media_requests", None) is not None
        and getattr(app.state, "paid_media_assets", None) is not None
    ):
        return
    if str(getattr(app.state, "paid_media_authority_mode", "") or "") != (
        "installation-root"
    ):
        return
    control = getattr(app.state, "installation_root_control", None)
    asset_control = getattr(app.state, "asset_installation_control", None)
    if control is None or asset_control is None:
        return
    try:
        observed = control.state
        observed_asset = asset_control.state
        if (
            observed.mode not in {"provisioned_not_active", "ready", "manual_only"}
            or observed_asset.mode
            not in {"provisioned_not_active", "ready", "manual_only"}
        ):
            return
        current, current_asset, store, asset_store = await run_in_threadpool(
            _reconcile_waiting_paid_media_authority,
            control,
            asset_control,
        )
        if store is None or asset_store is None:
            waiting = (
                current
                if current.mode == "provisioned_not_active"
                else current_asset
            )
            _set_paid_media_authority_status(
                app,
                mode="provisioned_not_active",
                reason_code=waiting.reason_code,
                new_operations_ready=False,
                replay_available=False,
                packaged=True,
            )
            return
        if not _paid_media_control_pair_identity_is_consistent(
            current,
            current_asset,
            getattr(app.state, "paid_media_installation_id", None),
            getattr(app.state, "paid_media_epoch", None),
        ):
            raise GatewayInstallationControlUnavailable(
                "paid-media controller installation identities diverged"
            )
        expected_principal = getattr(app.state, "paid_media_principal", None)
        if not _control_paid_principal_is_consistent(
            current,
            expected_principal,
        ):
            app.state.paid_media_principal = None
            app.state.paid_media_root_principal = None
            app.state.media_requests = None
            app.state.paid_media_assets = None
            _set_paid_media_authority_status(
                app,
                mode="fused",
                reason_code="installation-principal-mismatch",
                new_operations_ready=False,
                replay_available=False,
                packaged=True,
            )
            return
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 -- caller returns one fixed unavailable error
        app.state.media_requests = None
        app.state.paid_media_assets = None
        app.state.paid_media_principal = None
        app.state.paid_media_root_principal = None
        _set_paid_media_authority_status(
            app,
            mode="fused",
            reason_code="activation-reconcile-failed",
            new_operations_ready=False,
            replay_available=False,
            packaged=True,
        )
        return
    app.state.media_requests = store
    app.state.paid_media_assets = asset_store
    combined_manual_only = (
        current.mode == "manual_only" or current_asset.mode == "manual_only"
    )
    _set_paid_media_authority_status(
        app,
        mode="manual_only" if combined_manual_only else "ready",
        reason_code=(
            "manual-recovery-required"
            if combined_manual_only
            else "authority-exact"
        ),
        new_operations_ready=not combined_manual_only,
        replay_available=True,
        packaged=True,
    )


def _reconcile_waiting_channel_media_authority(
    control: Any,
) -> tuple[Any, DurableChannelMediaRequestStore | None]:
    """Singleflight one retained channel controller entirely off-loop."""

    with _CHANNEL_ACTIVATION_RECONCILE_LOCK:
        state = control.state
        if state.mode == "provisioned_not_active":
            state = control.reconcile_startup()
        if state.mode == "provisioned_not_active":
            return state, None
        if state.mode not in {"ready", "manual_only"}:
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media controller is not read capable"
            )
        return state, control.store


async def _refresh_waiting_channel_media_authority() -> None:
    """Converge first-run Desktop activation without creating authority."""

    if getattr(app.state, "channel_media_requests", None) is not None:
        return
    authority = getattr(app.state, "channel_media_authority", None)
    if (
        not isinstance(authority, Mapping)
        or not bool(authority.get("packaged"))
        or str(authority.get("mode") or "") != "provisioned_not_active"
    ):
        return
    control = getattr(app.state, "channel_media_installation_control", None)
    if control is None:
        return
    hard_failure = False
    try:
        state, store = await run_in_threadpool(
            _reconcile_waiting_channel_media_authority,
            control,
        )
        if store is None:
            _set_channel_media_authority_status(
                app,
                mode="provisioned_not_active",
                reason_code=state.reason_code,
                new_operations_ready=False,
                replay_available=False,
                packaged=True,
            )
            return
        if (
            state.installation_id
            != getattr(app.state, "paid_media_installation_id", None)
            or state.epoch != getattr(app.state, "paid_media_epoch", None)
        ):
            hard_failure = True
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media activation identity changed"
            )
        manual_only = state.mode == "manual_only"
        if not manual_only and not bool(state.provider_dispatch_ready):
            hard_failure = True
            raise ChannelMediaInstallationControlUnavailable(
                "channel-media provider authority is unavailable"
            )
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 -- publish only a fixed failure code
        app.state.channel_media_requests = None
        observed_mode = str(getattr(getattr(control, "state", None), "mode", ""))
        fused = hard_failure or observed_mode == "fused"
        _set_channel_media_authority_status(
            app,
            mode="fused" if fused else "provisioned_not_active",
            reason_code=(
                "activation-reconcile-failed"
                if fused
                else "activation-reconcile-temporarily-unavailable"
            ),
            new_operations_ready=False,
            replay_available=False,
            packaged=True,
        )
        return
    app.state.channel_media_requests = store
    _set_channel_media_authority_status(
        app,
        mode="manual_only" if manual_only else "ready",
        reason_code=(
            "manual-recovery-required" if manual_only else "authority-exact"
        ),
        new_operations_ready=not manual_only,
        replay_available=True,
        packaged=True,
    )


def _assert_paid_media_outbound_pair(
    control: Any,
    asset_control: Any,
    *,
    installation_id: object,
    epoch: object,
    paid_principal: object,
) -> None:
    """Freshly prove both controllers at the remote provider boundary."""

    with _PAID_ACTIVATION_RECONCILE_LOCK:
        gateway_state = control.state
        asset_state = asset_control.state
        if gateway_state.mode != "ready" or asset_state.mode != "ready":
            raise GatewayInstallationControlUnavailable(
                "paid-media controller pair is not mutation ready"
            )
        if not _paid_media_control_pair_identity_is_consistent(
            gateway_state,
            asset_state,
            installation_id,
            epoch,
        ) or not _control_paid_principal_is_consistent(
            gateway_state,
            paid_principal,
        ):
            raise GatewayInstallationControlUnavailable(
                "paid-media controller pair identity is inconsistent"
            )
        fresh_gateway = control.assert_outbound_ready()
        asset_control.assert_local_mutation_ready()
        fresh_asset = asset_control.state
        if (
            fresh_gateway.mode != "ready"
            or fresh_asset.mode != "ready"
            or not _paid_media_control_pair_identity_is_consistent(
                fresh_gateway,
                fresh_asset,
                installation_id,
                epoch,
            )
            or not _control_paid_principal_is_consistent(
                fresh_gateway,
                paid_principal,
            )
        ):
            raise GatewayInstallationControlUnavailable(
                "paid-media controller pair changed during admission"
            )


def _assert_paid_media_asset_admission_pair(
    control: Any,
    asset_control: Any,
    *,
    installation_id: object,
    epoch: object,
) -> None:
    """Block a new create admission unless the Asset Store remains Root-ready.

    The gateway ledger's ``claim`` method intentionally performs its bounded
    read/replay lookup before entering its controller-gated write transaction.
    This callback runs while that transaction owns the durable ledger lock, so
    it must never acquire ``_PAID_ACTIVATION_RECONCILE_LOCK``: the provider
    boundary acquires that process lock before freshly inspecting the ledger,
    and the inverse order would deadlock two concurrent requests.  The
    gateway's own mutation proof has already run as the store pre-mutation
    hook.  Here we independently prove the Asset Store, then resample both
    controller identities before SQLite is changed.  The provider boundary
    still performs the full fresh outbound proof immediately before dispatch.
    """

    gateway_state = control.state
    asset_state = asset_control.state
    if (
        asset_state.mode != "ready"
        or not _paid_media_control_pair_identity_is_consistent(
            gateway_state,
            asset_state,
            installation_id,
            epoch,
        )
    ):
        raise AssetInstallationControlUnavailable(
            "asset controller is not ready for create admission"
        )
    asset_control.assert_local_mutation_ready()
    fresh_gateway = control.state
    fresh_asset = asset_control.state
    if (
        fresh_asset.mode != "ready"
        or not _paid_media_control_pair_identity_is_consistent(
            fresh_gateway,
            fresh_asset,
            installation_id,
            epoch,
        )
    ):
        raise AssetInstallationControlUnavailable(
            "asset controller changed during create admission"
        )


def _assert_paid_media_new_operation_ready() -> None:
    authority_mode = str(
        getattr(app.state, "paid_media_authority_mode", "") or ""
    )
    if authority_mode != "installation-root" and not _is_packaged_runtime():
        return
    control = getattr(app.state, "installation_root_control", None)
    asset_control = getattr(app.state, "asset_installation_control", None)
    if authority_mode != "installation-root" or control is None or asset_control is None:
        raise _media_http_error(
            503,
            code="paid_media_authority_unavailable",
            message="Installation authority is unavailable; no provider call was made.",
            retryable=False,
        )
    try:
        _assert_paid_media_asset_admission_pair(
            control,
            asset_control,
            installation_id=getattr(app.state, "paid_media_installation_id", None),
            epoch=getattr(app.state, "paid_media_epoch", None),
        )
    except Exception as exc:
        try:
            gateway_state = control.state
            asset_state = asset_control.state
            manual_only = (
                gateway_state.mode == "manual_only"
                or asset_state.mode == "manual_only"
            )
        except Exception:  # noqa: BLE001 -- fixed, secret-free projection
            manual_only = False
        _set_paid_media_authority_status(
            app,
            mode="manual_only" if manual_only else "fused",
            reason_code=(
                "manual-recovery-required"
                if manual_only
                else "new-operation-authority-unavailable"
            ),
            new_operations_ready=False,
            replay_available=(
                getattr(app.state, "media_requests", None) is not None
                and getattr(app.state, "paid_media_assets", None) is not None
            ),
            packaged=True,
        )
        raise _media_http_error(
            503,
            code="paid_media_authority_unavailable",
            message="Installation authority is unavailable; no provider call was made.",
            retryable=False,
        ) from exc


async def _claim_paid_media_request(
    *,
    principal_hash: str,
    operation: str,
    idempotency_key: str,
    payload: dict[str, Any],
) -> DurableMediaRequestClaim:
    await _refresh_waiting_paid_media_authority()
    store = getattr(app.state, "media_requests", None)
    if store is None:
        raise _media_http_error(
            503,
            code="paid_media_authority_unavailable",
            message="Installation authority is unavailable; no provider call was made.",
            retryable=False,
        )
    try:
        claim = await run_in_threadpool(
            store.claim,
            principal_hash=principal_hash,
            operation=operation,
            idempotency_key=idempotency_key,
            request_sha256=hash_media_request(operation, payload),
            max_success_bytes=PAID_MEDIA_RESULT_MAX_BYTES,
            admission_hook=_assert_paid_media_new_operation_ready,
        )
    except ValueError as exc:
        raise _media_http_error(
            422,
            code="invalid_media_request_identity",
            message="The paid media request identity is invalid.",
            retryable=False,
        ) from exc
    except DurableMediaRequestUnavailable as exc:
        raise _media_http_error(
            503,
            code="media_idempotency_unavailable",
            message="Durable paid-media admission is unavailable; do not create a new key.",
            retryable=False,
        ) from exc

    if claim.state == "conflict":
        raise _media_http_error(
            409,
            code="idempotency_key_conflict",
            message="This Idempotency-Key is already bound to another request.",
            retryable=False,
        )
    if claim.state == "processing":
        retry_after = min(900, max(1, int(claim.retry_after_seconds)))
        raise _media_http_error(
            425,
            code="media_request_processing",
            message="The original paid media request is still processing.",
            retryable=True,
            headers={"Retry-After": str(retry_after)},
        )
    if claim.state == "recovery_required":
        raise _media_http_error(
            409,
            code="media_recovery_required",
            message="Provider outcome requires manual recovery; do not auto-retry.",
            retryable=False,
        )
    return claim


def _request_paid_media_principal_hash(request: Request) -> str:
    """Read only the verified paid principal established by the dependency."""

    principal_hash = str(
        getattr(request.state, "nachuan_paid_media_principal_hash", "") or ""
    )
    if re.fullmatch(r"[0-9a-f]{64}", principal_hash) is None:
        raise _media_http_error(
            503,
            code="paid_media_authority_unavailable",
            message="Verified paid-media authority is unavailable.",
            retryable=False,
        )
    return principal_hash


def _trusted_media_probe_error_response(exc: BaseException) -> JSONResponse:
    status_code = 503
    code = "media_probe_unavailable"
    message = "Trusted media probe is unavailable."
    retryable = True
    headers = {"Cache-Control": "no-store"}
    if isinstance(exc, TrustedMediaRequestError):
        status_code = exc.status_code
        code = exc.code
        message = exc.public_message
        retryable = exc.retryable
        if status_code == 429:
            headers["Retry-After"] = "2"
    elif isinstance(exc, TrustedMediaTooLarge):
        status_code = 413
        code = "media_probe_payload_too_large"
        message = "Trusted media probe payload exceeds its limit."
        retryable = False
    elif isinstance(exc, TrustedMediaRejected):
        status_code = 422
        code = "media_probe_rejected"
        message = "Trusted media bytes failed full-decode validation."
        retryable = False
    elif isinstance(exc, TrustedMediaProbeBusy):
        status_code = 429
        code = "media_probe_busy"
        message = "Trusted media probe capacity is busy."
        retryable = True
        headers["Retry-After"] = "2"
    elif isinstance(exc, TrustedMediaProbeTimeout):
        status_code = 503
        code = "media_probe_timeout"
        message = "Trusted media probe timed out."
        retryable = True
        headers["Retry-After"] = "2"
    elif isinstance(
        exc,
        (MediaBinaryUnavailable, TrustedMediaProbeUnavailable, TrustedMediaProbeError),
    ):
        pass
    elif isinstance(exc, ValueError):
        status_code = 422
        code = "invalid_media_probe_request"
        message = "Trusted media probe request is invalid."
        retryable = False
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": {
                "code": code,
                "message": message,
                "retryable": retryable,
            }
        },
        headers=headers,
    )


@app.get("/v1/paid-media/probe/readiness")
async def paid_media_probe_readiness(
    request: Request,
    _: str = Depends(require_paid_media_api_key),
) -> JSONResponse:
    """Re-attest and launch both decoders before a newly paid operation."""

    _require_paid_media_protocol_v2(request)
    try:
        receipt = await trusted_media_readiness_receipt()
    except BaseException as exc:  # all boundary ambiguity is fail-closed
        if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
        return _trusted_media_probe_error_response(exc)
    return JSONResponse(
        receipt,
        headers={
            "Cache-Control": "no-store",
            PAID_MEDIA_PROTOCOL_HEADER: PAID_MEDIA_PROTOCOL_VERSION,
        },
    )


@app.post("/v1/paid-media/probe")
async def paid_media_probe_validate(
    request: Request,
    _: str = Depends(require_paid_media_api_key),
) -> JSONResponse:
    """Fully decode an authenticated raw upload; never accept a host path."""

    _require_paid_media_protocol_v2(request)
    try:
        receipt = await validate_trusted_media_request(request)
    except BaseException as exc:  # all boundary ambiguity is fail-closed
        if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
        return _trusted_media_probe_error_response(exc)
    return JSONResponse(
        receipt,
        headers={
            "Cache-Control": "no-store",
            PAID_MEDIA_PROTOCOL_HEADER: PAID_MEDIA_PROTOCOL_VERSION,
        },
    )


def _reject_paid_media_asset_stream_ambiguity(request: Request) -> None:
    counts: dict[bytes, int] = {}
    values: dict[bytes, list[bytes]] = {}
    for raw_name, raw_value in request.scope.get("headers", ()):
        name = bytes(raw_name).lower()
        if name in {
            b"range",
            b"accept-encoding",
            b"content-length",
            b"transfer-encoding",
            b"upgrade",
        }:
            counts[name] = counts.get(name, 0) + 1
            values.setdefault(name, []).append(bytes(raw_value))
    if any(count > 1 for count in counts.values()):
        raise _media_http_error(
            400,
            code="ambiguous_paid_media_asset_request",
            message="Paid media asset request headers are ambiguous.",
            retryable=False,
        )
    if any(name in counts for name in (b"range", b"content-length", b"transfer-encoding", b"upgrade")):
        raise _media_http_error(
            400,
            code="unsupported_paid_media_asset_transfer",
            message="Paid media asset requests require one complete identity transfer.",
            retryable=False,
        )
    encodings = values.get(b"accept-encoding", [])
    if encodings:
        try:
            encoding = encodings[0].decode("ascii", "strict").strip().lower()
        except UnicodeError as exc:
            raise _media_http_error(
                400,
                code="unsupported_paid_media_asset_encoding",
                message="Paid media asset content encoding is unsupported.",
                retryable=False,
            ) from exc
        if encoding != "identity":
            raise _media_http_error(
                400,
                code="unsupported_paid_media_asset_encoding",
                message="Paid media asset content encoding is unsupported.",
                retryable=False,
            )


@app.get("/v1/paid-media/assets/{token}")
async def get_paid_media_asset(
    token: str,
    request: Request,
    _runtime_api_key: str = Depends(require_paid_media_api_key),
) -> StreamingResponse:
    _require_paid_media_protocol_v2(request)
    _reject_paid_media_asset_stream_ambiguity(request)
    principal_hash = _request_paid_media_principal_hash(request)
    try:
        pinned = await pin_paid_media_asset_for_principal(
            app.state,
            token=token,
            principal_hash=principal_hash,
        )
    except PaidMediaAssetAuthorizationError as exc:
        raise _media_http_error(
            404,
            code="paid_media_asset_unavailable",
            message="Paid media asset is unavailable.",
            retryable=False,
        ) from exc
    except PaidMediaAssetProtocolError as exc:
        raise _media_http_error(
            404,
            code="paid_media_asset_unavailable",
            message="Paid media asset is unavailable.",
            retryable=False,
        ) from exc
    except (
        PaidMediaAssetDeliveryUnavailable,
        PaidMediaAssetStoreError,
        DurableMediaRequestUnavailable,
        OSError,
    ) as exc:
        raise _media_http_error(
            503,
            code="paid_media_asset_authority_unavailable",
            message="Paid media asset authority could not be verified.",
            retryable=False,
        ) from exc
    return pinned_asset_streaming_response(
        pinned,
        headers={
            "Content-Length": str(pinned.byte_length),
            "Content-Type": pinned.media_type,
            "X-Content-SHA256": pinned.sha256,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            PAID_MEDIA_PROTOCOL_HEADER: PAID_MEDIA_PROTOCOL_VERSION,
        },
    )


@app.post("/v1/paid-media/assets/ack")
async def acknowledge_paid_media_assets(
    request: Request,
    _runtime_api_key: str = Depends(require_paid_media_api_key),
) -> JSONResponse:
    _require_paid_media_protocol_v2(request)
    try:
        ack = parse_asset_ack(await request.json())
    except (PaidMediaAssetProtocolError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _media_http_error(
            422,
            code="invalid_paid_media_asset_ack",
            message="Paid media asset ACK is invalid.",
            retryable=False,
        ) from exc
    principal_hash = _request_paid_media_principal_hash(request)
    asset_store = getattr(app.state, "paid_media_assets", None)
    request_store = getattr(app.state, "media_requests", None)
    epoch = getattr(app.state, "paid_media_epoch", None)
    if (
        not isinstance(asset_store, PaidMediaAssetStore)
        or request_store is None
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 1
    ):
        raise _media_http_error(
            503,
            code="paid_media_asset_store_unavailable",
            message="Paid media asset storage is unavailable.",
            retryable=False,
        )
    try:
        candidates = []
        for operation in ("images.create", "videos.create"):
            document = await run_in_threadpool(
                request_store.read_asset_success_document,
                turn_id=ack.turn_id,
                principal_hash=principal_hash,
                operation=operation,
            )
            if document is not None:
                candidates.append(document)
        if len(candidates) != 1:
            raise DurableMediaAssetConflict(
                "ACK does not identify one exact paid-media asset success"
            )
        document = candidates[0]
        durable_receipt = await run_in_threadpool(
            request_store.ack_asset_success,
            turn_id=ack.turn_id,
            principal_hash=principal_hash,
            operation=document.operation,
            installation_epoch=epoch,
            tokens=list(ack.tokens),
            archive_receipt_sha256=ack.archive_receipt_sha256,
        )
        cleanup = await run_in_threadpool(
            asset_store.ack,
            ack=ack,
            durable_result=document.response,
            principal_hash=principal_hash,
            epoch=epoch,
            operation=document.operation,
        )
        if cleanup.cleanup_complete:
            completed = await run_in_threadpool(
                request_store.complete_asset_ack_cleanup,
                turn_id=ack.turn_id,
                principal_hash=principal_hash,
                operation=document.operation,
                installation_epoch=epoch,
                token_set_digest=durable_receipt.token_set_digest,
                archive_receipt_sha256=durable_receipt.archive_receipt_sha256,
            )
            if not completed:
                raise DurableMediaRequestUnavailable(
                    "paid-media ACK cleanup completion was not committed"
                )
    except (DurableMediaAssetConflict, PaidMediaAssetConflictError) as exc:
        raise _media_http_error(
            409,
            code="paid_media_asset_ack_conflict",
            message="Paid media asset ACK conflicts with durable authority.",
            retryable=False,
        ) from exc
    except PaidMediaAssetAuthorizationError as exc:
        raise _media_http_error(
            409,
            code="paid_media_asset_ack_conflict",
            message="Paid media asset ACK conflicts with durable authority.",
            retryable=False,
        ) from exc
    except (PaidMediaAssetStoreError, DurableMediaRequestUnavailable, OSError) as exc:
        raise _media_http_error(
            503,
            code="paid_media_asset_ack_unavailable",
            message="Paid media asset ACK could not be safely completed.",
            retryable=False,
        ) from exc
    status_code = 200 if cleanup.cleanup_complete else 202
    return JSONResponse(
        status_code=status_code,
        content={
            "ok": cleanup.cleanup_complete,
            "turnId": ack.turn_id,
            "replayed": bool(durable_receipt.replayed or cleanup.replayed),
            "cleanupComplete": cleanup.cleanup_complete,
        },
        headers={
            "Cache-Control": "no-store",
            PAID_MEDIA_PROTOCOL_HEADER: PAID_MEDIA_PROTOCOL_VERSION,
            **({"Retry-After": "1"} if not cleanup.cleanup_complete else {}),
        },
    )


def _paid_media_response(
    result: dict[str, Any], *, replayed: bool
) -> JSONResponse:
    return JSONResponse(
        result,
        headers={
            "Idempotency-Replayed": "true" if replayed else "false",
            "Cache-Control": "no-store",
            PAID_MEDIA_PROTOCOL_HEADER: PAID_MEDIA_PROTOCOL_VERSION,
        },
    )


def _require_paid_media_protocol_v2(request: Request) -> None:
    try:
        require_protocol_v2(request.scope)
    except PaidMediaAssetProtocolError as exc:
        raise _media_http_error(
            426,
            code=exc.code,
            message="Paid media asset protocol v2 is required.",
            retryable=False,
        ) from exc


async def _assert_paid_media_outbound_ready() -> None:
    """Freshly prove the installation authority at the remote-call boundary."""

    authority_mode = str(
        getattr(app.state, "paid_media_authority_mode", "") or ""
    )
    if authority_mode != "installation-root" and not _is_packaged_runtime():
        return
    control = getattr(app.state, "installation_root_control", None)
    asset_control = getattr(app.state, "asset_installation_control", None)
    if (
        authority_mode != "installation-root"
        or control is None
        or asset_control is None
    ):
        raise _media_http_error(
            503,
            code="paid_media_authority_unavailable",
            message="Installation authority is unavailable; no provider call was made.",
            retryable=False,
        )
    try:
        await run_in_threadpool(
            _assert_paid_media_outbound_pair,
            control,
            asset_control,
            installation_id=getattr(app.state, "paid_media_installation_id", None),
            epoch=getattr(app.state, "paid_media_epoch", None),
            paid_principal=getattr(app.state, "paid_media_principal", None),
        )
        state = control.state
        asset_state = asset_control.state
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # fail closed across the local authority boundary
        try:
            failed_state = control.state
            failed_asset_state = asset_control.state
            failed_modes = {failed_state.mode, failed_asset_state.mode}
            manual_only = "manual_only" in failed_modes
            reason_code = (
                "manual-recovery-required"
                if manual_only
                else "outbound-authority-unavailable"
            )
        except Exception:  # noqa: BLE001
            manual_only = False
            reason_code = "outbound-authority-check-failed"
        _set_paid_media_authority_status(
            app,
            mode="manual_only" if manual_only else "fused",
            reason_code=reason_code or "outbound-authority-unavailable",
            new_operations_ready=False,
            replay_available=(
                getattr(app.state, "media_requests", None) is not None
                and getattr(app.state, "paid_media_assets", None) is not None
            ),
            packaged=True,
        )
        raise _media_http_error(
            503,
            code="paid_media_authority_unavailable",
            message="Installation authority is unavailable; no provider call was made.",
            retryable=False,
        ) from exc
    _set_paid_media_authority_status(
        app,
        mode="ready",
        reason_code=(
            "authority-exact"
            if asset_state.mode == "ready"
            else "outbound-authority-unavailable"
        ),
        new_operations_ready=True,
        replay_available=True,
        packaged=True,
    )


async def _enter_paid_media_provider_phase(
    claim: DurableMediaRequestClaim,
    *,
    principal_hash: str,
    asset_store: PaidMediaAssetStore,
) -> None:
    request_store = app.state.media_requests
    enter_task = asyncio.create_task(
        run_in_threadpool(
            request_store.enter_provider_phase,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            max_success_bytes=PAID_MEDIA_RESULT_MAX_BYTES,
        )
    )
    try:
        entered = await asyncio.shield(enter_task)
    except asyncio.CancelledError:
        async def drain_and_abandon_before_invocation() -> None:
            try:
                entered_after_cancel = bool(await enter_task)
            except BaseException:  # noqa: BLE001 -- unknown outcome stays held
                return
            if not entered_after_cancel:
                return

            def compensate() -> None:
                try:
                    local_released = bool(
                        asset_store.release_pre_provider(
                            turn_id=claim.turn_id,
                            principal_hash=principal_hash,
                        )
                    )
                except Exception:  # noqa: BLE001 -- keep durable hold
                    return
                if not local_released:
                    return
                try:
                    request_store.abandon_fenced_before_invocation(
                        turn_id=claim.turn_id,
                        fencing_token=claim.fencing_token,
                    )
                except Exception:  # noqa: BLE001 -- never mask cancellation
                    pass

            await run_in_threadpool(compensate)

        cleanup_task = asyncio.create_task(drain_and_abandon_before_invocation())
        try:
            await asyncio.wait_for(asyncio.shield(cleanup_task), timeout=10.0)
        except BaseException:  # noqa: BLE001 -- shielded cleanup keeps running
            pass
        raise
    except DurableMediaRequestUnavailable as exc:
        raise _media_http_error(
            503,
            code="media_provider_fence_unavailable",
            message="Paid provider admission could not be fenced; do not auto-retry.",
            retryable=False,
        ) from exc
    if not entered:
        raise _media_http_error(
            409,
            code="media_provider_fence_lost",
            message="Paid provider ownership was lost; do not auto-retry.",
            retryable=False,
        )


async def _abandon_paid_media_pre_provider(
    claim: DurableMediaRequestClaim,
) -> None:
    try:
        abandoned = await run_in_threadpool(
            app.state.media_requests.abandon_pre_provider,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
    except DurableMediaRequestUnavailable as exc:
        raise _media_http_error(
            503,
            code="media_pre_provider_release_unavailable",
            message="Unused paid-media admission could not be released; do not auto-retry.",
            retryable=False,
        ) from exc
    if not abandoned:
        raise _media_http_error(
            503,
            code="media_pre_provider_release_unavailable",
            message="Unused paid-media admission could not be released; do not auto-retry.",
            retryable=False,
        )


async def _resolve_paid_media_route_or_abandon(
    *,
    router: Any,
    model: str,
    claim: DurableMediaRequestClaim,
) -> Any:
    try:
        route = router.resolve(model)
    except Exception as exc:
        await _abandon_paid_media_pre_provider(claim)
        raise _media_http_error(
            503,
            code="media_route_unavailable",
            message="Paid media routing is unavailable; no provider call was made.",
            retryable=False,
        ) from exc
    if route is not None:
        return route
    await _abandon_paid_media_pre_provider(claim)
    raise _media_http_error(
        404,
        code="unknown_media_model",
        message="Requested paid media model is unavailable.",
        retryable=False,
    )


def _provider_supports_paid_media_asset_v2(provider: object) -> bool:
    versions = frozenset(
        str(value)
        for value in (
            getattr(provider, "paid_media_asset_protocol_versions", ()) or ()
        )
    )
    method = getattr(provider, "generate_image_asset_urls", None)
    implementation = getattr(method, "__func__", method)
    return (
        "2" in versions
        and callable(method)
        and implementation is not ChatProvider.generate_image_asset_urls
    )


async def _require_image_asset_v2_or_abandon(
    provider: object,
    claim: DurableMediaRequestClaim,
) -> None:
    if _provider_supports_paid_media_asset_v2(provider):
        return
    await _abandon_paid_media_pre_provider(claim)
    raise _media_http_error(
        503,
        code="paid_media_provider_protocol_unsupported",
        message="Paid media provider does not support asset protocol v2.",
        retryable=False,
    )


def _provider_supports_paid_media_video_asset_v2(provider: object) -> bool:
    versions = frozenset(
        str(value)
        for value in (
            getattr(provider, "paid_media_video_asset_protocol_versions", ()) or ()
        )
    )
    generate = getattr(provider, "generate_video", None)
    poll = getattr(provider, "get_video", None)
    generate_impl = getattr(generate, "__func__", generate)
    poll_impl = getattr(poll, "__func__", poll)
    return (
        "2" in versions
        and callable(generate)
        and callable(poll)
        and generate_impl is not ChatProvider.generate_video
        and poll_impl is not ChatProvider.get_video
    )


async def _require_video_asset_v2_or_abandon(
    provider: object,
    claim: DurableMediaRequestClaim,
) -> None:
    if _provider_supports_paid_media_video_asset_v2(provider):
        return
    await _abandon_paid_media_pre_provider(claim)
    raise _media_http_error(
        503,
        code="paid_media_video_protocol_unsupported",
        message="Paid video asset protocol v2 is not enabled for this provider.",
        retryable=False,
    )


async def _reserve_paid_media_asset_capacity(
    *,
    claim: DurableMediaRequestClaim,
    principal_hash: str,
    operation: str,
) -> tuple[PaidMediaAssetStore, int]:
    request_store = getattr(app.state, "media_requests", None)
    asset_store = getattr(app.state, "paid_media_assets", None)
    epoch = getattr(app.state, "paid_media_epoch", None)
    if (
        request_store is None
        or not isinstance(asset_store, PaidMediaAssetStore)
        or isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or epoch < 1
    ):
        await _abandon_paid_media_pre_provider(claim)
        raise _media_http_error(
            503,
            code="paid_media_asset_store_unavailable",
            message="Paid media asset storage is unavailable; no provider call was made.",
            retryable=False,
        )
    durable_reserved = False
    mirror_reserved = False
    stage_task: asyncio.Task[Any] | None = None
    stage_kind = ""
    try:
        stage_kind = "durable"
        stage_task = asyncio.create_task(
            run_in_threadpool(
                request_store.reserve_asset_capacity,
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
                principal_hash=principal_hash,
                operation=operation,
                installation_epoch=epoch,
                reserved_bytes=PAID_MEDIA_ASSET_RESERVATION_BYTES,
            )
        )
        durable_reserved = bool(
            await asyncio.shield(stage_task)
        )
        stage_task = None
        if not durable_reserved:
            raise PaidMediaAssetConflictError(
                "durable paid-media asset reservation was not acquired"
            )
        stage_kind = "mirror"
        stage_task = asyncio.create_task(
            run_in_threadpool(
                asset_store.reserve,
                turn_id=claim.turn_id,
                principal_hash=principal_hash,
                epoch=epoch,
                operation=operation,
                reserved_bytes=PAID_MEDIA_ASSET_RESERVATION_BYTES,
            )
        )
        await asyncio.shield(stage_task)
        stage_task = None
        mirror_reserved = True
        return asset_store, epoch
    except asyncio.CancelledError:
        # ``run_in_threadpool`` work is not synchronously cancelled.  First
        # drain the in-flight reservation, then compensate both ledgers in one
        # shielded task.  A second cancellation or the local wait bound cannot
        # cancel that compensator, and the original cancellation is preserved.
        async def drain_and_compensate() -> None:
            mirror_outcome_unknown = False
            mirror_committed = mirror_reserved
            if stage_task is not None:
                try:
                    await stage_task
                    if stage_kind == "mirror":
                        mirror_committed = True
                except BaseException:  # noqa: BLE001 -- cleanup still must run
                    mirror_outcome_unknown = stage_kind == "mirror"

            def compensate() -> None:
                local_released = not (mirror_committed or mirror_outcome_unknown)
                try:
                    local_released = bool(
                        asset_store.release_pre_provider(
                            turn_id=claim.turn_id,
                            principal_hash=principal_hash,
                        )
                    )
                except Exception:  # noqa: BLE001 -- durable cleanup remains mandatory
                    local_released = False
                # Once the mirror may have committed, never release Root
                # authority unless the mirror removal is positively confirmed.
                # A hold consumes capacity but cannot orphan private bytes.
                if not local_released:
                    return
                try:
                    request_store.abandon_pre_provider(
                        turn_id=claim.turn_id,
                        fencing_token=claim.fencing_token,
                    )
                except Exception:  # noqa: BLE001 -- never mask original cancellation
                    pass

            await run_in_threadpool(compensate)

        cleanup_task = asyncio.create_task(drain_and_compensate())
        try:
            await asyncio.wait_for(asyncio.shield(cleanup_task), timeout=10.0)
        except BaseException:  # noqa: BLE001 -- task remains shielded and will finish
            pass
        raise
    except (DurableMediaRequestUnavailable, PaidMediaAssetStoreError, OSError, ValueError) as exc:
        # Always ask the typed local authority to remove an exact same-turn
        # reservation, even if this invocation failed before reaching the
        # mirror stage. A prior crash/retry can already have committed that row.
        try:
            local_released = bool(
                await run_in_threadpool(
                    asset_store.release_pre_provider,
                    turn_id=claim.turn_id,
                    principal_hash=principal_hash,
                )
            )
        except Exception:  # noqa: BLE001 -- retain Root authority on ambiguity
            local_released = False
        if local_released:
            try:
                await _abandon_paid_media_pre_provider(claim)
            except HTTPException:
                pass
        status = 507 if isinstance(exc, PaidMediaAssetCapacityError) else 503
        code = (
            "paid_media_asset_capacity_unavailable"
            if status == 507
            else "paid_media_asset_reservation_unavailable"
        )
        raise _media_http_error(
            status,
            code=code,
            message="Paid media asset capacity is unavailable; no provider call was made.",
            retryable=False,
        ) from exc


async def _release_paid_media_assets_pre_provider(
    *,
    claim: DurableMediaRequestClaim,
    principal_hash: str,
    asset_store: PaidMediaAssetStore,
) -> None:
    asset_released = False
    try:
        asset_released = bool(
            await run_in_threadpool(
                asset_store.release_pre_provider,
                turn_id=claim.turn_id,
                principal_hash=principal_hash,
            )
        )
    except PaidMediaAssetStoreError:
        asset_released = False
    if not asset_released:
        raise _media_http_error(
            503,
            code="paid_media_asset_release_unavailable",
            message="Unused paid-media asset reservation could not be released.",
            retryable=False,
        )
    try:
        await _abandon_paid_media_pre_provider(claim)
    except HTTPException:
        raise


async def _mark_paid_media_recovery_or_fail(
    claim: DurableMediaRequestClaim,
) -> None:
    try:
        persisted = await run_in_threadpool(
            app.state.media_requests.mark_recovery_required,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
    except DurableMediaRequestUnavailable as exc:
        raise _media_http_error(
            503,
            code="media_recovery_persistence_unavailable",
            message="Provider outcome could not be finalized; do not auto-retry.",
            retryable=False,
        ) from exc
    if not persisted:
        raise _media_http_error(
            503,
            code="media_recovery_persistence_unavailable",
            message="Provider outcome could not be finalized; do not auto-retry.",
            retryable=False,
        )


async def _persist_paid_media_success(
    claim: DurableMediaRequestClaim,
    result: dict[str, Any],
) -> None:
    try:
        persisted = await run_in_threadpool(
            app.state.media_requests.succeed,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            response=result,
        )
    except (DurableMediaRequestUnavailable, ValueError):
        persisted = False
    if persisted:
        return
    try:
        await run_in_threadpool(
            app.state.media_requests.mark_recovery_required,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
        )
    except DurableMediaRequestUnavailable:
        pass
    raise _media_http_error(
        503,
        code="media_result_persistence_unavailable",
        message="Provider result is not durably replayable; do not auto-retry.",
        retryable=False,
    )


def _normalized_paid_video_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if candidate.startswith("sha256:"):
        candidate = candidate[7:]
    return candidate if re.fullmatch(r"[0-9a-f]{64}", candidate) else None


def _canonical_paid_video_endpoint(value: object) -> str:
    """Canonicalize an already-authorized provider root without network I/O."""

    if not isinstance(value, str):
        raise ValueError("provider base URL is not a string")
    raw = value.strip()
    if (
        not raw
        or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw)
        or "\\" in raw
    ):
        raise ValueError("provider base URL contains unsafe characters")
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("provider base URL must be HTTP(S)")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("provider base URL must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("provider base URL must not contain query or fragment")
        host = parsed.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
        if not host or "%" in host:
            raise ValueError("provider host is invalid")
        port = parsed.port or (443 if scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("provider port is invalid")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("provider base URL is invalid") from exc

    path = parsed.path.rstrip("/")
    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise ValueError("provider path contains invalid escaping")
    for segment in path.split("/"):
        decoded = unquote(segment)
        if (
            decoded in {".", ".."}
            or "\\" in decoded
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in decoded)
        ):
            raise ValueError("provider path is ambiguous")
    path = re.sub(
        r"%[0-9a-fA-F]{2}", lambda match: match.group(0).upper(), path
    )
    default_port = 443 if scheme == "https" else 80
    shown_host = f"[{host}]" if ":" in host else host
    authority = shown_host if port == default_port else f"{shown_host}:{port}"
    return f"{scheme}://{authority}{path}"


def _paid_video_provider_domain(route: Any) -> str:
    provider = getattr(route, "provider", None)
    # ReviewGate deliberately folds paths and ports so aliases cannot multiply
    # votes.  A remote task is the opposite contract: every later poll must hit
    # the exact adapter + endpoint that accepted the paid create.  Never fall
    # back to route.independence_domain here.
    explicit_value = getattr(route, "paid_video_route_domain", "") or getattr(
        provider, "paid_video_route_domain", ""
    )
    if explicit_value:
        explicit = _normalized_paid_video_digest(explicit_value)
        if explicit is None:
            raise _media_http_error(
                503,
                code="video_route_identity_unavailable",
                message="Paid video provider route has no stable identity.",
                retryable=False,
            )
        return explicit

    try:
        endpoint = _canonical_paid_video_endpoint(getattr(provider, "base_url", ""))
    except ValueError as exc:
        raise _media_http_error(
            503,
            code="video_route_identity_unavailable",
            message="Paid video provider route has no stable identity.",
            retryable=False,
        ) from exc
    provider_type = type(provider)
    material = json.dumps(
        {
            "adapter": f"{provider_type.__module__}.{provider_type.__qualname__}",
            "endpoint": endpoint,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(b"nachuan-paid-video-route-v2\x00" + material).hexdigest()


def _paid_video_provider_credential_domain(route: Any, provider_domain: str) -> str:
    provider = getattr(route, "provider", None)
    explicit_value = getattr(provider, "paid_video_credential_domain", "") or ""
    if explicit_value:
        explicit = _normalized_paid_video_digest(explicit_value)
        if explicit is None:
            raise _media_http_error(
                503,
                code="video_route_identity_unavailable",
                message="Paid video provider credential has no stable identity.",
                retryable=False,
            )
        return explicit

    headers = getattr(provider, "_headers", None)
    scoped_headers: list[tuple[str, str]] = []
    excluded_headers = {
        "accept",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "date",
        "host",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
    }
    # Provider adapters keep their static outbound headers here.  Hash every
    # non-transport header so vendor-specific organization/account/tenant scope
    # cannot drift while the API key itself stays constant.  Plaintext is never
    # persisted or logged.
    if isinstance(headers, dict):
        if len(headers) > 128:
            raise _media_http_error(
                503,
                code="video_route_identity_unavailable",
                message="Paid video provider credential has no stable identity.",
                retryable=False,
            )
        seen: set[str] = set()
        total_size = 0
        for raw_name, raw_value in headers.items():
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise _media_http_error(
                    503,
                    code="video_route_identity_unavailable",
                    message="Paid video provider credential has no stable identity.",
                    retryable=False,
                )
            name = raw_name.casefold()
            if (
                len(name) > 256
                or re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", name) is None
                or name in seen
                or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw_value)
            ):
                raise _media_http_error(
                    503,
                    code="video_route_identity_unavailable",
                    message="Paid video provider credential has no stable identity.",
                    retryable=False,
                )
            seen.add(name)
            value = raw_value.strip(" \t")
            total_size += len(name.encode("ascii")) + len(value.encode("utf-8"))
            if total_size > 65_536:
                raise _media_http_error(
                    503,
                    code="video_route_identity_unavailable",
                    message="Paid video provider credential has no stable identity.",
                    retryable=False,
                )
            if name not in excluded_headers:
                scoped_headers.append((name, value))
    scoped_headers.sort()
    material = json.dumps(
        {
            "headers": scoped_headers,
            "route": provider_domain,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(
        b"nachuan-paid-video-route-credential-v2\x00" + material
    ).hexdigest()


async def _persist_paid_video_success(
    *,
    claim: DurableMediaRequestClaim,
    principal_hash: str,
    requested_model: str,
    route: Any,
    provider_domain: str,
    provider_credential_domain: str,
    asset_store: PaidMediaAssetStore,
    result: dict[str, Any],
) -> dict[str, object]:
    task_ids = _video_job_ids(result)
    if not task_ids:
        await _mark_paid_media_recovery_or_fail(claim)
        raise _media_http_error(
            502,
            code="video_task_identity_unavailable",
            message="Paid video provider returned no pollable task identity.",
            retryable=False,
        )
    terminal = _video_job_terminal(result)
    terminal_failed = terminal and _video_job_failed(result)
    try:
        persisted, public_result = await run_in_threadpool(
            app.state.media_requests.succeed_video,
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash=principal_hash,
            response=result,
            requested_model=requested_model,
            provider_name=str(getattr(route.provider, "name", "") or ""),
            provider_domain=provider_domain,
            provider_credential_domain=provider_credential_domain,
            upstream_model=str(route.upstream_model),
            upstream_task_id=task_ids[0],
            # A successful immediate terminal result first becomes a durable,
            # pollable receipt.  Only then may the private asset store see the
            # raw capability token.  The prepared poll path publishes the final
            # result after both databases can recover it across a crash.
            terminal=terminal and terminal_failed,
            prepared_provider_response=(
                result if terminal and not terminal_failed else None
            ),
        )
    except (DurableMediaRequestUnavailable, ValueError):
        persisted = False
        public_result = {}
    if not persisted:
        try:
            await run_in_threadpool(
                app.state.media_requests.mark_recovery_required,
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
            )
        except DurableMediaRequestUnavailable:
            pass
        raise _media_http_error(
            503,
            code="media_result_persistence_unavailable",
            message="Provider result is not durably replayable; do not auto-retry.",
            retryable=False,
        )

    if terminal and not terminal_failed:
        task_alias = str(public_result.get("task_id") or "")
        try:
            poll_claim = await run_in_threadpool(
                app.state.media_requests.begin_video_poll,
                task_alias=task_alias,
                principal_hash=principal_hash,
            )
        except (DurableMediaRequestUnavailable, ValueError) as exc:
            raise _media_http_error(
                503,
                code="video_task_registry_unavailable",
                message="Durable paid video task registry is unavailable.",
                retryable=False,
            ) from exc
        if poll_claim.state == "terminal" and isinstance(poll_claim.response, dict):
            return poll_claim.response
        if poll_claim.state == "deferred":
            return public_result
        if poll_claim.state not in {"claimed", "prepared"}:
            raise _media_http_error(
                503,
                code="video_task_registry_unavailable",
                message="Durable paid video task registry is unavailable.",
                retryable=False,
            )

        async def release_poll_fence() -> None:
            try:
                await run_in_threadpool(
                    app.state.media_requests.fail_video_poll,
                    task_alias=task_alias,
                    principal_hash=principal_hash,
                    fencing_token=poll_claim.fencing_token,
                )
            except DurableMediaRequestUnavailable:
                pass

        provider_result = (
            poll_claim.prepared_provider_response
            if poll_claim.state == "prepared"
            else result
        )
        if not isinstance(provider_result, dict):
            await release_poll_fence()
            raise _media_http_error(
                503,
                code="video_task_registry_unavailable",
                message="Durable paid video task registry is unavailable.",
                retryable=False,
            )
        try:
            published, final_result = await _commit_prepared_paid_video_asset(
                task_alias=task_alias,
                principal_hash=principal_hash,
                fencing_token=poll_claim.fencing_token,
                provider_result=provider_result,
                asset_store=asset_store,
                prepared_token=poll_claim.prepared_token,
                prepared_asset_response=poll_claim.prepared_asset_response,
            )
        except (
            ValueError,
            PaidMediaAssetStoreError,
            PaidMediaAssetProtocolError,
            PublicFetchError,
            OSError,
        ) as exc:
            await release_poll_fence()
            raise _media_http_error(
                502,
                code="paid_video_asset_ingestion_failed",
                message="Terminal video could not be committed as a verified private asset.",
                retryable=False,
            ) from exc
        except DurableMediaRequestUnavailable as exc:
            await release_poll_fence()
            raise _media_http_error(
                503,
                code="video_poll_persistence_unavailable",
                message="Paid video poll result could not be persisted.",
                retryable=False,
            ) from exc
        if not published:
            raise _media_http_error(
                409,
                code="video_poll_fence_lost",
                message="Paid video poll ownership was lost.",
                retryable=True,
            )
        return final_result

    if terminal_failed:
        try:
            local_released = bool(
                await run_in_threadpool(
                    asset_store.release_pre_provider,
                    turn_id=claim.turn_id,
                    principal_hash=principal_hash,
                )
            )
            cleanup_complete = local_released and bool(
                await run_in_threadpool(
                    app.state.media_requests.complete_video_terminal_failure_cleanup,
                    task_alias=f"nvt1_{claim.turn_id}",
                    principal_hash=principal_hash,
                )
            )
        except (PaidMediaAssetStoreError, DurableMediaRequestUnavailable):
            cleanup_complete = False
        if not cleanup_complete:
            raise _media_http_error(
                503,
                code="video_terminal_cleanup_pending",
                message="Terminal video failure is durable but capacity cleanup is pending.",
                retryable=False,
            )
    return public_result


async def _restore_durable_video_capacity(pool: Any) -> int:
    """Rebuild process-local admission from the durable nonterminal registry.

    Two snapshots close the terminal-poll race: a task completed between the
    first read and its restoration is released again, while a task committed
    during reconciliation is picked up by the second read.  Re-running this
    before every create also repairs leases whose bounded in-memory TTL elapsed.
    """

    first = await run_in_threadpool(
        app.state.media_requests.list_active_video_leases
    )
    for lease in first:
        pool.restore(
            kind="video",
            bucket_hash=lease.principal_hash,
            external_ids=(lease.task_alias,),
        )
    second = await run_in_threadpool(
        app.state.media_requests.list_active_video_leases
    )
    live_aliases = {lease.task_alias for lease in second}
    for lease in second:
        pool.restore(
            kind="video",
            bucket_hash=lease.principal_hash,
            external_ids=(lease.task_alias,),
        )
    for lease in first:
        if lease.task_alias not in live_aliases:
            pool.release_external("video", lease.task_alias)
    return len(second)


async def _execute_paid_image_generation(
    *,
    principal_hash: str,
    idempotency_key: str,
    body: Any,
    trace_id: str | None,
    runtime_api_key: str,
) -> tuple[dict[str, Any], bool]:
    """Shared paid image choke point for the public route and the web console.

    Every caller crosses the same durable claim, asset reservation, provider
    fence and fresh Root proof.  The returned boolean marks a durable replay.
    """
    router: Router = app.state.router
    usage: UsageLogger = app.state.usage
    try:
        _require_versioned_paid_media_body(body, video=False)
        if body.get("response_format") == "b64_json":
            raise ValueError("paid-media protocol v2 does not accept b64_json")
        req = ImageGenerationRequest(**body)
        req = req.model_copy(update={"response_format": "url"})
    except (ValidationError, TypeError, ValueError) as exc:
        raise _media_http_error(
            422,
            code="invalid_media_request",
            message="Paid media request body is invalid.",
            retryable=False,
        ) from exc
    claim = await _claim_paid_media_request(
        principal_hash=principal_hash,
        operation="images.create",
        idempotency_key=idempotency_key,
        payload=req.model_dump(mode="json", exclude_none=True),
    )
    if claim.state == "succeeded":
        if not isinstance(claim.response, dict):
            raise _media_http_error(
                503,
                code="media_replay_unavailable",
                message="Durable paid-media replay is unavailable.",
                retryable=False,
            )
        return claim.response, True
    route = await _resolve_paid_media_route_or_abandon(
        router=router,
        model=req.model,
        claim=claim,
    )
    provider = route.provider
    await _require_image_asset_v2_or_abandon(provider, claim)
    asset_store, _asset_epoch = await _reserve_paid_media_asset_capacity(
        claim=claim,
        principal_hash=principal_hash,
        operation="images.create",
    )
    provider_name = str(provider.name)
    upstream_model = str(route.upstream_model)
    tier = str(route.tier)
    started = time.time()
    call_context = ProviderCallContext(
        trace_id=trace_id,
        turn_id=claim.turn_id,
        workflow_id="paid_media:images.create",
        role="paid_media_create",
    )
    await _enter_paid_media_provider_phase(
        claim,
        principal_hash=principal_hash,
        asset_store=asset_store,
    )
    # Fence the durable provider phase first, then prove Root authority at the
    # last await boundary before invocation.  Checking Root before the durable
    # transition leaves a drift window while that transition is in flight.
    try:
        await _assert_paid_media_outbound_ready()
    except HTTPException:
        # Once provider_phase is durable, a crash cannot prove that invocation
        # did not start.  Keep the private reservation and require recovery.
        await _mark_paid_media_recovery_or_fail(claim)
        raise
    try:
        with bind_paid_media_authority(
            principal_hash=principal_hash,
            operation="images.create",
        ):
            result = await generate_image_asset_urls_with_accounting(
                provider,
                req,
                upstream_model,
                actual_model=req.model,
                call_context=call_context,
            )
    except ProviderError as e:
        await _mark_paid_media_recovery_or_fail(claim)
        await _log_usage_best_effort(
            usage,
            api_key=runtime_api_key, virtual_model=req.model, provider=provider_name,
            upstream_model=upstream_model, tier=tier, stream=0,
            status=f"error:{e.status_code}", latency_ms=int((time.time() - started) * 1000),
        )
        raise _media_http_error(
            _safe_media_provider_status(e.status_code),
            code="media_provider_error",
            message="Paid media provider request failed.",
            retryable=False,
        )
    except Exception:
        await _mark_paid_media_recovery_or_fail(claim)
        raise _media_http_error(
            502,
            code="media_provider_error",
            message="Paid media provider request failed.",
            retryable=False,
        )
    try:
        raw_assets = result.get("data") if isinstance(result, dict) else None
        if not isinstance(raw_assets, list) or not 1 <= len(raw_assets) <= 4:
            raise PaidMediaAssetStoreError(
                "provider v2 result has an invalid URL asset list"
            )
        descriptors = []
        for ordinal, raw_asset in enumerate(raw_assets):
            if (
                not isinstance(raw_asset, dict)
                or frozenset(raw_asset) != frozenset({"url"})
                or not isinstance(raw_asset.get("url"), str)
            ):
                raise PaidMediaAssetStoreError(
                    "provider v2 result contains ambiguous asset metadata"
                )
            descriptors.append(
                await run_in_threadpool(
                    asset_store.stage_url,
                    turn_id=claim.turn_id,
                    ordinal=ordinal,
                    url=raw_asset["url"],
                )
            )
        created = result.get("created")
        if (
            isinstance(created, bool)
            or not isinstance(created, int)
            or not 0 <= created <= (1 << 53) - 1
        ):
            created = int(time.time())
        asset_result = PaidMediaAssetResult(
            kind="image",
            created=created,
            turn_id=claim.turn_id,
            assets=tuple(descriptors),
        )
        committed_result = await run_in_threadpool(
            asset_store.finalize_result,
            asset_result,
        )
        public_result = asset_result_document(committed_result)
    except (
        PaidMediaAssetStoreError,
        PaidMediaAssetProtocolError,
        PublicFetchError,
        OSError,
        ValueError,
    ):
        await _mark_paid_media_recovery_or_fail(claim)
        raise _media_http_error(
            502,
            code="paid_media_asset_ingestion_failed",
            message="Provider result could not be committed as a verified private asset.",
            retryable=False,
        )
    await _persist_paid_media_success(claim, public_result)
    await _log_usage_best_effort(
        usage,
        api_key=runtime_api_key, virtual_model=req.model, provider=provider_name,
        upstream_model=upstream_model, tier=tier, stream=0, status="ok",
        latency_ms=int((time.time() - started) * 1000),
    )
    return public_result, False


@app.post("/v1/images/generations")
async def image_generations(
    request: Request,
    idempotency_key_header: str = Header(
        alias="Idempotency-Key",
        description="Stable client operation identifier for paid image creation.",
    ),
    runtime_api_key: str = Depends(require_paid_media_api_key),
):
    """生图（M3）：OpenAI 兼容。路由到支持生图的 provider（如 Agnes Image）。"""
    _require_paid_media_protocol_v2(request)
    idempotency_key = _required_media_idempotency_key(idempotency_key_header)
    body = await request.json()
    principal_hash = _request_paid_media_principal_hash(request)
    public_result, replayed = await _execute_paid_image_generation(
        principal_hash=principal_hash,
        idempotency_key=idempotency_key,
        body=body,
        trace_id=str(getattr(request.state, "trace_id", "") or "") or None,
        runtime_api_key=runtime_api_key,
    )
    return _paid_media_response(public_result, replayed=replayed)


@app.post("/v1/orchestrate/panel")
async def orchestrate_panel(request: Request, api_key: str = Depends(require_api_key)):
    """M4 协作编排 · 议会汇总：多个 panelists 独立作答 → judge 综合。"""
    body = await request.json()
    try:
        spec = PanelWorkflowRequest.model_validate(body)
        result = await run_panel(
            app.state.router,
            prompt=spec.prompt,
            panelists=spec.panelists,
            judge=spec.judge,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="协作议会参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="协作模型输出超过安全上限") from exc
    return JSONResponse(result)


def _validated_git_repo(value: Any) -> str:
    """Resolve an exact existing repository root for capability binding."""

    raw = str(value or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="需要 repo")
    try:
        repo = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail="repo 不存在或无法解析") from exc
    if not repo.is_dir() or repo.parent == repo or not (repo / ".git").exists():
        raise HTTPException(status_code=422, detail="repo 必须是现有 Git 仓库根目录")
    return str(repo)


@app.post("/v1/orchestrate/coding")
async def orchestrate_coding(request: Request, _: str = Depends(require_api_key)):
    """M4 协作编排 · 编程团队：规划 → 并行实现(各 agent 一个 worktree) → 评审。"""
    raise HTTPException(
        status_code=503,
        detail="编程 CLI 团队已关闭：需要独立低权限执行 worker 后才能启用",
    )
    body = await request.json()
    repo = _validated_git_repo(body.get("repo"))
    task = (body.get("task") or "").strip()
    planner = str(body.get("planner") or "")
    reviewer = str(body.get("reviewer") or "")
    implementers = body.get("implementers") or []
    if not task or not planner or not reviewer or not implementers:
        raise HTTPException(
            status_code=422, detail="需要 repo、task、planner、reviewer、implementers"
        )
    if app.state.router.resolve(planner) is None or app.state.router.resolve(reviewer) is None:
        raise HTTPException(status_code=422, detail="planner/reviewer 必须是当前已连接模型")
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=repo,
        user_id=str(body.get("user_id") or get_settings().agent_user_id or "owner"),
        scope="orchestrate_coding",
        mode="auto",
        require_explicit_capability=True,
        payload_extra={
            "planner": planner,
            "reviewer": reviewer,
            "implementers": implementers,
        },
    )
    if held is not None:
        return held
    try:
        result = await run_coding_team(
            app.state.router,
            repo=repo,
            task=task,
            planner=planner,
            implementers=implementers,
            reviewer=reviewer,
        )
    except (ValueError, TypeError) as exc:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return JSONResponse(result)


@app.post("/v1/orchestrate/arch-editor")
async def orchestrate_arch_editor(request: Request, _: str = Depends(require_api_key)):
    """架构师/编辑：强模型规划 → 便宜模型出文件代码（省 token 的编程模式）。"""
    raise HTTPException(
        status_code=503,
        detail="架构编辑执行已关闭：Git/worktree 写入需要独立低权限执行 worker 后才能启用",
    )
    body = await request.json()
    repo = _validated_git_repo(body.get("repo"))
    task = (body.get("task") or "").strip()
    architect = str(body.get("architect") or "")
    editor = str(body.get("editor") or "")
    if not task or not architect or not editor:
        raise HTTPException(status_code=422, detail="需要 repo、task、architect、editor")
    if app.state.router.resolve(architect) is None or app.state.router.resolve(editor) is None:
        raise HTTPException(status_code=422, detail="architect/editor 必须是当前已连接模型")
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=repo,
        user_id=str(body.get("user_id") or get_settings().agent_user_id or "owner"),
        scope="orchestrate_arch_editor",
        mode="auto",
        require_explicit_capability=True,
        payload_extra={"architect": architect, "editor": editor},
    )
    if held is not None:
        return held
    try:
        result = await run_arch_editor(
            app.state.router, repo=repo, task=task, architect=architect, editor=editor
        )
    except Exception:
        if approval_id:
            app.state.approvals.finish_action(approval_id, success=False)
        raise
    if approval_id:
        app.state.approvals.finish_action(approval_id, success=True)
    return JSONResponse(result)


def _summary_clear_spec(conv_id: str) -> dict[str, Any]:
    store = conv_summary._get_store()  # noqa: SLF001 - module owns no public reader
    if store is None:
        raise HTTPException(status_code=503, detail="对话摘要存储不可用")
    summary, covered = store.get(conv_id)
    state_sha256, _ = _snapshot_hash([(summary, covered)])
    return {
        "target": {"kind": "conversation_summary", "conversation_id": conv_id},
        "snapshot": {
            "sha256": state_sha256,
            "covered": covered,
            "exists": bool(summary or covered),
        },
    }


@app.post("/v1/conv/{conv_id}/clear-summary")
async def clear_conv_summary(
    conv_id: str, request: Request, _: str = Depends(require_api_key)
):
    """Clear one exact reviewed rolling-summary snapshot after approval."""
    normalized_conv_id = _normalized_mutation_id(
        conv_id, label="conversation_id", max_length=256
    )
    body = await _destructive_request_body(request)
    user_id = _destructive_user_id(body)
    spec = _summary_clear_spec(normalized_conv_id)
    if not _has_approval_id(body) and not spec["snapshot"]["exists"]:
        return {
            "ok": True,
            "conversation_id": normalized_conv_id,
            "already_empty": True,
        }
    task = f"清空对话滚动摘要：{normalized_conv_id}"
    approval_id, held = await _action_capability(
        body=body,
        router=app.state.router,
        task=task,
        workdir=str(Path(get_settings().usage_db_path).parent.resolve()),
        user_id=user_id,
        scope="conversation_summary_clear",
        mode="full",
        require_explicit_capability=True,
        payload_extra=spec,
    )
    if held is not None:
        return held
    try:
        if _summary_clear_spec(normalized_conv_id) != spec:
            raise HTTPException(status_code=409, detail="对话摘要已变化，请重新审批")
        conv_summary.clear(normalized_conv_id)
        if _summary_clear_spec(normalized_conv_id)["snapshot"]["exists"]:
            raise RuntimeError("conversation summary clear did not remove the reviewed target")
    except Exception:
        app.state.approvals.finish_action(approval_id, success=False)
        raise
    app.state.approvals.finish_action(approval_id, success=True)
    return {"ok": True, "conversation_id": normalized_conv_id}


@app.post("/v1/route")
async def route_mode(request: Request, api_key: str = Depends(require_api_key)):
    """单答模式调度：auto(自动智能·默认) / smart / cascade / economy / best / harness。"""
    body = await request.json()
    mode = body.get("mode", "smart")
    messages = body.get("messages") or []
    # 长对话累积滚动摘要（带 conversation_id 才启用；老对话折进摘要、近的原样留）。
    messages = await conv_summary.rolling_compress(
        app.state.router, str(body.get("conversation_id") or ""), messages
    ) or messages
    _is_short_followup = _inject_followup_context(messages)
    reasoning_effort = str(body.get("reasoning_effort") or "").strip().lower()
    if reasoning_effort in {"low", "medium", "high"}:
        effort_zh = {"low": "低", "medium": "中", "high": "高"}[reasoning_effort]
        messages.insert(
            0,
            {
                "role": "system",
                "content": f"本次推理级别：{effort_zh}。低=快速简答；中=平衡；高=更充分地核查与规划，但最终仍只输出结论和必要过程摘要。",
            },
        )
    if body.get("web_search") and not _is_short_followup:
        try:
            _web_req = ChatCompletionRequest(
                model=str(body.get("model") or get_settings().bridge_model),
                messages=messages,
                web_search=True,
            )
            await websearch.maybe_augment_request(_web_req)
            messages = [m.model_dump(exclude_none=True) for m in _web_req.messages]
        except Exception:  # noqa: BLE001
            pass
    # 注入机主长期记忆（与 /v1/chat/completions 一致：让 auto/smart 等模式也带上记忆，行为统一）
    try:
        _um = next(
            (
                m.get("content")
                for m in reversed(messages)
                if m.get("role") == "user" and isinstance(m.get("content"), str)
            ),
            "",
        )
        _note, _ = memory_system_note(app.state.memory, get_settings().agent_user_id or "owner", _um)
        if _note:
            _li = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)
            _mm = {"role": "system", "content": _note}
            if _li >= 0:
                messages.insert(_li, _mm)
            else:
                messages.append(_mm)
    except Exception:  # noqa: BLE001
        pass
    fn = SINGLE_ANSWER_MODES.get(mode)
    if fn is None:
        raise HTTPException(status_code=422, detail=f"未知模式 {mode}")
    try:
        result = await fn(app.state.router, messages)
    except ProviderError as e:
        raise _public_provider_http_error(e) from e
    # 记账：按最终命中的真实模型记，用量看板能正确归类
    meta = result.get("_route", {})
    u = result.get("usage") or {}
    _pd = u.get("prompt_tokens_details") or {}
    await _log_usage_best_effort(
        app.state.usage,
        api_key=api_key,
        virtual_model=mode,
        provider=str(meta.get("provider") or "mode-unserved"),
        upstream_model=str(meta.get("upstream_model") or ""),
        tier=str(meta.get("tier") or "mode"),
        prompt_tokens=int(u.get("prompt_tokens", 0) or 0),
        completion_tokens=int(u.get("completion_tokens", 0) or 0),
        total_tokens=int(u.get("total_tokens", 0) or 0),
        cached_tokens=int(u.get("cached_tokens", 0) or _pd.get("cached_tokens", 0) or 0),
        cost_usd=float(u.get("cost_usd", 0) or 0),
        stream=0,
        status="ok",
        latency_ms=0,
    )
    return JSONResponse(result)


@app.post("/v1/orchestrate/debate")
async def orchestrate_debate(request: Request, api_key: str = Depends(require_api_key)):
    """辩论：多模型多轮互评 → 裁判综合。"""
    body = await request.json()
    try:
        spec = DebateWorkflowRequest.model_validate(body)
        result = await run_debate(
            app.state.router,
            prompt=spec.prompt,
            debaters=spec.debaters,
            judge=spec.judge,
            rounds=spec.rounds,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="辩论参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="辩论模型输出超过安全上限") from exc
    return JSONResponse(result)


@app.post("/v1/orchestrate/decompose")
async def orchestrate_decompose(request: Request, api_key: str = Depends(require_api_key)):
    """拆解分工：规划→子任务各派最便宜能做的→汇总。"""
    body = await request.json()
    try:
        spec = DecomposeWorkflowRequest.model_validate(body)
        result = await run_decompose(
            app.state.router,
            task=spec.task,
            planner=spec.planner,
            aggregator=spec.aggregator,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="任务拆解参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="任务拆解模型输出超过安全上限") from exc
    return JSONResponse(result)


@app.post("/v1/orchestrate/pipeline")
async def orchestrate_pipeline(request: Request, api_key: str = Depends(require_api_key)):
    """流水线：固定工序，每步指定模型。"""
    body = await request.json()
    try:
        spec = PipelineWorkflowRequest.model_validate(body)
        try:
            lease = app.state.router.plugin_kernel.borrow_service(
                PIPELINE_WORKFLOW_SERVICE
            )
        except ServiceNotFound as exc:
            raise HTTPException(
                status_code=503,
                detail="流水线工作流插件当前不可用",
            ) from exc
        try:
            service = lease.value
            result = await service(
                app.state.router,
                prompt=spec.prompt,
                steps=[step.model_dump() for step in spec.steps],
            )
        finally:
            lease.release()
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="流水线参数不符合资源限制") from exc
    except WorkflowOutputLimitError as exc:
        raise HTTPException(status_code=502, detail="流水线模型输出超过安全上限") from exc
    except DurableWorkflowEventUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="流水线持久事件日志当前不可用",
            headers={"X-Nachuan-Retry-Safe": "false"},
        ) from exc
    return JSONResponse(result)


def _video_job_ids(payload: Any) -> tuple[str, ...]:
    if not isinstance(payload, dict):
        return ()
    nested = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    out: list[str] = []
    for key in ("video_id", "task_id", "id", "request_id", "upstream_task_id"):
        value = payload.get(key) or nested.get(key)
        item = str(value or "").strip()
        if item and len(item) <= 256 and not any(ord(ch) < 32 for ch in item) and item not in out:
            out.append(item)
    return tuple(out)


def _video_job_terminal(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    nested = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    status = str(payload.get("status") or nested.get("status") or "").strip().lower()
    if status in {
        "complete",
        "completed",
        "done",
        "success",
        "succeeded",
        "failure",
        "failed",
        "error",
        "cancelled",
        "canceled",
    }:
        return True
    if status:
        return False
    for key in ("url", "video_url", "output_url", "download_url"):
        if payload.get(key) or nested.get(key):
            return True
    return False


def _video_job_failed(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    nested = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    status = str(payload.get("status") or nested.get("status") or "").strip().lower()
    return status in {"failure", "failed", "error", "cancelled", "canceled"}


def _video_terminal_asset_url(payload: Any) -> str:
    """Return one unambiguous HTTPS terminal URL from bounded provider metadata."""

    if not isinstance(payload, dict):
        raise ValueError("video terminal metadata is not an object")
    paths = (
        ("url",),
        ("video_url",),
        ("output_url",),
        ("download_url",),
        ("data", "url"),
        ("data", "video_url"),
        ("data", "output_url"),
        ("result", "url"),
        ("result", "video_url"),
        ("video", "url"),
        ("metadata", "url"),
    )
    candidates: list[str] = []
    for path in paths:
        value: Any = payload
        for segment in path:
            value = value.get(segment) if isinstance(value, dict) else None
        if value is None:
            continue
        if not isinstance(value, str) or not 1 <= len(value) <= 8192:
            raise ValueError("video terminal URL metadata is invalid")
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ValueError("video terminal URL metadata is invalid") from exc
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ValueError("video terminal URL metadata is invalid")
        if value not in candidates:
            candidates.append(value)
    if len(candidates) != 1:
        raise ValueError("video terminal URL metadata is ambiguous")
    return candidates[0]


def _settle_video_background_lease(pool: Any, lease: str, result: Any) -> None:
    if _video_job_terminal(result):
        pool.release(lease)
        return
    aliases = _video_job_ids(result)
    # No provider id means an unobservable remote job may still exist.  The
    # pool's hard 5-minute..24-hour TTL bounds this conservative lease.
    if aliases and not pool.bind(lease, aliases):
        pool.release(lease)


async def _execute_paid_video_generation(
    *,
    principal_hash: str,
    idempotency_key: str,
    body: Any,
    trace_id: str | None,
) -> tuple[dict[str, Any], bool]:
    """Shared paid video choke point for the public route and the web console.

    Every caller crosses the same durable claim, asset reservation, background
    slot, provider fence and fresh Root proof.  The boolean marks a replay.
    """
    try:
        _require_versioned_paid_media_body(body, video=True)
        req = VideoGenerationRequest(**body)
    except (ValidationError, TypeError, ValueError) as exc:
        raise _media_http_error(
            422,
            code="invalid_media_request",
            message="Paid media request body is invalid.",
            retryable=False,
        ) from exc
    claim = await _claim_paid_media_request(
        principal_hash=principal_hash,
        operation="videos.create",
        idempotency_key=idempotency_key,
        payload=req.model_dump(mode="json", exclude_none=True),
    )
    if claim.state == "succeeded":
        if not isinstance(claim.response, dict):
            raise _media_http_error(
                503,
                code="media_replay_unavailable",
                message="Durable paid-media replay is unavailable.",
                retryable=False,
            )
        return claim.response, True
    route = await _resolve_paid_media_route_or_abandon(
        router=app.state.router,
        model=req.model,
        claim=claim,
    )
    try:
        provider_domain = _paid_video_provider_domain(route)
        provider_credential_domain = _paid_video_provider_credential_domain(
            route, provider_domain
        )
    except HTTPException:
        await _abandon_paid_media_pre_provider(claim)
        raise
    provider = route.provider
    await _require_video_asset_v2_or_abandon(provider, claim)
    try:
        await trusted_media_readiness_receipt()
    except Exception as exc:
        await _abandon_paid_media_pre_provider(claim)
        raise _media_http_error(
            503,
            code="media_probe_unavailable",
            message="Trusted media probe is unavailable; no provider call was made.",
            retryable=True,
        ) from exc
    asset_store, _asset_epoch = await _reserve_paid_media_asset_capacity(
        claim=claim,
        principal_hash=principal_hash,
        operation="videos.create",
    )
    upstream_model = str(route.upstream_model)
    pool = get_background_job_pool()
    try:
        await _restore_durable_video_capacity(pool)
    except (DurableMediaRequestUnavailable, ValueError) as exc:
        await _release_paid_media_assets_pre_provider(
            claim=claim,
            principal_hash=principal_hash,
            asset_store=asset_store,
        )
        raise _media_http_error(
            503,
            code="video_capacity_registry_unavailable",
            message="Paid video capacity could not be safely rebuilt.",
            retryable=False,
        ) from exc
    lease = pool.try_acquire(kind="video", bucket_hash=principal_hash)
    if lease is None:
        await _release_paid_media_assets_pre_provider(
            claim=claim,
            principal_hash=principal_hash,
            asset_store=asset_store,
        )
        raise BackgroundJobLimitExceeded("background video capacity reached")
    lease_context = set_background_job_lease("video", lease)
    call_context = ProviderCallContext(
        trace_id=trace_id,
        turn_id=claim.turn_id,
        workflow_id="paid_media:videos.create",
        role="paid_media_create",
    )
    try:
        try:
            await _enter_paid_media_provider_phase(
                claim,
                principal_hash=principal_hash,
                asset_store=asset_store,
            )
        except HTTPException:
            pool.release(lease)
            raise
        try:
            await _assert_paid_media_outbound_ready()
        except HTTPException:
            try:
                await _mark_paid_media_recovery_or_fail(claim)
            finally:
                # No provider was invoked, so the process-local execution slot
                # is safe to release even though durable authority stays held.
                pool.release(lease)
            raise
        try:
            with bind_paid_media_authority(
                principal_hash=principal_hash,
                operation="videos.create",
            ):
                result = await generate_video_with_accounting(
                    provider,
                    req,
                    upstream_model,
                    actual_model=req.model,
                    call_context=call_context,
                )
        except ProviderError as e:
            await _mark_paid_media_recovery_or_fail(claim)
            # The request crossed the provider boundary.  With no trustworthy
            # task id, retain the unbound slot only until the pool's bounded TTL.
            raise _media_http_error(
                _safe_media_provider_status(e.status_code),
                code="media_provider_error",
                message="Paid media provider request failed.",
                retryable=False,
            )
        except Exception:
            await _mark_paid_media_recovery_or_fail(claim)
            raise _media_http_error(
                502,
                code="media_provider_error",
                message="Paid media provider request failed.",
                retryable=False,
            )
        provider_result = result
        try:
            result = await _persist_paid_video_success(
                claim=claim,
                principal_hash=principal_hash,
                requested_model=req.model,
                route=route,
                provider_domain=provider_domain,
                provider_credential_domain=provider_credential_domain,
                asset_store=asset_store,
                result=result,
            )
        except HTTPException:
            # The provider result exists but cannot be returned until it is
            # durable.  Still bind/release the background slot deterministically.
            _settle_video_background_lease(pool, lease, result)
            raise
        settlement_result = (
            provider_result if _video_job_terminal(provider_result) else result
        )
    finally:
        reset_background_job_lease(lease_context)
    _settle_video_background_lease(pool, lease, settlement_result)
    return result, False


@app.post("/v1/videos/generations")
async def create_video(
    request: Request,
    idempotency_key_header: str = Header(
        alias="Idempotency-Key",
        description="Stable client operation identifier for paid video creation.",
    ),
    _runtime_api_key: str = Depends(require_paid_media_api_key),
):
    """生视频（异步）：创建任务，返回上游响应（含 task_id）。"""
    _require_paid_media_protocol_v2(request)
    idempotency_key = _required_media_idempotency_key(idempotency_key_header)
    body = await request.json()
    principal_hash = _request_paid_media_principal_hash(request)
    result, replayed = await _execute_paid_video_generation(
        principal_hash=principal_hash,
        idempotency_key=idempotency_key,
        body=body,
        trace_id=str(getattr(request.state, "trace_id", "") or "") or None,
    )
    return _paid_media_response(result, replayed=replayed)


@app.get("/v1/videos/fetch")
async def fetch_video_bytes(url: str, _: str = Depends(require_api_key)):
    """引擎代下海外成片：前端 <video> 直连 agnes-ai.space 等海外域名常拉不动（灰播放键）→
    引擎把视频拉回来，前端据此做本地 blob 播放。引擎本身能连上游（建任务/轮询都走它），所以这条最稳。
    注意：必须定义在 /v1/videos/{task_id} 之前，否则 "fetch" 会被当成 task_id 匹配到轮询路由。"""
    from fastapi.responses import FileResponse
    from starlette.background import BackgroundTask

    try:
        fetched = await run_in_threadpool(
            download_public_file,
            url,
            max_bytes=512 * 1024 * 1024,
            allowed_type_prefixes=("video/",),
            allowed_exact_types=("application/octet-stream",),
            total_timeout=180.0,
            idle_timeout=20.0,
            max_redirects=5,
            headers={"Accept": "video/*, application/octet-stream;q=0.8"},
        )
    except PublicFetchSecurityError as exc:
        raise HTTPException(status_code=400, detail="仅允许可验证的公网视频 URL") from exc
    except PublicFetchTooLarge as exc:
        raise HTTPException(status_code=413, detail="成片超过 512MB 安全上限") from exc
    except PublicFetchTimeout as exc:
        raise HTTPException(status_code=504, detail="代下成片超过总时限或读取空闲时限") from exc
    except PublicFetchContentTypeError as exc:
        raise HTTPException(status_code=502, detail="上游返回的不是视频内容") from exc
    except (PublicFetchHTTPError, PublicFetchError) as exc:
        raise HTTPException(status_code=502, detail="代下成片失败") from exc

    def _cleanup() -> None:
        try:
            os.remove(fetched.path)
        except OSError:
            pass

    return FileResponse(
        fetched.path,
        media_type=fetched.content_type,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        background=BackgroundTask(_cleanup),
    )


def _paid_video_poll_response(
    payload: dict[str, object], *, retry_after_seconds: int = 0
) -> JSONResponse:
    headers = {
        "Cache-Control": "no-store",
        PAID_MEDIA_PROTOCOL_HEADER: PAID_MEDIA_PROTOCOL_VERSION,
    }
    if retry_after_seconds:
        headers["Retry-After"] = str(retry_after_seconds)
    return JSONResponse(payload, headers=headers)


async def _commit_prepared_paid_video_asset(
    *,
    task_alias: str,
    principal_hash: str,
    fencing_token: str,
    provider_result: dict[str, object],
    asset_store: PaidMediaAssetStore,
    prepared_token: str = "",
    prepared_asset_response: dict[str, object] | None = None,
    authority_state: Any | None = None,
) -> tuple[bool, dict[str, object]]:
    """Recover or publish one terminal video without repeating provider work."""

    state = app.state if authority_state is None else authority_state
    turn_id = task_alias.removeprefix("nvt1_")
    if prepared_token:
        token = prepared_token
        asset_response = (
            dict(prepared_asset_response)
            if isinstance(prepared_asset_response, dict)
            else None
        )
    else:
        prepared = await run_in_threadpool(
            state.media_requests.prepare_video_poll_asset,
            task_alias=task_alias,
            principal_hash=principal_hash,
            fencing_token=fencing_token,
            provider_response=provider_result,
        )
        token = prepared.token
        asset_response = prepared.asset_response

    descriptor = await run_in_threadpool(
        asset_store.describe_prepared_asset,
        turn_id=turn_id,
        principal_hash=principal_hash,
        epoch=asset_store.epoch,
        operation="videos.create",
        token=token,
    )
    if descriptor is None:
        if asset_response is not None:
            raise PaidMediaAssetStoreError(
                "durable prepared asset is missing from the private store"
            )
        descriptor = await run_in_threadpool(
            asset_store.stage_url,
            turn_id=turn_id,
            ordinal=0,
            url=_video_terminal_asset_url(provider_result),
            prepared_token=token,
        )

    if asset_response is None:
        created = provider_result.get("created")
        if (
            isinstance(created, bool)
            or not isinstance(created, int)
            or not 0 <= created <= (1 << 53) - 1
        ):
            created = int(time.time())
        asset_response = asset_result_document(
            PaidMediaAssetResult(
                kind="video",
                created=created,
                turn_id=turn_id,
                assets=(descriptor,),
            )
        )

    attached = await run_in_threadpool(
        state.media_requests.attach_video_poll_asset,
        task_alias=task_alias,
        principal_hash=principal_hash,
        fencing_token=fencing_token,
        response=asset_response,
    )
    if not isinstance(attached.asset_response, dict):
        raise DurableMediaRequestUnavailable(
            "prepared video asset result is unavailable"
        )
    await run_in_threadpool(
        asset_store.finalize_prepared_result,
        attached.asset_response,
        principal_hash=principal_hash,
        epoch=asset_store.epoch,
        operation="videos.create",
    )
    return await run_in_threadpool(
        state.media_requests.commit_prepared_video_poll_asset,
        task_alias=task_alias,
        principal_hash=principal_hash,
        fencing_token=fencing_token,
        prepare_sha256=attached.prepare_sha256,
    )


async def _complete_video_terminal_failure_cleanup(
    *,
    task_alias: str,
    turn_id: str,
    principal_hash: str,
    asset_store: PaidMediaAssetStore,
) -> None:
    try:
        local_released = bool(
            await run_in_threadpool(
                asset_store.release_pre_provider,
                turn_id=turn_id,
                principal_hash=principal_hash,
            )
        )
        completed = local_released and bool(
            await run_in_threadpool(
                app.state.media_requests.complete_video_terminal_failure_cleanup,
                task_alias=task_alias,
                principal_hash=principal_hash,
            )
        )
    except (PaidMediaAssetStoreError, DurableMediaRequestUnavailable):
        completed = False
    if not completed:
        raise _media_http_error(
            503,
            code="video_terminal_cleanup_pending",
            message="Terminal video failure is durable but capacity cleanup is pending.",
            retryable=False,
        )


async def _poll_paid_video_once(
    *,
    principal_hash: str,
    task_id: str,
    model: str | None = None,
) -> JSONResponse:
    """Poll an owner-bound alias through the provider route frozen at creation."""

    asset_store = getattr(app.state, "paid_media_assets", None)
    if not isinstance(asset_store, PaidMediaAssetStore):
        raise _media_http_error(
            503,
            code="paid_media_asset_store_unavailable",
            message="Paid media asset storage is unavailable.",
            retryable=False,
        )

    try:
        claim = await run_in_threadpool(
            app.state.media_requests.begin_video_poll,
            task_alias=task_id,
            principal_hash=principal_hash,
        )
    except (DurableMediaRequestUnavailable, ValueError) as exc:
        raise _media_http_error(
            503,
            code="video_task_registry_unavailable",
            message="Durable paid video task registry is unavailable.",
            retryable=False,
        ) from exc
    if claim.state == "not_found":
        raise _media_http_error(
            404,
            code="video_task_not_found",
            message="Paid video task was not found for this capability.",
            retryable=False,
        )
    if claim.state in {"terminal", "deferred"}:
        response = claim.response or {"status": "processing"}
        if claim.state == "terminal" and _video_job_failed(response):
            await _complete_video_terminal_failure_cleanup(
                task_alias=task_id,
                turn_id=task_id.removeprefix("nvt1_"),
                principal_hash=principal_hash,
                asset_store=asset_store,
            )
        return _paid_video_poll_response(
            response,
            retry_after_seconds=claim.retry_after_seconds,
        )

    async def release_poll_fence() -> None:
        try:
            await run_in_threadpool(
                app.state.media_requests.fail_video_poll,
                task_alias=task_id,
                principal_hash=principal_hash,
                fencing_token=claim.fencing_token,
            )
        except DurableMediaRequestUnavailable:
            pass

    if model is not None and str(model) != claim.requested_model:
        await release_poll_fence()
        raise _media_http_error(
            409,
            code="video_route_changed",
            message="Paid video task is bound to a different frozen route.",
            retryable=False,
        )
    if claim.state == "prepared":
        if not isinstance(claim.prepared_provider_response, dict):
            await release_poll_fence()
            raise _media_http_error(
                503,
                code="video_task_registry_unavailable",
                message="Durable paid video task registry is unavailable.",
                retryable=False,
            )
        try:
            persisted, public_result = await _commit_prepared_paid_video_asset(
                task_alias=task_id,
                principal_hash=principal_hash,
                fencing_token=claim.fencing_token,
                provider_result=claim.prepared_provider_response,
                asset_store=asset_store,
                prepared_token=claim.prepared_token,
                prepared_asset_response=claim.prepared_asset_response,
            )
        except MediaBinaryUnavailable as exc:
            await release_poll_fence()
            raise _media_http_error(
                503,
                code="media_probe_unavailable",
                message=(
                    "Trusted media probe is unavailable; "
                    "provider work will not be repeated."
                ),
                retryable=True,
            ) from exc
        except (
            ValueError,
            PaidMediaAssetStoreError,
            PaidMediaAssetProtocolError,
            PublicFetchError,
            OSError,
        ) as exc:
            await release_poll_fence()
            raise _media_http_error(
                502,
                code="paid_video_asset_ingestion_failed",
                message="Terminal video could not be committed as a verified private asset.",
                retryable=False,
            ) from exc
        except DurableMediaRequestUnavailable as exc:
            await release_poll_fence()
            raise _media_http_error(
                503,
                code="video_poll_persistence_unavailable",
                message="Paid video poll result could not be persisted.",
                retryable=False,
            ) from exc
        if not persisted:
            raise _media_http_error(
                409,
                code="video_poll_fence_lost",
                message="Paid video poll ownership was lost.",
                retryable=True,
            )
        get_background_job_pool().release_external("video", task_id)
        return _paid_video_poll_response(public_result)

    try:
        route = app.state.router.resolve(claim.requested_model)
    except Exception:
        route = None
    route_matches = (
        route is not None
        and str(getattr(route.provider, "name", "") or "") == claim.provider_name
        and str(getattr(route, "upstream_model", "") or "") == claim.upstream_model
    )
    if route_matches:
        try:
            current_provider_domain = _paid_video_provider_domain(route)
            route_matches = (
                current_provider_domain == claim.provider_domain
                and _paid_video_provider_credential_domain(
                    route, current_provider_domain
                )
                == claim.provider_credential_domain
            )
        except HTTPException:
            route_matches = False
    if not route_matches:
        await release_poll_fence()
        raise _media_http_error(
            409,
            code="video_route_changed",
            message="Paid video provider route changed; the frozen route was not used.",
            retryable=False,
        )
    provider = route.provider
    if not _provider_supports_paid_media_video_asset_v2(provider):
        await release_poll_fence()
        raise _media_http_error(
            503,
            code="paid_media_video_protocol_unsupported",
            message="Paid video asset protocol v2 is not enabled for this provider.",
            retryable=False,
        )
    call_context = ProviderCallContext(
        turn_id=task_id.removeprefix("nvt1_"),
        workflow_id="paid_media:videos.poll",
        role="paid_media_poll",
    )
    try:
        await _assert_paid_media_outbound_ready()
    except HTTPException:
        await release_poll_fence()
        raise
    try:
        result = await get_video_with_accounting(
            provider,
            claim.upstream_task_id,
            requested_model=claim.requested_model,
            actual_model=claim.requested_model,
            upstream_model=claim.upstream_model,
            attempt=claim.attempt,
            call_context=call_context,
        )
    except ProviderError as e:
        await release_poll_fence()
        status_code = _safe_media_provider_status(e.status_code)
        raise _media_http_error(
            status_code,
            code="video_provider_poll_error",
            message="Paid video provider poll failed.",
            retryable=_media_provider_poll_retryable(status_code),
        ) from e
    except Exception as exc:
        await release_poll_fence()
        raise _media_http_error(
            502,
            code="video_provider_poll_error",
            message="Paid video provider poll failed.",
            retryable=True,
        ) from exc
    terminal = _video_job_terminal(result)
    terminal_failed = terminal and _video_job_failed(result)
    try:
        if terminal and not terminal_failed:
            persisted, public_result = await _commit_prepared_paid_video_asset(
                task_alias=task_id,
                principal_hash=principal_hash,
                fencing_token=claim.fencing_token,
                provider_result=result,
                asset_store=asset_store,
            )
        else:
            persisted, public_result = await run_in_threadpool(
                app.state.media_requests.finish_video_poll,
                task_alias=task_id,
                principal_hash=principal_hash,
                fencing_token=claim.fencing_token,
                response=result,
                terminal=terminal,
            )
            if persisted and terminal_failed:
                await _complete_video_terminal_failure_cleanup(
                    task_alias=task_id,
                    turn_id=task_id.removeprefix("nvt1_"),
                    principal_hash=principal_hash,
                    asset_store=asset_store,
                )
    except MediaBinaryUnavailable as exc:
        await release_poll_fence()
        raise _media_http_error(
            503,
            code="media_probe_unavailable",
            message=(
                "Trusted media probe is unavailable; "
                "provider work will not be repeated."
            ),
            retryable=True,
        ) from exc
    except (
        ValueError,
        PaidMediaAssetStoreError,
        PaidMediaAssetProtocolError,
        PublicFetchError,
        OSError,
    ) as exc:
        await release_poll_fence()
        raise _media_http_error(
            502,
            code="paid_video_asset_ingestion_failed",
            message="Terminal video could not be committed as a verified private asset.",
            retryable=False,
        ) from exc
    except DurableMediaRequestUnavailable as exc:
        await release_poll_fence()
        raise _media_http_error(
            503,
            code="video_poll_persistence_unavailable",
            message="Paid video poll result could not be persisted.",
            retryable=False,
        ) from exc
    if not persisted:
        raise _media_http_error(
            409,
            code="video_poll_fence_lost",
            message="Paid video poll ownership was lost.",
            retryable=True,
        )
    pool = get_background_job_pool()
    if terminal:
        pool.release_external("video", task_id)
    else:
        pool.renew_external("video", task_id)
    return _paid_video_poll_response(public_result)


_VIDEO_POLL_SINGLEFLIGHTS: dict[tuple[str, str, str], asyncio.Task[JSONResponse]] = {}


async def _poll_paid_video_singleflight(
    *,
    principal_hash: str,
    task_id: str,
    model: str | None = None,
) -> JSONResponse:
    key = (principal_hash, task_id, str(model or ""))
    existing = _VIDEO_POLL_SINGLEFLIGHTS.get(key)
    if existing is not None:
        return await asyncio.shield(existing)
    flight = asyncio.create_task(
        _poll_paid_video_once(
            principal_hash=principal_hash,
            task_id=task_id,
            model=model,
        )
    )
    _VIDEO_POLL_SINGLEFLIGHTS[key] = flight

    def cleanup(done: asyncio.Task[JSONResponse]) -> None:
        if _VIDEO_POLL_SINGLEFLIGHTS.get(key) is done:
            _VIDEO_POLL_SINGLEFLIGHTS.pop(key, None)

    flight.add_done_callback(cleanup)
    return await asyncio.shield(flight)


@app.get("/v1/videos/{task_id}")
async def poll_video(
    request: Request,
    task_id: str,
    model: str | None = None,
    _runtime_api_key: str = Depends(require_paid_media_api_key),
) -> JSONResponse:
    _require_paid_media_protocol_v2(request)
    principal_hash = _request_paid_media_principal_hash(request)
    return await _poll_paid_video_singleflight(
        principal_hash=principal_hash,
        task_id=task_id,
        model=model,
    )


@app.get("/v1/scoreboard")
async def get_scoreboard(_: str = Depends(require_api_key)) -> dict[str, Any]:
    """只读战绩看板（F6）：返回记分牌全表（每行含胜率），供桌面「进化 · 战绩」页。

    读失败一律降级为空表（scoreboard.dump_all 内部已全吞异常），永不 500。
    """
    return {"rows": scoreboard.dump_all()}


def _stage_ready_installation_principal(public_app: FastAPI) -> str | None:
    """Return the exact Root principal committed to current FastAPI state.

    The Desktop-provided Vault digest is a boot-local attestation made by the
    already authenticated Main process.  It is not independently readable by
    Gateway.  Gateway does independently validate the Root epoch principal and
    its paid-media derivation before the session wrapper may latch that digest.
    """

    if (
        str(getattr(public_app.state, "paid_media_authority_mode", "") or "")
        != "installation-root"
    ):
        return None
    root_principal = getattr(
        public_app.state, "paid_media_root_principal", None
    )
    installation_id = getattr(
        public_app.state, "paid_media_installation_id", None
    )
    epoch = getattr(public_app.state, "paid_media_epoch", None)
    paid_principal = getattr(public_app.state, "paid_media_principal", None)
    if (
        not isinstance(root_principal, str)
        or re.fullmatch(r"[0-9a-f]{64}", root_principal) is None
        or root_principal == "0" * 64
        or not isinstance(installation_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", installation_id) is None
        or installation_id == "0" * 64
        or type(epoch) is not int
        or not 1 <= epoch <= (1 << 63) - 1
        or not isinstance(paid_principal, str)
    ):
        return None
    try:
        expected_root = installation_principal(installation_id, epoch)
        expected_paid = stable_paid_principal(root_principal)
    except (InstallationRootError, TypeError, ValueError):
        return None
    if not hmac.compare_digest(expected_root, root_principal):
        return None
    if not hmac.compare_digest(expected_paid, paid_principal):
        return None
    return root_principal


def _compose_gateway_asgi_app(
    public_app: FastAPI,
    *,
    packaged: bool,
    configured_port: int | None = None,
    environ: Mapping[str, str] | None = None,
    pid_provider: Callable[[], int] = os.getpid,
) -> Any:
    """Install raw-ASGI private boundaries from one boot authority."""

    # A fresh wrapper owns an empty boot-local stage latch. No environment bit
    # or mutable FastAPI boolean can activate paid operations.
    public_app.state.paid_media_engine_session_verifier = None
    public_app.state.desktop_engine_session_verifier = None
    downstream: Any = public_app
    desktop_session_required = packaged or _desktop_engine_session_environment_requested(
        environ
    )
    listener_port: int | None = None
    if desktop_session_required:
        listener_port = (
            get_settings().gateway_port
            if configured_port is None
            else configured_port
        )
        desktop_verifier = DesktopEngineSessionGatewayApp(
            downstream,
            configured_port=listener_port,
            environ=environ,
            pid_provider=pid_provider,
        )
        public_app.state.desktop_engine_session_verifier = desktop_verifier
        downstream = desktop_verifier
    if packaged:
        assert listener_port is not None
        verifier = PaidMediaEngineSessionGatewayApp(
            downstream,
            configured_port=listener_port,
            environ=environ,
            pid_provider=pid_provider,
            installation_principal_supplier=lambda: (
                _stage_ready_installation_principal(public_app)
            ),
            # A packaged caller cannot distinguish a missing/invalid session
            # from a forbidden long-lived credential path.
            hide_auth_failures=True,
        )
        public_app.state.paid_media_engine_session_verifier = verifier
        downstream = verifier
    # Installation Root remains the outermost byte-exact private dispatcher;
    # both wrappers delegate unrelated paths without normalizing the scope.
    return InstallationRootGatewayApp(downstream)


# The private boundaries remain outside FastAPI's router and user middleware.
# Attribute proxying preserves ``app.state``/OpenAPI/test access for callers.
_public_fastapi_app = app
# ADR-0013：CLI + 本地 Web 分发形态。catch-all 必须在全部 API 路由之后注册；
# 未配置 NACHUAN_WEB_UI_DIR 时使用 wheel 内 gateway/web_ui；显式无效覆盖仍 fail-closed。
from gateway.local_web_ui import mount_local_web_ui
from gateway.paid_media_web import PaidMediaWebLedger, register_paid_media_web_routes
from gateway.paid_media_web_archive import PaidMediaWebAssetArchive

register_paid_media_web_routes(_public_fastapi_app)
mount_local_web_ui(_public_fastapi_app)
app = _compose_gateway_asgi_app(
    _public_fastapi_app,
    packaged=_is_packaged_runtime(),
)


def main() -> None:
    import uvicorn

    settings = get_settings()
    if _is_packaged_runtime() or _desktop_engine_session_environment_requested():
        desktop_verifier = getattr(
            _public_fastapi_app.state, "desktop_engine_session_verifier", None
        )
        if (
            not isinstance(desktop_verifier, DesktopEngineSessionGatewayApp)
            or not desktop_verifier.ready
        ):
            raise SystemExit(
                "⛔ 拒绝启动：Desktop Engine Session 启动授权不可用。"
            )
    # 空 host 会绑所有网卡(=0.0.0.0，不安全)——先归一到本机；否则 host="" 会被下面误判成 loopback 而绕过护栏(codex 审出)。
    host = settings.gateway_host or "127.0.0.1"
    # 安全护栏：绑非本机地址(0.0.0.0/局域网 IP) 却用默认/空 key = 局域网内任何人可带**公开的默认 key**
    # 打 /v1/agent/exec 在本机执行任意命令。拒启，逼用户先设真 key（桌面 app 走 127.0.0.1+随机 key，不受影响）。
    _loopback = host in {"127.0.0.1", "localhost", "::1"}
    _weak = (not settings.api_keys) or ("sk-local-dev-changeme" in settings.api_keys)
    if not _loopback and _weak:
        raise SystemExit(
            f"⛔ 拒绝启动：绑定了非本机地址 {host}，但网关 key 仍是默认/空。\n"
            "   局域网内任何人都能用公开的默认 key 驱动本机 agent 执行命令。\n"
            "   要暴露到局域网：先设 GATEWAY_API_KEYS=<你自己的随机串>。\n"
            "   仅本机自用：用默认的 GATEWAY_HOST=127.0.0.1 即可。"
        )
    # Asset capability tokens live in URL paths.  Uvicorn's stock access log
    # records the raw request target, so the redacted structured middleware is
    # the only request log allowed in this process.
    uvicorn.run(app, host=host, port=settings.gateway_port, access_log=False)


if __name__ == "__main__":
    main()
