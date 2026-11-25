"""音频转写、实时翻译与视觉理解路由（从 gateway/app.py 拆出）。"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Mapping

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from gateway.audio import AudioUnavailable
from gateway.auth import require_api_key, require_bridge_or_api_key
from gateway.channel_media_protocol import (
    ChannelMediaFrame,
    ChannelMediaFrameError,
    decode_channel_media_frame,
    recompute_channel_media_identity,
)
from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.durable_media_requests import (
    DurableMediaRequestClaim,
    DurableMediaRequestUnavailable,
)
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.providers.base import ProviderError
from gateway.router import Router
from orchestrator.modes import pick_model
from orchestrator.translate import translate
from orchestrator.vision import describe_image, pick_vision_model

router = APIRouter(tags=["audio-vision"])

_CHANNEL_VISION_DEFAULT_QUESTION = (
    "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。"
)
_CHANNEL_VISION_RESULT_RESERVATION_BYTES = 1024 * 1024
_CHANNEL_LAPIAN_RESULT_RESERVATION_BYTES = 8 * 1024 * 1024
_CHANNEL_MEDIA_HEARTBEAT_MAX_INTERVAL_SECONDS = 30.0
_BRIDGE_CHANNEL_CREDENTIALS = frozenset({"bridge:feishu", "bridge:weixin"})


def _app_mod():
    import gateway.app as _mod

    return _mod


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
    app_mod = _app_mod()
    await app_mod._refresh_waiting_channel_media_authority()  # noqa: SLF001
    store = getattr(app_mod.app.state, "channel_media_requests", None)
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
    app_mod = _app_mod()

    async def assert_packaged_provider_authority() -> None:
        authority = getattr(app_mod.app.state, "channel_media_authority", None)
        if not isinstance(authority, Mapping) or not bool(
            authority.get("packaged")
        ):
            return
        controller = getattr(
            app_mod.app.state, "channel_media_installation_control", None
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
            app_mod.app.state, "paid_media_installation_id", None
        )
        paid_epoch = getattr(app_mod.app.state, "paid_media_epoch", None)
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


@router.post("/v1/audio/transcriptions")
async def transcribe_audio(
    request: Request,
    language: str | None = None,
    _: str = Depends(require_bridge_or_api_key),
):
    """语音转文字（D1·本地 faster-whisper，免费离线）。请求体=音频字节；?language=zh 可选（默认自动）。"""
    app_mod = _app_mod()
    data = await request.body()
    if not data:
        raise HTTPException(status_code=422, detail="需要音频数据（请求体）")
    try:
        text = await run_in_threadpool(app_mod.audio_mod.transcribe, data, language)
    except AudioUnavailable:
        raise HTTPException(
            status_code=503,
            detail="语音转写暂不可用；请检查本地模型与已锁定语音引擎",
        )
    return {"text": text}


@router.get("/v1/audio/model")
async def get_audio_model(_: str = Depends(require_api_key)):
    """当前语音转写模型档 + 可选项。"""
    app_mod = _app_mod()
    return {
        "model": app_mod.audio_mod.current_model_name(),
        "options": list(app_mod.audio_mod.WHISPER_MODELS),
    }


@router.post("/v1/audio/model")
async def set_audio_model(request: Request, _: str = Depends(require_api_key)):
    """切换语音转写模型档（tiny 最快 / base 均衡 / small 最准）。切完后台预热新档。"""
    app_mod = _app_mod()
    body = await request.json()
    name = str(body.get("model") or "")
    if not app_mod.audio_mod.set_model(name):
        raise HTTPException(
            status_code=422,
            detail=f"无效档位；可选：{', '.join(app_mod.audio_mod.WHISPER_MODELS)}",
        )
    threading.Thread(target=app_mod.audio_mod.warm, daemon=True).start()
    return {"model": app_mod.audio_mod.current_model_name()}


@router.post("/v1/translate")
async def translate_endpoint(request: Request, _: str = Depends(require_api_key)):
    """实时翻译（D2·走自家免费模型）。入参 text、target(语种码/名)；model 可选（默认免费 Agnes）。"""
    app_mod = _app_mod()
    router_obj: Router = request.app.state.router
    body = await request.json()
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="需要 text")
    target = str(body.get("target") or body.get("target_lang") or "en")
    model = str(
        body.get("model")
        or (
            "agnes-flash"
            if router_obj.resolve("agnes-flash")
            else (
                pick_model(router_obj, "cheap")
                or app_mod.get_settings().bridge_model
            )
        )
    )
    try:
        return JSONResponse(
            await translate(router_obj, text=text, target=target, model=model)
        )
    except ProviderError as e:
        raise app_mod._public_provider_http_error(e) from e  # noqa: SLF001


@router.post("/v1/vision")
async def vision_endpoint(
    request: Request,
    question: str | None = None,
    model: str | None = None,
    credential: str = Depends(require_bridge_or_api_key),
):
    """看图理解 / OCR（#28）：API raw bytes；bridge uses a sealed durable frame."""
    app_mod = _app_mod()
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
            request.app.state.router,
            data,
            question=normalized_question,
            model=model,
        )
        if not text:
            raise HTTPException(status_code=503, detail="没有可用的视觉模型，或识别失败")
        return {"text": text}

    store, claim = await app_mod._claim_bridge_channel_media(  # noqa: SLF001
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
        selected_model = pick_vision_model(request.app.state.router, model)
    except BaseException:
        await _abandon_channel_media_pre_provider(store, claim)
        raise
    if not selected_model:
        await _abandon_channel_media_pre_provider(store, claim)
        raise HTTPException(status_code=503, detail="没有可用的视觉模型，或识别失败")
    await app_mod._enter_channel_media_provider_phase(  # noqa: SLF001
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
                request.app.state.router,
                frame.raw,
                question=normalized_question,
                model=selected_model,
            ),
        )
    if not text:
        raise HTTPException(status_code=503, detail="没有可用的视觉模型，或识别失败")
    return await _persist_channel_media_success(store, claim, {"text": text})
