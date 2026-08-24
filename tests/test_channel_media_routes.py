from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from gateway.channel_media_protocol import encode_channel_media_frame
from gateway.channel_media_requests import DurableChannelMediaRequestStore


gateway_app = importlib.import_module("gateway.app")

_VISION_QUESTION = "详细描述这张图片的内容；若图中有文字，逐字准确识别出来（OCR）。"


def _request(path: str, body: bytes) -> Request:
    delivered = False

    async def receive():  # noqa: ANN202
        nonlocal delivered
        if delivered:
            return {"type": "http.request", "body": b"", "more_body": False}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 8080),
        },
        receive,
    )


def _frame(
    *,
    operation: str = "vision.describe",
    raw: bytes = b"image-bytes",
    message_hex: str = "1",
) -> bytes:
    if operation == "vision.describe":
        pipeline = "vision.describe/v1"
        params = {"question": _VISION_QUESTION, "model": ""}
    else:
        pipeline = "lapian.analyze/v1"
        params = {
            "vision_model": "agnes-flash",
            "synth_model": "",
            "max_frames": 40,
            "with_audio": True,
        }
    return encode_channel_media_frame(
        channel="feishu",
        user_id="ou_media",
        chat_id="oc_media",
        message_key="fsmsg-v1:" + (message_hex * 64),
        operation=operation,
        pipeline_version=pipeline,
        params=params,
        raw=raw,
    )


@pytest.fixture
def durable_store(tmp_path, monkeypatch):
    store = DurableChannelMediaRequestStore(tmp_path / "channel-media.db")
    monkeypatch.setattr(gateway_app.app.state, "channel_media_requests", store, raising=False)
    monkeypatch.setattr(gateway_app.app.state, "router", object(), raising=False)
    try:
        yield store
    finally:
        store.close()


def test_channel_media_health_is_honest_about_unverified_recovery(
    durable_store,
    monkeypatch,
):
    assert gateway_app._channel_media_request_readiness() == {
        "ready": True,
        "mode": "durable",
        "backup_supported": False,
        "reanchor_supported": False,
        "real_channel_e2e_verified": False,
    }


async def test_bridge_result_expired_is_a_nonretryable_gone_response(
    durable_store,
    monkeypatch,
):
    monkeypatch.setattr(
        durable_store,
        "claim",
        lambda **_kwargs: SimpleNamespace(
            state="result_expired",
            retry_after_seconds=0,
        ),
    )

    with pytest.raises(HTTPException) as expired:
        await gateway_app.vision_endpoint(
            _request("/v1/vision", _frame()),
            question=None,
            model=None,
            credential="bridge:feishu",
        )
    assert expired.value.status_code == 410
    assert expired.value.detail == {
        "code": "channel_media_result_expired",
        "retryable": False,
    }
    monkeypatch.setattr(
        gateway_app.app.state,
        "channel_media_requests",
        None,
    )
    assert gateway_app._channel_media_request_readiness() == {
        "ready": False,
        "mode": "unavailable",
        "backup_supported": False,
        "reanchor_supported": False,
        "real_channel_e2e_verified": False,
    }


async def test_bridge_vision_persists_success_before_exact_replay(
    durable_store,
    monkeypatch,
):
    calls = 0

    async def describe(_router, data, *, question, model):  # noqa: ANN001, ANN202
        nonlocal calls
        calls += 1
        assert data == b"image-bytes"
        assert question == _VISION_QUESTION
        assert model == "vision"
        return "durable description"

    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "vision")
    monkeypatch.setattr(gateway_app, "describe_image", describe)
    body = _frame()

    first = await gateway_app.vision_endpoint(
        _request("/v1/vision", body),
        question=None,
        model=None,
        credential="bridge:feishu",
    )
    replay = await gateway_app.vision_endpoint(
        _request("/v1/vision", body),
        question=None,
        model=None,
        credential="bridge:feishu",
    )

    assert first == replay == {"text": "durable description"}
    assert calls == 1


async def test_bridge_vision_rejects_channel_and_operation_confusion(
    durable_store,
    monkeypatch,
):
    monkeypatch.setattr(
        gateway_app,
        "describe_image",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("provider must not run")
        ),
    )

    with pytest.raises(HTTPException) as channel_error:
        await gateway_app.vision_endpoint(
            _request("/v1/vision", _frame()),
            question=None,
            model=None,
            credential="bridge:weixin",
        )
    assert channel_error.value.status_code == 403

    with pytest.raises(HTTPException) as operation_error:
        await gateway_app.vision_endpoint(
            _request("/v1/vision", _frame(operation="lapian.analyze")),
            question=None,
            model=None,
            credential="bridge:feishu",
        )
    assert operation_error.value.status_code == 422


async def test_bridge_vision_same_key_changed_media_conflicts_before_provider(
    durable_store,
    monkeypatch,
):
    calls = 0

    async def describe(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal calls
        calls += 1
        return "first"

    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "vision")
    monkeypatch.setattr(gateway_app, "describe_image", describe)
    await gateway_app.vision_endpoint(
        _request("/v1/vision", _frame(raw=b"first")),
        question=None,
        model=None,
        credential="bridge:feishu",
    )

    with pytest.raises(HTTPException) as conflict:
        await gateway_app.vision_endpoint(
            _request("/v1/vision", _frame(raw=b"changed")),
            question=None,
            model=None,
            credential="bridge:feishu",
        )

    assert conflict.value.status_code == 409
    assert calls == 1


async def test_bridge_vision_heartbeat_loss_cancels_and_never_repeats_provider(
    durable_store,
    monkeypatch,
):
    calls = 0
    cancelled = asyncio.Event()

    async def describe(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal calls
        calls += 1
        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "vision")
    monkeypatch.setattr(gateway_app, "describe_image", describe)
    monkeypatch.setattr(durable_store, "heartbeat", lambda **_kwargs: False)
    monkeypatch.setattr(
        gateway_app,
        "_CHANNEL_MEDIA_HEARTBEAT_MAX_INTERVAL_SECONDS",
        0.01,
        raising=False,
    )
    body = _frame(message_hex="3")

    with pytest.raises(HTTPException) as lost:
        await gateway_app.vision_endpoint(
            _request("/v1/vision", body),
            question=None,
            model=None,
            credential="bridge:feishu",
        )

    assert lost.value.status_code == 503
    assert lost.value.detail["code"] == "channel_media_lease_lost"
    assert cancelled.is_set()
    assert calls == 1

    with pytest.raises(HTTPException) as retry:
        await gateway_app.vision_endpoint(
            _request("/v1/vision", body),
            question=None,
            model=None,
            credential="bridge:feishu",
        )
    assert retry.value.detail["code"] == "channel_media_in_progress"
    assert calls == 1


async def test_bridge_vision_request_cancellation_drains_provider_task(
    durable_store,
    monkeypatch,
):
    started = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()

    async def describe(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "vision")
    monkeypatch.setattr(gateway_app, "describe_image", describe)
    task = asyncio.create_task(
        gateway_app.vision_endpoint(
            _request("/v1/vision", _frame(message_hex="5")),
            question=None,
            model=None,
            credential="bridge:feishu",
        )
    )
    try:
        await asyncio.wait_for(started.wait(), timeout=10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(cancelled.wait(), timeout=2)
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

async def test_runtime_api_vision_keeps_raw_body_compatibility(monkeypatch):
    async def describe(_router, data, *, question, model):  # noqa: ANN001, ANN202
        assert data == b"legacy-raw-image"
        return f"{question}:{model}"

    monkeypatch.setattr(gateway_app.app.state, "router", object(), raising=False)
    monkeypatch.setattr(gateway_app, "describe_image", describe)

    result = await gateway_app.vision_endpoint(
        _request("/v1/vision", b"legacy-raw-image"),
        question="question",
        model="model",
        credential="runtime-api-key",
    )

    assert result == {"text": "question:model"}


async def test_bridge_lapian_replays_and_crosses_fence_only_after_preflight(
    durable_store,
    monkeypatch,
):
    calls = 0

    async def run(_router, path, **kwargs):  # noqa: ANN001, ANN202
        nonlocal calls
        calls += 1
        assert kwargs["vision_model"] == "agnes-flash"
        assert kwargs["synth_model"] is None
        assert kwargs["max_frames"] == 40
        assert kwargs["with_audio"] is True
        await kwargs["before_provider"]()
        return {"report": "durable lapian", "frames": 1}

    monkeypatch.setattr(gateway_app, "run_lapian", run)
    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "agnes-flash")
    body = _frame(operation="lapian.analyze", raw=b"video-bytes")

    first = await gateway_app.lapian_endpoint(
        _request("/v1/lapian", body),
        vision_model="agnes-flash",
        synth_model=None,
        max_frames=40,
        with_audio=True,
        credential="bridge:feishu",
    )
    replay = await gateway_app.lapian_endpoint(
        _request("/v1/lapian", body),
        vision_model="agnes-flash",
        synth_model=None,
        max_frames=40,
        with_audio=True,
        credential="bridge:feishu",
    )

    assert first == replay == {"report": "durable lapian", "frames": 1}
    assert calls == 1


async def test_bridge_lapian_local_failure_abandons_pre_provider_for_safe_retry(
    durable_store,
    monkeypatch,
):
    calls = 0

    async def local_failure(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal calls
        calls += 1
        return {"error": "unsupported local media"}

    monkeypatch.setattr(gateway_app, "run_lapian", local_failure)
    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "agnes-flash")
    body = _frame(operation="lapian.analyze", raw=b"bad-video")

    for _attempt in range(2):
        with pytest.raises(HTTPException) as failure:
            await gateway_app.lapian_endpoint(
                _request("/v1/lapian", body),
                vision_model="agnes-flash",
                synth_model=None,
                max_frames=40,
                with_audio=True,
                credential="bridge:feishu",
            )
        assert failure.value.status_code == 502

    assert calls == 2


async def test_bridge_lapian_heartbeat_loss_cancels_after_provider_fence(
    durable_store,
    monkeypatch,
):
    calls = 0
    cancelled = asyncio.Event()

    async def run(_router, _path, **kwargs):  # noqa: ANN001, ANN202
        nonlocal calls
        calls += 1
        await kwargs["before_provider"]()
        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return {"report": "must not commit"}

    monkeypatch.setattr(gateway_app, "run_lapian", run)
    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "agnes-flash")
    monkeypatch.setattr(durable_store, "heartbeat", lambda **_kwargs: False)
    monkeypatch.setattr(
        gateway_app,
        "_CHANNEL_MEDIA_HEARTBEAT_MAX_INTERVAL_SECONDS",
        0.01,
    )
    body = _frame(operation="lapian.analyze", raw=b"video-lease-loss", message_hex="4")

    with pytest.raises(HTTPException) as lost:
        await gateway_app.lapian_endpoint(
            _request("/v1/lapian", body),
            vision_model="agnes-flash",
            synth_model=None,
            max_frames=40,
            with_audio=True,
            credential="bridge:feishu",
        )

    assert lost.value.detail["code"] == "channel_media_lease_lost"
    assert cancelled.is_set()
    assert calls == 1


async def test_bridge_lapian_request_cancellation_drains_workflow_task(
    durable_store,
    monkeypatch,
):
    started = asyncio.Event()
    cancelled = asyncio.Event()
    release = asyncio.Event()

    async def run(_router, _path, **kwargs):  # noqa: ANN001, ANN202
        await kwargs["before_provider"]()
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(gateway_app, "run_lapian", run)
    monkeypatch.setattr(gateway_app, "pick_vision_model", lambda *_args: "agnes-flash")
    task = asyncio.create_task(
        gateway_app.lapian_endpoint(
            _request(
                "/v1/lapian",
                _frame(
                    operation="lapian.analyze",
                    raw=b"cancel-video",
                    message_hex="6",
                ),
            ),
            vision_model="agnes-flash",
            synth_model=None,
            max_frames=40,
            with_audio=True,
            credential="bridge:feishu",
        )
    )
    try:
        await asyncio.wait_for(started.wait(), timeout=10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(cancelled.wait(), timeout=2)
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
