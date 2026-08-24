from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import sqlite3
import ssl
from pathlib import Path

import httpx
import pytest
import respx

from gateway.media_call_metering import (
    bind_paid_media_authority,
    generate_image_with_accounting,
    generate_video_with_accounting,
    get_video_with_accounting,
)
from gateway.provider_call_ledger import (
    ProviderCallContext,
    ProviderCallLedger,
    ProviderCallLedgerUnavailable,
    bind_provider_call_context,
    configured_provider_call_ledger,
)
from gateway.providers.base import ProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import ImageGenerationRequest, VideoGenerationRequest
import orchestrator.media as media


@pytest.fixture(autouse=True)
def _durable_paid_authority_for_accounting_unit_tests():
    """These tests exercise accounting after durable paid admission."""

    with bind_paid_media_authority(
        principal_hash="a" * 64,
        operation="images.create",
    ):
        with bind_paid_media_authority(
            principal_hash="a" * 64,
            operation="videos.create",
        ):
            yield


def test_media_entrypoints_have_no_unmetered_provider_calls() -> None:
    root = Path(__file__).resolve().parents[1]
    targets = (
        root / "gateway" / "app.py",
        root / "orchestrator" / "media.py",
        root / "orchestrator" / "tool_agent.py",
    )
    provider_methods = {"generate_image", "generate_video", "get_video"}
    bypasses: list[str] = []

    for path in targets:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in provider_methods
            ):
                bypasses.append(f"{path.relative_to(root)}:{node.lineno}:{node.func.attr}")

    assert bypasses == [], "unmetered media provider calls: " + ", ".join(bypasses)


async def test_media_image_success_freezes_identity_and_keeps_unknown_usage_null(
    tmp_path,
) -> None:
    class Provider:
        name = "image-provider-before"

        async def generate_image(self, _request, _upstream):  # noqa: ANN001
            self.name = "image-provider-after"
            return {
                "model": "observed-image-model",
                "data": [{"url": "https://example.invalid/image.png"}],
            }

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    result = await generate_image_with_accounting(
        Provider(),
        ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
        "image-upstream",
        actual_model="image-seat",
        attempt=1,
        provider_call_ledger=ledger,
        call_context=ProviderCallContext(
            trace_id="trace-media-1",
            turn_id="turn-media-1",
            workflow_id="workflow-media-1",
            role="tool-agent",
        ),
    )

    assert result["data"][0]["url"].endswith("image.png")
    calls = ledger.list_calls()
    assert len(calls) == 1
    call = calls[0]
    assert call["requested_model"] == "image-seat"
    assert call["actual_model"] == "image-seat"
    assert call["provider"] == "image-provider-before"
    assert call["upstream_model"] == "image-upstream"
    assert call["observed_model"] == "observed-image-model"
    assert call["trace_id"] == "trace-media-1"
    assert call["turn_id"] == "turn-media-1"
    assert call["workflow_id"] == "workflow-media-1"
    assert call["role"] == "tool-agent/media.generate_image"
    assert call["attempt"] == 1
    assert call["status"] == "success"
    assert call["prompt_tokens"] is None
    assert call["completion_tokens"] is None
    assert call["total_tokens"] is None
    assert call["cost_microusd"] is None


async def test_media_provider_exception_is_terminal_and_propagates(tmp_path) -> None:
    class Provider:
        name = "video-provider"

        async def generate_video(self, _request, _upstream):  # noqa: ANN001
            raise ProviderError("video quota exhausted", status_code=429)

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    with pytest.raises(ProviderError, match="quota exhausted"):
        await generate_video_with_accounting(
            Provider(),
            VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
            "video-upstream",
            actual_model="video-seat",
            provider_call_ledger=ledger,
        )

    call = ledger.list_calls()[0]
    assert call["status"] == "provider_error"
    assert call["error_type"] == "ProviderError"
    assert call["error_message"] == (
        "sha256:" + hashlib.sha256(b"video quota exhausted").hexdigest()
    )


async def test_media_poll_timeout_is_terminal_and_unknown_usage_stays_null(
    tmp_path,
) -> None:
    class Provider:
        name = "poll-provider"

        async def get_video(self, _task_id):  # noqa: ANN001
            raise asyncio.TimeoutError

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    with pytest.raises(asyncio.TimeoutError):
        await get_video_with_accounting(
            Provider(),
            "task-1",
            requested_model="video-seat",
            actual_model="video-seat",
            upstream_model="video-upstream",
            attempt=3,
            provider_call_ledger=ledger,
        )

    call = ledger.list_calls()[0]
    assert call["attempt"] == 3
    assert call["role"] == "media.get_video"
    assert call["status"] == "timeout"
    assert call["error_type"] == "TimeoutError"
    assert call["total_tokens"] is None
    assert call["cost_microusd"] is None


async def test_media_cancellation_is_recorded_before_it_propagates(tmp_path) -> None:
    started = asyncio.Event()

    class Provider:
        name = "blocking-image-provider"

        async def generate_image(self, _request, _upstream):  # noqa: ANN001
            started.set()
            await asyncio.Event().wait()

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    task = asyncio.create_task(
        generate_image_with_accounting(
            Provider(),
            ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
            "image-upstream",
            actual_model="image-seat",
            provider_call_ledger=ledger,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=2.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    call = ledger.list_calls()[0]
    assert call["status"] == "cancelled"
    assert call["error_type"] == "CancelledError"


async def test_required_media_ledger_failure_blocks_provider_invocation() -> None:
    class UnwritableLedger:
        required = True

        def start_attempt(self, **_fields):  # noqa: ANN003, ANN201
            raise ProviderCallLedgerUnavailable("media ledger unavailable")

    class Provider:
        name = "must-not-run"

        def __init__(self) -> None:
            self.called = False

        async def generate_video(self, _request, _upstream):  # noqa: ANN001
            self.called = True
            return {"task_id": "unsafe"}

    provider = Provider()
    with pytest.raises(ProviderCallLedgerUnavailable, match="media ledger unavailable"):
        await generate_video_with_accounting(
            provider,
            VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
            "video-upstream",
            actual_model="video-seat",
            provider_call_ledger=UnwritableLedger(),
        )

    assert provider.called is False


async def test_media_lazy_ledger_init_lock_does_not_freeze_event_loop(
    monkeypatch,
    tmp_path,
) -> None:
    class Provider:
        name = "lock-test-image"

        def __init__(self) -> None:
            self.called = False

        async def generate_image(self, _request, _upstream):  # noqa: ANN001
            self.called = True
            return {"data": []}

    db_path = tmp_path / "usage.db"
    blocker = sqlite3.connect(db_path)
    blocker.execute("CREATE TABLE lock_holder (id INTEGER PRIMARY KEY)")
    blocker.commit()
    blocker.execute("BEGIN EXCLUSIVE")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = Provider()
    stop = asyncio.Event()
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.005)

    call_task = asyncio.create_task(
        generate_image_with_accounting(
            provider,
            ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
            "image-upstream",
            actual_model="image-seat",
        )
    )
    ticker_task = asyncio.create_task(ticker())
    await asyncio.sleep(0.06)
    ticks_while_locked = ticks
    provider_called_while_locked = provider.called
    blocker.rollback()
    blocker.close()

    result = await asyncio.wait_for(call_task, timeout=7.0)
    stop.set()
    await ticker_task

    assert ticks_while_locked >= 1
    assert provider_called_while_locked is False
    assert result == {"data": []}
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    assert ledger.list_calls()[0]["status"] == "success"
    ledger.close()


async def test_video_orchestrator_does_not_retry_when_required_ledger_is_unavailable(
    monkeypatch,
    tmp_path,
) -> None:
    class Provider:
        name = "must-not-run"

        def __init__(self) -> None:
            self.calls = 0

        async def generate_video(self, _request, _upstream):  # noqa: ANN001
            self.calls += 1
            return {"task_id": "unsafe"}

    provider = Provider()
    route = type(
        "Route",
        (),
        {"provider": provider, "upstream_model": "video-upstream"},
    )()
    router = type("Router", (), {"resolve": lambda _self, _model: route})()

    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(tmp_path))

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(media.asyncio, "sleep", no_sleep)

    with pytest.raises(ProviderCallLedgerUnavailable):
        await media.gen_video(router, "a lighthouse", model="video-seat")

    assert provider.calls == 0


async def test_video_orchestrator_records_create_and_each_poll_attempt(
    monkeypatch,
    tmp_path,
) -> None:
    class Provider:
        name = "retry-video"

        def __init__(self) -> None:
            self.create_calls = 0
            self.poll_calls = 0

        async def generate_video(self, _request, _upstream):  # noqa: ANN001
            self.create_calls += 1
            return {"task_id": "video-task-1"}

        async def get_video(self, _task_id):  # noqa: ANN001
            self.poll_calls += 1
            if self.poll_calls == 1:
                raise asyncio.TimeoutError
            return {
                "status": "completed",
                "video_url": "https://example.invalid/result.mp4",
            }

    provider = Provider()
    route = type(
        "Route",
        (),
        {"provider": provider, "upstream_model": "video-upstream"},
    )()
    router = type("Router", (), {"resolve": lambda _self, _model: route})()
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(media.asyncio, "sleep", no_sleep)
    with bind_provider_call_context(
        ProviderCallContext(trace_id="trace-video", turn_id="turn-video")
    ):
        result = await media.gen_video(
            router,
            "a lighthouse",
            model="video-seat",
            max_wait=12,
        )

    assert result == "https://example.invalid/result.mp4"
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    create_calls = [c for c in calls if c["role"] == "media.generate_video"]
    poll_calls = [c for c in calls if c["role"] == "media.get_video"]
    assert [(c["attempt"], c["status"]) for c in create_calls] == [
        (1, "success"),
    ]
    assert [(c["attempt"], c["status"]) for c in poll_calls] == [
        (1, "timeout"),
        (2, "success"),
    ]
    assert all(c["trace_id"] == "trace-video" for c in calls)
    assert all(c["turn_id"] == "turn-video" for c in calls)
    assert all(c["total_tokens"] is None for c in calls)
    assert all(c["cost_microusd"] is None for c in calls)
    ledger.close()


async def test_video_orchestrator_never_retries_non_idempotent_create(
    monkeypatch,
    tmp_path,
) -> None:
    class Provider:
        name = "single-shot-video"

        def __init__(self) -> None:
            self.calls = 0

        async def generate_video(self, _request, _upstream):  # noqa: ANN001
            self.calls += 1
            raise asyncio.TimeoutError

    provider = Provider()
    route = type(
        "Route",
        (),
        {"provider": provider, "upstream_model": "video-upstream"},
    )()
    router = type("Router", (), {"resolve": lambda _self, _model: route})()
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))

    result = await media.gen_video(router, "a lighthouse", model="video-seat")

    assert result == ""
    assert provider.calls == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["status"] == "timeout"
    assert calls[0]["error_type"] == "video_submission_outcome_unknown"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0
    ledger.close()


@respx.mock
async def test_openai_video_get_records_each_raw_http_retry(monkeypatch, tmp_path) -> None:
    base_url = "https://metering.example/v1"
    route = respx.get(f"{base_url}/videos/video-task-1").mock(
        side_effect=[
            httpx.ReadTimeout("slow poll"),
            httpx.Response(
                200,
                json={
                    "status": "completed",
                    "video_url": "https://example.invalid/result.mp4",
                },
            ),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))

    import gateway.providers.openai_compat as openai_compat

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(openai_compat.asyncio, "sleep", no_sleep)
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )
    result = await get_video_with_accounting(
        provider,
        "video-task-1",
        requested_model="video-seat",
        actual_model="video-seat",
        upstream_model="video-upstream",
    )

    assert result["status"] == "completed"
    assert route.call_count == 2
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert [(c["attempt"], c["status"]) for c in calls] == [
        (1, "timeout"),
        (2, "success"),
    ]
    assert all(c["role"] == "media.get_video" for c in calls)
    assert all(c["total_tokens"] is None for c in calls)
    assert all(c["cost_microusd"] is None for c in calls)
    await provider.aclose()
    ledger.close()


@respx.mock
async def test_openai_video_post_timeout_is_not_automatically_retried(
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://metering.example/v1"
    route = respx.post(f"{base_url}/videos").mock(
        side_effect=[
            httpx.ReadTimeout("submission outcome unknown"),
            httpx.Response(200, json={"task_id": "duplicate-task"}),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))

    import gateway.providers.openai_compat as openai_compat

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(openai_compat.asyncio, "sleep", no_sleep)
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )
    with pytest.raises(ProviderError, match="结果未知.*禁止自动重试"):
        await generate_video_with_accounting(
            provider,
            VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
            "video-upstream",
            actual_model="video-seat",
        )

    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["status"] == "timeout"
    assert calls[0]["error_type"] == "video_submission_outcome_unknown"
    await provider.aclose()
    ledger.close()


@respx.mock
async def test_openai_image_post_timeout_is_single_raw_attempt(monkeypatch, tmp_path) -> None:
    base_url = "https://metering.example/v1"
    route = respx.post(f"{base_url}/images/generations").mock(
        side_effect=[
            httpx.ReadTimeout("image outcome unknown"),
            httpx.Response(200, json={"data": [{"url": "duplicate-image"}]}),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )

    with pytest.raises(ProviderError, match="结果未知.*禁止自动重试"):
        await generate_image_with_accounting(
            provider,
            ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
            "image-upstream",
            actual_model="image-seat",
        )

    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["status"] == "timeout"
    assert calls[0]["error_type"] == "image_submission_outcome_unknown"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0
    await provider.aclose()
    ledger.close()


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, text="provider may have accepted the image job"),
        httpx.Response(
            200,
            text="not-json",
            headers={"content-type": "application/json"},
        ),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"data": []}),
        httpx.Response(200, json={"data": [{}]}),
    ],
    ids=("5xx", "invalid-json", "missing-data", "empty-data", "unusable-data"),
)
@respx.mock
async def test_openai_image_post_response_phase_failure_is_outcome_unknown(
    response,
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://image-response-metering.example/v1"
    route = respx.post(f"{base_url}/images/generations").mock(
        side_effect=[
            response,
            httpx.Response(200, json={"data": [{"url": "duplicate-image"}]}),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )

    try:
        with pytest.raises(ProviderError, match="结果未知.*禁止自动重试"):
            await generate_image_with_accounting(
                provider,
                ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
                "image-upstream",
                actual_model="image-seat",
            )
    finally:
        await provider.aclose()

    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["status"] == "provider_error"
    assert calls[0]["error_type"] == "image_submission_outcome_unknown"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0
    ledger.close()


@respx.mock
async def test_openai_image_post_explicit_4xx_remains_failed(
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://image-4xx-metering.example/v1"
    route = respx.post(f"{base_url}/images/generations").mock(
        side_effect=[
            httpx.Response(400, text="invalid prompt"),
            httpx.Response(200, json={"data": [{"url": "must-not-run"}]}),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )

    try:
        with pytest.raises(ProviderError) as exc_info:
            await generate_image_with_accounting(
                provider,
                ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
                "image-upstream",
                actual_model="image-seat",
            )
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 400
    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["error_type"] == "HTTPStatusError"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 0
    assert summary["failed_calls"] == 1
    ledger.close()


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(503, text="provider may have accepted the video job"),
        httpx.Response(
            200,
            text="not-json",
            headers={"content-type": "application/json"},
        ),
        httpx.Response(200, json={}),
    ],
    ids=("5xx", "invalid-json", "missing-task-id"),
)
@respx.mock
async def test_openai_video_post_response_phase_failure_is_outcome_unknown(
    response,
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://video-response-metering.example/v1"
    route = respx.post(f"{base_url}/videos").mock(
        side_effect=[
            response,
            httpx.Response(200, json={"task_id": "duplicate-task"}),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )

    try:
        with pytest.raises(ProviderError, match="结果未知.*禁止自动重试"):
            await generate_video_with_accounting(
                provider,
                VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
                "video-upstream",
                actual_model="video-seat",
            )
    finally:
        await provider.aclose()

    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["status"] == "provider_error"
    assert calls[0]["error_type"] == "video_submission_outcome_unknown"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0
    ledger.close()


@respx.mock
async def test_openai_video_post_explicit_4xx_remains_failed(
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://video-4xx-metering.example/v1"
    route = respx.post(f"{base_url}/videos").mock(
        side_effect=[
            httpx.Response(400, text="invalid prompt"),
            httpx.Response(200, json={"task_id": "must-not-run"}),
        ]
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )

    try:
        with pytest.raises(ProviderError) as exc_info:
            await generate_video_with_accounting(
                provider,
                VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
                "video-upstream",
                actual_model="video-seat",
            )
    finally:
        await provider.aclose()

    assert exc_info.value.status_code == 400
    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0]["error_type"] == "HTTPStatusError"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 0
    assert summary["failed_calls"] == 1
    ledger.close()


@respx.mock
async def test_openai_image_post_persists_only_local_billing_dimensions(
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://image-billing-dimensions.example/v1"
    respx.post(f"{base_url}/images/generations").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"url": "https://example.invalid/one.png"},
                    {"b64_json": "aW1hZ2U="},
                ]
            },
        )
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )
    request = ImageGenerationRequest(
        model="image-seat",
        prompt="secret prompt must never enter billing dimensions",
        n=2,
        size="1024x1024",
        quality="hd",
    )

    try:
        await generate_image_with_accounting(
            provider,
            request,
            "image-upstream",
            actual_model="image-seat",
        )
    finally:
        await provider.aclose()

    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    call = ledger.list_calls()[0]
    assert call["billing_dimensions_schema"] == "media_billing_dimensions_v1"
    assert json.loads(call["billing_dimensions_json"]) == {
        "operation": "media.generate_image",
        "n": 2,
        "quality": "hd",
        "size": "1024x1024",
    }
    assert "secret prompt" not in call["billing_dimensions_json"]
    ledger.close()


@respx.mock
async def test_openai_video_post_normalizes_local_billing_aliases_and_get_omits_them(
    monkeypatch,
    tmp_path,
) -> None:
    base_url = "https://video-billing-dimensions.example/v1"
    respx.post(f"{base_url}/videos").mock(
        return_value=httpx.Response(200, json={"task_id": "private-task-id"})
    )
    respx.get(f"{base_url}/videos/private-task-id").mock(
        return_value=httpx.Response(
            200,
            json={"status": "completed", "url": "https://example.invalid/video.mp4"},
        )
    )
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )
    request = VideoGenerationRequest(
        model="video-seat",
        prompt="private video prompt",
        n=1,
        size="1280x720",
        quality="standard",
        seconds=8,
        width=1280,
        height=720,
        frame_rate=24,
        num_frames=49,
    )

    try:
        created = await generate_video_with_accounting(
            provider,
            request,
            "video-upstream",
            actual_model="video-seat",
        )
        await get_video_with_accounting(
            provider,
            created["task_id"],
            requested_model="video-seat",
            actual_model="video-seat",
            upstream_model="video-upstream",
        )
    finally:
        await provider.aclose()

    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    create_call, get_call = ledger.list_calls()
    assert create_call["billing_dimensions_schema"] == "media_billing_dimensions_v1"
    assert json.loads(create_call["billing_dimensions_json"]) == {
        "fps": 24,
        "frame_count": 49,
        "n": 1,
        "operation": "media.generate_video",
        "quality": "standard",
        "resolution": "1280x720",
        "seconds": 8,
        "size": "1280x720",
    }
    assert "private video prompt" not in create_call["billing_dimensions_json"]
    assert "private-task-id" not in create_call["billing_dimensions_json"]
    assert get_call["billing_dimensions_json"] is None
    assert get_call["billing_dimensions_schema"] is None
    ledger.close()


@pytest.mark.parametrize("media_kind", ("image", "video"))
async def test_openai_media_post_cancellation_after_http_start_is_outcome_unknown(
    media_kind,
    tmp_path,
) -> None:
    started = asyncio.Event()

    class BlockingClient:
        async def post(self, *_args, **_kwargs):  # noqa: ANN002, ANN003, ANN201
            started.set()
            await asyncio.Event().wait()

        async def request(self, *_args, **_kwargs):  # noqa: ANN002, ANN003, ANN201
            started.set()
            await asyncio.Event().wait()

        async def aclose(self) -> None:
            return None

    db_path = tmp_path / "usage.db"
    # Establish the durable ledger before starting the cancellation window.
    # Cold schema creation can legitimately take longer than the bounded HTTP
    # start assertion on a busy Windows disk; this contract is specifically
    # about cancellation after provider invocation, not lazy-ledger startup.
    ledger = await asyncio.to_thread(ProviderCallLedger, db_path, required=True)
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=f"https://{media_kind}-cancel.example/v1",
        api_key="test-key",
    )
    await provider._client.aclose()
    provider._client = BlockingClient()

    if media_kind == "image":
        invoke = generate_image_with_accounting(
            provider,
            ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
            "image-upstream",
            actual_model="image-seat",
            provider_call_ledger=ledger,
        )
    else:
        invoke = generate_video_with_accounting(
            provider,
            VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
            "video-upstream",
            actual_model="video-seat",
            provider_call_ledger=ledger,
        )
    task = asyncio.create_task(invoke)
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        await provider.aclose()

    call = ledger.list_calls()[0]
    assert call["status"] == "cancelled"
    assert call["error_type"] == f"{media_kind}_submission_outcome_unknown"
    assert call["billing_dimensions_schema"] == "media_billing_dimensions_v1"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0
    ledger.close()


async def test_openai_video_get_cancellation_remains_ordinary_cancelled(
    tmp_path,
) -> None:
    started = asyncio.Event()

    class BlockingClient:
        async def request(self, *_args, **_kwargs):  # noqa: ANN002, ANN003, ANN201
            started.set()
            await asyncio.Event().wait()

        async def aclose(self) -> None:
            return None

    db_path = tmp_path / "usage.db"
    # Keep cold durable-ledger initialization outside the bounded HTTP-start
    # window. This contract distinguishes GET cancellation from an uncertain
    # POST submission; lazy initialization has separate coverage.
    ledger = await asyncio.to_thread(ProviderCallLedger, db_path, required=True)
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url="https://video-get-cancel.example/v1",
        api_key="test-key",
    )
    await provider._client.aclose()
    provider._client = BlockingClient()
    task = asyncio.create_task(
        get_video_with_accounting(
            provider,
            "task-id",
            requested_model="video-seat",
            actual_model="video-seat",
            upstream_model="video-upstream",
            provider_call_ledger=ledger,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        await provider.aclose()

    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == ("cancelled", "CancelledError")
    assert call["billing_dimensions_json"] is None
    assert ledger.financial_summary()["outcome_unknown_calls"] == 0
    ledger.close()


@pytest.mark.parametrize("media_kind", ("image", "video"))
@pytest.mark.parametrize("transport_kind", ("ssl", "connect"))
@respx.mock
async def test_openai_media_post_transport_classification_is_conservative(
    media_kind,
    transport_kind,
    monkeypatch,
    tmp_path,
) -> None:
    base_url = f"https://{media_kind}-{transport_kind}.example/v1"
    endpoint = (
        f"{base_url}/images/generations"
        if media_kind == "image"
        else f"{base_url}/videos"
    )
    error = (
        ssl.SSLError("TLS failed after request may have been written")
        if transport_kind == "ssl"
        else httpx.ConnectError("connection refused before submission")
    )
    route = respx.post(endpoint).mock(side_effect=error)
    db_path = tmp_path / "usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))
    provider = OpenAICompatProvider(
        name="metered-openai",
        base_url=base_url,
        api_key="test-key",
    )

    try:
        with pytest.raises(ProviderError):
            if media_kind == "image":
                await generate_image_with_accounting(
                    provider,
                    ImageGenerationRequest(model="image-seat", prompt="a lighthouse"),
                    "image-upstream",
                    actual_model="image-seat",
                )
            else:
                await generate_video_with_accounting(
                    provider,
                    VideoGenerationRequest(model="video-seat", prompt="a lighthouse"),
                    "video-upstream",
                    actual_model="video-seat",
                )
    finally:
        await provider.aclose()

    assert route.call_count == 1
    ledger = configured_provider_call_ledger()
    assert isinstance(ledger, ProviderCallLedger)
    call = ledger.list_calls()[0]
    if transport_kind == "ssl":
        assert call["error_type"] == f"{media_kind}_submission_outcome_unknown"
        assert ledger.financial_summary()["outcome_unknown_calls"] == 1
    else:
        assert call["error_type"] == "ConnectError"
        assert ledger.financial_summary()["outcome_unknown_calls"] == 0
    ledger.close()
