"""Fail-closed resource limits for paid media and multi-model workflows."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.schemas import (
    ChatCompletionRequest,
    ImageGenerationRequest,
    VideoGenerationRequest,
)
from orchestrator.workflows.debate import run_debate
from orchestrator.workflows.decompose import run_decompose
from orchestrator.workflows.panel_judge import run_panel
from orchestrator.workflows.pipeline import run_pipeline


def test_chat_request_rejects_message_and_choice_amplification() -> None:
    with pytest.raises(ValidationError):
        ChatCompletionRequest(
            model="echo",
            messages=[{"role": "user", "content": "x"}] * 257,
        )
    with pytest.raises(ValidationError):
        ChatCompletionRequest(
            model="echo",
            messages=[{"role": "user", "content": "x"}],
            n=5,
        )


def test_chat_request_rejects_too_many_multimodal_images() -> None:
    images = [
        {"type": "image_url", "image_url": {"url": f"https://example.test/{i}.png"}}
        for i in range(5)
    ]
    with pytest.raises(ValidationError):
        ChatCompletionRequest(
            model="echo",
            messages=[{"role": "user", "content": images}],
        )


def test_image_request_bounds_paid_count_and_dimensions() -> None:
    assert ImageGenerationRequest(model="image", prompt="cat", n=4).n == 4
    with pytest.raises(ValidationError):
        ImageGenerationRequest(model="image", prompt="cat", n=5)
    with pytest.raises(ValidationError):
        ImageGenerationRequest(model="image", prompt="cat", size="100000x100000")
    with pytest.raises(ValidationError):
        ImageGenerationRequest(
            model="image", prompt="cat", extra_body={"num_outputs": 100}
        )


def test_video_request_enforces_verified_frame_and_pixel_limits() -> None:
    valid = VideoGenerationRequest(
        model="video",
        prompt="cat",
        width=1280,
        height=720,
        num_frames=441,
        frame_rate=24,
    )
    assert valid.num_frames == 441
    with pytest.raises(ValidationError):
        VideoGenerationRequest(model="video", prompt="cat", num_frames=10)
    with pytest.raises(ValidationError):
        VideoGenerationRequest(
            model="video", prompt="cat", width=4096, height=4096
        )


def test_video_request_rejects_more_than_four_keyframes() -> None:
    with pytest.raises(ValidationError):
        VideoGenerationRequest(
            model="video",
            prompt="cat",
            extra_body={"image": ["https://example.test/i.png"] * 5},
        )
    with pytest.raises(ValidationError):
        VideoGenerationRequest(
            model="video", prompt="cat", extra_body={"num_videos": 2}
        )


class _CountingProvider:
    def __init__(self, *, answer: str = "ok") -> None:
        self.answer = answer
        self.name = "counting-provider"
        self.independence_domain = (
            "sha256:" + hashlib.sha256(b"counting-provider-target").hexdigest()
        )
        self.active = 0
        self.max_active = 0
        self.calls = 0

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        if upstream_model != observed_model:
            return None
        return observed_model, "counting-test-family"

    async def chat(self, _req: Any, model: str) -> dict[str, Any]:
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0.01)
        self.active -= 1
        return {
            "model": model,
            "choices": [{"message": {"content": self.answer}}],
        }


@dataclass
class _Route:
    virtual_model: str
    provider: _CountingProvider
    upstream_model: str = "upstream"


class _Router:
    def __init__(self, provider: _CountingProvider) -> None:
        self.provider = provider

    def resolve(self, _model: str) -> _Route:
        return _Route(_model, self.provider)


async def test_panel_rejects_unbounded_fanout_and_caps_concurrency() -> None:
    provider = _CountingProvider()
    router = _Router(provider)
    with pytest.raises(ValueError, match="panel"):
        await run_panel(
            router,
            prompt="x",
            panelists=[f"m{i}" for i in range(9)],
            judge="judge",
        )

    out = await run_panel(
        router,
        prompt="x",
        panelists=[f"m{i}" for i in range(6)],
        judge="judge",
    )
    assert out["summary"] == "ok"
    assert out["review_verdict"] is None
    assert out["judge_vote_weight"] == 0
    assert provider.max_active <= 4


async def test_debate_rejects_round_clamping_and_debater_fanout() -> None:
    router = _Router(_CountingProvider())
    with pytest.raises(ValueError, match="round"):
        await run_debate(
            router,
            prompt="x",
            debaters=["a", "b"],
            judge="judge",
            rounds=5,
        )
    with pytest.raises(ValueError, match="debater"):
        await run_debate(
            router,
            prompt="x",
            debaters=[f"m{i}" for i in range(5)],
            judge="judge",
            rounds=2,
        )


async def test_pipeline_rejects_unbounded_steps_before_model_call() -> None:
    provider = _CountingProvider()
    with pytest.raises(ValueError, match="step"):
        await run_pipeline(
            _Router(provider),
            prompt="x",
            steps=[{"model": "echo", "instruction": "work"}] * 13,
        )
    assert provider.calls == 0


async def test_decompose_rejects_oversized_task_before_model_call() -> None:
    provider = _CountingProvider()
    with pytest.raises(ValueError, match="task"):
        await run_decompose(
            _Router(provider),
            task="x" * 65_537,
            planner="planner",
            aggregator="aggregator",
        )
    assert provider.calls == 0


async def test_panel_rejects_oversized_intermediate_output() -> None:
    provider = _CountingProvider(answer="x" * 65_537)
    out = await run_panel(
        _Router(provider), prompt="x", panelists=["one"], judge="judge"
    )

    assert out["outcome"] == "failed"
    assert out["stopped_reason"] == "panelist_output_limit"
    assert out["panelists"][0]["error_type"] == "output_limit"


def test_http_endpoints_surface_resource_rejections_as_422(
    paid_media_auth_headers,
) -> None:
    auth = {"Authorization": "Bearer test-key"}
    with TestClient(app) as client:
        responses = [
            client.post(
                "/v1/orchestrate/panel",
                headers=auth,
                json={
                    "prompt": "x",
                    "panelists": [f"m{i}" for i in range(9)],
                    "judge": "judge",
                },
            ),
            client.post(
                "/v1/orchestrate/debate",
                headers=auth,
                json={
                    "prompt": "x",
                    "debaters": ["a", "b"],
                    "judge": "judge",
                    "rounds": 5,
                },
            ),
            client.post(
                "/v1/orchestrate/pipeline",
                headers=auth,
                json={
                    "prompt": "x",
                    "steps": [{"model": "echo"}] * 13,
                },
            ),
            client.post(
                "/v1/orchestrate/decompose",
                headers=auth,
                json={
                    "task": "x" * 65_537,
                    "planner": "echo",
                    "aggregator": "echo",
                },
            ),
            client.post(
                "/v1/images/generations",
                headers={
                    **paid_media_auth_headers,
                    "X-Nachuan-Paid-Media-Protocol": "2",
                    "Idempotency-Key": "resource-image-1111111111111111",
                },
                json={"model": "echo", "prompt": "x", "n": 5},
            ),
            client.post(
                "/v1/videos/generations",
                headers={
                    **paid_media_auth_headers,
                    "X-Nachuan-Paid-Media-Protocol": "2",
                    "Idempotency-Key": "resource-video-2222222222222222",
                },
                json={"model": "echo", "prompt": "x", "num_frames": 10},
            ),
        ]
    assert [response.status_code for response in responses] == [422] * len(responses)
