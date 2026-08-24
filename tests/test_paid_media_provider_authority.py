from __future__ import annotations

import asyncio
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import gateway.app as appmod
import gateway.media_call_metering as metering
import orchestrator.agent as agentmod
import orchestrator.studio as studiomod
from gateway.provider_call_ledger import ProviderCallLedger
from gateway.providers.base import ProviderError
from gateway.router import _ProviderGeneration
from gateway.schemas import ImageGenerationRequest, VideoGenerationRequest


RUNTIME_AUTH = {"Authorization": "Bearer test-key"}


class _ImageProvider:
    name = "paid-boundary-image"

    def __init__(self) -> None:
        self.calls = 0

    async def generate_image(self, _request, _upstream_model):  # noqa: ANN001
        self.calls += 1
        return {"data": [{"url": "https://media.invalid/forbidden.png"}]}


class _VideoProvider:
    name = "paid-boundary-video"

    def __init__(self) -> None:
        self.calls = 0

    async def generate_video(self, _request, _upstream_model):  # noqa: ANN001
        self.calls += 1
        return {"url": "https://media.invalid/forbidden.mp4"}


class _AllMediaProvider:
    name = "paid-boundary-all-media"
    enabled = True
    independence_domain = None
    media_http_attempt_accounting_operations = frozenset(
        {"media.generate_image", "media.generate_video"}
    )

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def generate_image(self, _request, _upstream_model):  # noqa: ANN001
        self.calls.append("generate_image")
        return {"data": [{"url": "https://media.invalid/forbidden.png"}]}

    async def generate_image_asset_urls(
        self, _request, _upstream_model  # noqa: ANN001
    ):
        self.calls.append("generate_image_asset_urls")
        return {"data": [{"url": "https://media.invalid/forbidden.png"}]}

    async def generate_video(self, _request, _upstream_model):  # noqa: ANN001
        self.calls.append("generate_video")
        return {"url": "https://media.invalid/forbidden.mp4"}

    async def aclose(self) -> None:
        return None


class _ReentrantImageProvider:
    name = "paid-boundary-reentrant-image"
    enabled = True
    independence_domain = None
    media_http_attempt_accounting_operations = frozenset({"media.generate_image"})

    def __init__(self) -> None:
        self.calls = 0
        self.generation: _ProviderGeneration | None = None

    async def generate_image(self, request, upstream_model):  # noqa: ANN001
        self.calls += 1
        assert self.generation is not None
        return await self.generation.generate_image(request, upstream_model)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "payload"),
    (
        (
            "generate_image",
            ImageGenerationRequest(model="paid-image", prompt="draw"),
        ),
        (
            "generate_image_asset_urls",
            ImageGenerationRequest(
                model="paid-image", prompt="draw", response_format="url"
            ),
        ),
        (
            "generate_video",
            VideoGenerationRequest(model="paid-video", prompt="animate"),
        ),
    ),
)
async def test_router_media_generation_requires_accounted_dispatch_permit(
    method: str,
    payload: ImageGenerationRequest | VideoGenerationRequest,
) -> None:
    raw = _AllMediaProvider()
    provider = _ProviderGeneration(raw, on_closed=lambda _provider: None)

    with pytest.raises(ProviderError) as exc_info:
        await getattr(provider, method)(payload, "paid-upstream")

    assert exc_info.value.status_code == 403
    assert raw.calls == []


@pytest.mark.asyncio
async def test_accounted_router_dispatch_permit_cannot_be_reused(tmp_path) -> None:
    raw = _ReentrantImageProvider()
    provider = _ProviderGeneration(raw, on_closed=lambda _provider: None)
    raw.generation = provider
    ledger = ProviderCallLedger(tmp_path / "dispatch-permit-ledger.db", required=True)

    try:
        with metering.bind_paid_media_authority(
            principal_hash="a" * 64,
            operation="images.create",
        ):
            with pytest.raises(ProviderError) as exc_info:
                await metering.generate_image_with_accounting(
                    provider,
                    ImageGenerationRequest(model="paid-image", prompt="draw once"),
                    "paid-upstream",
                    actual_model="paid-image",
                    provider_call_ledger=ledger,
                )

        calls = ledger.list_calls()
    finally:
        ledger.close()

    assert exc_info.value.status_code == 403
    assert raw.calls == 1
    assert len(calls) == 1
    assert calls[0]["status"] == "provider_error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "helper", "payload", "authority_operation"),
    (
        (
            "generate_image",
            metering.generate_image_with_accounting,
            ImageGenerationRequest(model="paid-image", prompt="draw"),
            "images.create",
        ),
        (
            "generate_image_asset_urls",
            metering.generate_image_asset_urls_with_accounting,
            ImageGenerationRequest(
                model="paid-image", prompt="draw", response_format="url"
            ),
            "images.create",
        ),
        (
            "generate_video",
            metering.generate_video_with_accounting,
            VideoGenerationRequest(model="paid-video", prompt="animate"),
            "videos.create",
        ),
    ),
)
async def test_accounted_dispatch_reaches_exact_router_generation_once(
    tmp_path,
    method: str,
    helper,
    payload: ImageGenerationRequest | VideoGenerationRequest,
    authority_operation: str,
) -> None:
    raw = _AllMediaProvider()
    provider = _ProviderGeneration(raw, on_closed=lambda _provider: None)
    ledger = ProviderCallLedger(tmp_path / f"{method}.db", required=True)

    try:
        with metering.bind_paid_media_authority(
            principal_hash="b" * 64,
            operation=authority_operation,
        ):
            await helper(
                provider,
                payload,
                "paid-upstream",
                actual_model=payload.model,
                provider_call_ledger=ledger,
            )
        calls = ledger.list_calls()
    finally:
        ledger.close()

    assert raw.calls == [method]
    assert len(calls) == 1
    assert calls[0]["status"] == "success"


@pytest.mark.asyncio
async def test_accounted_dispatch_permit_is_bound_to_router_generation(
    tmp_path,
) -> None:
    target_raw = _AllMediaProvider()
    target = _ProviderGeneration(target_raw, on_closed=lambda _provider: None)

    class ForwardingProvider(_AllMediaProvider):
        async def generate_image(self, request, upstream_model):  # noqa: ANN001
            self.calls.append("generate_image")
            return await target.generate_image(request, upstream_model)

    source_raw = ForwardingProvider()
    source = _ProviderGeneration(source_raw, on_closed=lambda _provider: None)
    ledger = ProviderCallLedger(tmp_path / "generation-bound-ledger.db", required=True)

    try:
        with metering.bind_paid_media_authority(
            principal_hash="c" * 64,
            operation="images.create",
        ):
            with pytest.raises(ProviderError) as exc_info:
                await metering.generate_image_with_accounting(
                    source,
                    ImageGenerationRequest(model="paid-image", prompt="draw"),
                    "paid-upstream",
                    actual_model="paid-image",
                    provider_call_ledger=ledger,
                )
    finally:
        ledger.close()

    assert exc_info.value.status_code == 403
    assert source_raw.calls == ["generate_image"]
    assert target_raw.calls == []


@pytest.mark.asyncio
async def test_cancelled_accounted_dispatch_permit_cannot_be_reused(tmp_path) -> None:
    started = asyncio.Event()

    class BlockingProvider(_AllMediaProvider):
        async def generate_image(self, _request, _upstream_model):  # noqa: ANN001
            self.calls.append("generate_image")
            started.set()
            await asyncio.Event().wait()

    raw = BlockingProvider()
    provider = _ProviderGeneration(raw, on_closed=lambda _provider: None)
    ledger = ProviderCallLedger(tmp_path / "cancelled-permit-ledger.db", required=True)
    request = ImageGenerationRequest(model="paid-image", prompt="draw")

    try:
        with metering.bind_paid_media_authority(
            principal_hash="d" * 64,
            operation="images.create",
        ):
            task = asyncio.create_task(
                metering.generate_image_with_accounting(
                    provider,
                    request,
                    "paid-upstream",
                    actual_model="paid-image",
                    provider_call_ledger=ledger,
                )
            )
            await asyncio.wait_for(started.wait(), timeout=5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        with pytest.raises(ProviderError) as exc_info:
            await provider.generate_image(request, "paid-upstream")
        calls = ledger.list_calls()
    finally:
        ledger.close()

    assert exc_info.value.status_code == 403
    assert raw.calls == ["generate_image"]
    assert len(calls) == 1
    assert calls[0]["status"] == "cancelled"


class _Router:
    def __init__(self, provider, *, kind: str) -> None:  # noqa: ANN001
        self.provider = provider
        self.kind = kind
        self.chat_route = SimpleNamespace(
            provider=provider,
            upstream_model="chat-upstream",
            tier="cheap",
            modality="chat",
            exec_backend="",
        )
        self.route = SimpleNamespace(
            provider=provider,
            upstream_model=f"{kind}-upstream",
            tier="premium",
            modality=kind,
            exec_backend="",
        )

    def resolve(self, model: str):  # noqa: ANN201
        accepted = {"agnes-image", "paid-image"} if self.kind == "image" else {
            "agnes-video",
            "paid-video",
        }
        if model == "chat-model":
            return self.chat_route
        return self.route if model in accepted else None

    async def aclose(self) -> None:
        return None


async def test_paid_create_gate_runs_before_financial_ledger_and_provider(
    monkeypatch,
) -> None:
    provider = _ImageProvider()
    ledger_touched = False

    async def forbidden_ledger(_ledger):  # noqa: ANN001
        nonlocal ledger_touched
        ledger_touched = True
        raise AssertionError("financial ledger must not be reached without paid authority")

    monkeypatch.setattr(
        metering,
        "resolve_provider_call_ledger_durable",
        forbidden_ledger,
    )

    with pytest.raises(Exception, match="durable paid-media operation"):
        await metering.generate_image_with_accounting(
            provider,
            ImageGenerationRequest(model="paid-image", prompt="draw"),
            "image-upstream",
            actual_model="paid-image",
        )

    assert ledger_touched is False
    assert provider.calls == 0


async def test_one_durable_authority_cannot_create_twice(tmp_path) -> None:
    provider = _ImageProvider()
    ledger = ProviderCallLedger(tmp_path / "paid-authority-ledger.db", required=True)
    request = ImageGenerationRequest(model="paid-image", prompt="draw once")

    try:
        with metering.bind_paid_media_authority(
            principal_hash="a" * 64,
            operation="images.create",
        ):
            await metering.generate_image_with_accounting(
                provider,
                request,
                "image-upstream",
                actual_model="paid-image",
                provider_call_ledger=ledger,
            )
            with pytest.raises(Exception, match="durable paid-media operation"):
                await metering.generate_image_with_accounting(
                    provider,
                    request,
                    "image-upstream",
                    actual_model="paid-image",
                    provider_call_ledger=ledger,
                )
    finally:
        ledger.close()

    assert provider.calls == 1


def test_runtime_bearer_agent_image_path_cannot_reach_paid_provider(
    monkeypatch,
) -> None:
    provider = _ImageProvider()

    async def image_intent(*_args, **_kwargs):  # noqa: ANN002, ANN003
        return "image"

    async def fixed_prompt(*_args, **_kwargs):  # noqa: ANN002, ANN003
        return "fixed paid prompt"

    monkeypatch.setattr(agentmod, "classify_intent", image_intent)
    monkeypatch.setattr(agentmod, "polish_prompt", fixed_prompt)

    with TestClient(appmod.app, raise_server_exceptions=False) as client:
        client.app.state.router = _Router(provider, kind="image")
        response = client.post(
            "/v1/agent/chat",
            headers=RUNTIME_AUTH,
            json={
                "message": "生成一张付费图片",
                "channel": "api",
                "model": "chat-model",
            },
        )

    assert response.status_code == 403
    assert "鉴权失败" in response.text
    assert "durable paid-media operation" not in response.text
    assert provider.calls == 0


def test_runtime_bearer_agent_video_path_cannot_reach_paid_provider(
    monkeypatch,
) -> None:
    provider = _VideoProvider()

    async def video_intent(*_args, **_kwargs):  # noqa: ANN002, ANN003
        return "video"

    async def fixed_prompt(*_args, **_kwargs):  # noqa: ANN002, ANN003
        return "fixed paid video prompt"

    monkeypatch.setattr(agentmod, "classify_intent", video_intent)
    monkeypatch.setattr(agentmod, "polish_prompt", fixed_prompt)

    with TestClient(appmod.app, raise_server_exceptions=False) as client:
        client.app.state.router = _Router(provider, kind="video")
        response = client.post(
            "/v1/agent/chat",
            headers=RUNTIME_AUTH,
            json={
                "message": "生成一段付费视频",
                "channel": "api",
                "model": "chat-model",
                "video_async": True,
            },
        )

    assert response.status_code == 403
    assert "鉴权失败" in response.text
    assert "durable paid-media operation" not in response.text
    assert provider.calls == 0


async def test_studio_execution_without_durable_paid_operation_cannot_reach_provider(
    monkeypatch,
) -> None:
    provider = _VideoProvider()
    job_id = "paid-boundary-studio"
    studiomod._JOBS[job_id] = {  # noqa: SLF001
        "status": "running",
        "progress": 0,
        "total": 0,
        "video": "",
        "error": "",
        "msg": "start",
    }
    monkeypatch.setattr(studiomod, "_persist", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        studiomod,
        "_download",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("download must not run when paid provider is blocked")
        ),
    )
    plan = {
        "title": "blocked",
        "style": "",
        "subject": "",
        "shots": [{"desc": "one paid shot", "seconds": 5}],
    }

    try:
        await studiomod._do_execution(  # noqa: SLF001
            job_id,
            _Router(provider, kind="video"),
            plan,
            ".",
        )
        assert provider.calls == 0
        assert studiomod._JOBS[job_id]["status"] == "error"  # noqa: SLF001
        assert "durable paid-media operation" in studiomod._JOBS[job_id][  # noqa: SLF001
            "error"
        ]
    finally:
        studiomod._JOBS.pop(job_id, None)  # noqa: SLF001


def test_only_durable_paid_endpoints_bind_provider_authority() -> None:
    root = Path(__file__).resolve().parents[1]
    production_roots = (root / "gateway", root / "orchestrator")
    guarded_operations = {
        "generate_image": "media.generate_image",
        "generate_image_asset_urls": "media.generate_image",
        "generate_video": "media.generate_video",
    }
    provider_methods = frozenset(guarded_operations)
    unmetered: list[str] = []
    guarded_router_dispatches: set[str] = set()
    binders: list[tuple[str, str]] = []

    for production_root in production_roots:
        for path in production_root.rglob("*.py"):
            relative = path.relative_to(root).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            parents: dict[ast.AST, ast.AST] = {}
            for parent in ast.walk(tree):
                for child in ast.iter_child_nodes(parent):
                    parents[child] = parent
            for node in ast.walk(tree):
                if (
                    relative != "gateway/media_call_metering.py"
                    and not relative.startswith("gateway/providers/")
                    and isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in provider_methods
                ):
                    owner: ast.AST | None = node
                    while owner is not None and not isinstance(
                        owner, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        owner = parents.get(owner)
                    class_owner = parents.get(owner) if owner is not None else None
                    while class_owner is not None and not isinstance(
                        class_owner, ast.ClassDef
                    ):
                        class_owner = parents.get(class_owner)
                    expected_operation = guarded_operations[node.func.attr]
                    guard_precedes_dispatch = bool(
                        isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and owner.name == node.func.attr
                        and isinstance(class_owner, ast.ClassDef)
                        and class_owner.name == "_ProviderGeneration"
                        and any(
                            isinstance(candidate, ast.Call)
                            and isinstance(candidate.func, ast.Name)
                            and candidate.func.id
                            == "_consume_paid_media_dispatch_permit"
                            and len(candidate.args) == 2
                            and isinstance(candidate.args[0], ast.Name)
                            and candidate.args[0].id == "self"
                            and isinstance(candidate.args[1], ast.Constant)
                            and candidate.args[1].value == expected_operation
                            and candidate.lineno < node.lineno
                            for candidate in ast.walk(owner)
                        )
                    )
                    if guard_precedes_dispatch:
                        guarded_router_dispatches.add(node.func.attr)
                        continue
                    unmetered.append(f"{relative}:{node.lineno}:{node.func.attr}")
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "bind_paid_media_authority"
                ):
                    owner: ast.AST | None = node
                    while owner is not None and not isinstance(
                        owner, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        owner = parents.get(owner)
                    binders.append(
                        (
                            relative,
                            owner.name if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)) else "",
                        )
                    )

    assert unmetered == []
    assert guarded_router_dispatches == set(guarded_operations)
    # The public endpoints share one choke point with the ADR-0013 web console
    # routes; the authority bind must live in exactly those two internal
    # implementations and nowhere else.
    assert sorted(binders) == [
        ("gateway/app.py", "_execute_paid_image_generation"),
        ("gateway/app.py", "_execute_paid_video_generation"),
    ]
