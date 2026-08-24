"""Public paid-media idempotency contract for image and video creation."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.asset_installation_control import AssetInstallationControlUnavailable
from gateway.durable_media_requests import (
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    hash_media_principal,
    hash_media_request,
)
from gateway.gateway_installation_control import (
    GatewayInstallationControlUnavailable,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
)
from gateway.provider_call_ledger import ProviderCallContext
from gateway.providers.base import ProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import ImageGenerationRequest
from gateway.trusted_media_probe import TrustedMediaProbeResult


PAID_MEDIA_SECRET = "sk-paid-media-" + ("a" * 64)
RUNTIME_AUTH = {"Authorization": "Bearer test-key"}
INSTALLATION_ID = "d" * 64
INSTALLATION_EPOCH = 7
_BASE_PAID_AUTH = {
    **RUNTIME_AUTH,
    "X-Nachuan-Paid-Media-Key": PAID_MEDIA_SECRET,
}


def _v2_headers(base: dict[str, str] | None = None) -> dict[str, str]:
    return {
        **(_BASE_PAID_AUTH if base is None else base),
        "X-Nachuan-Paid-Media-Protocol": "2",
    }


# Every ordinary route fixture now speaks the mandatory asset protocol. Tests
# that intentionally vary credentials override only those credentials; none of
# them silently exercises the removed pre-v2 request shape.
AUTH = _v2_headers()


class _InstallationControl:
    def __init__(self, *, fail: bool = False, events: list[str] | None = None) -> None:
        self.fail = fail
        self.calls = 0
        self.events = events
        self.paid_principal = "c" * 64

    @property
    def state(self):  # noqa: ANN201
        return SimpleNamespace(
            mode="ready",
            reason_code=(
                "installation-root-unavailable" if self.fail else "authority-exact"
            ),
            outbound_ready=not self.fail,
            paid_principal=self.paid_principal,
            installation_id=INSTALLATION_ID,
            epoch=INSTALLATION_EPOCH,
        )

    def assert_outbound_ready(self):  # noqa: ANN201
        self.calls += 1
        if self.events is not None:
            self.events.append("assert")
        if self.fail:
            raise GatewayInstallationControlUnavailable(
                "installation root changed after the local fence"
            )
        return self.state


class _AssetInstallationControl:
    def __init__(self) -> None:
        self.calls = 0
        self.mode = "ready"

    @property
    def state(self):  # noqa: ANN201
        return SimpleNamespace(
            mode=self.mode,
            reason_code=(
                "authority-exact"
                if self.mode == "ready"
                else "manual-recovery-required"
            ),
            installation_id=INSTALLATION_ID,
            epoch=INSTALLATION_EPOCH,
        )

    def assert_local_mutation_ready(self) -> None:
        self.calls += 1
        if self.mode != "ready":
            raise AssetInstallationControlUnavailable(
                "asset installation authority is manual only"
            )


class _FakeProvider:
    name = "paid-media-fake"
    paid_media_asset_protocol_versions = frozenset({"2"})
    paid_media_video_asset_protocol_versions = frozenset({"2"})

    def __init__(self) -> None:
        self.image_calls = 0
        self.video_calls = 0
        self.video_poll_calls: list[str] = []
        self.video_create_status = "completed"
        self.video_poll_delay = 0.0
        self.fail_image = False
        self.fail_video = False
        self.assets_by_url: dict[str, tuple[bytes, str]] = {}

    def register_asset(self, url: str, payload: bytes, media_type: str) -> None:
        self.assets_by_url[url] = (payload, media_type)

    async def generate_image_asset_urls(self, _request, _upstream_model):
        self.image_calls += 1
        if self.fail_image:
            raise ProviderError(
                "provider outcome unavailable SECRET-UPSTREAM-BODY",
                status_code=502,
            )
        url = f"https://media.invalid/image-{self.image_calls}.png"
        self.register_asset(url, f"private-image-{self.image_calls}".encode(), "image/png")
        return {"data": [{"url": url}]}

    async def generate_video(self, _request, _upstream_model):
        self.video_calls += 1
        if self.fail_video:
            raise ProviderError(
                "video provider failed SECRET-VIDEO-UPSTREAM-BODY",
                status_code=502,
            )
        result = {
            "task_id": f"video-{self.video_calls}",
            "status": self.video_create_status,
            **(
                {"url": f"https://media.invalid/video-{self.video_calls}.mp4"}
                if self.video_create_status == "completed"
                else {}
            ),
        }
        if self.video_create_status == "completed":
            self.register_asset(
                str(result["url"]),
                f"private-video-{self.video_calls}".encode(),
                "video/mp4",
            )
        return result

    async def get_video(self, task_id: str):
        self.video_poll_calls.append(task_id)
        if self.video_poll_delay:
            await asyncio.sleep(self.video_poll_delay)
        result = {
            "task_id": task_id,
            "status": "completed",
            "url": f"https://media.invalid/{self.name}/{task_id}.mp4",
        }
        self.register_asset(
            str(result["url"]),
            f"private-video-poll-{task_id}".encode(),
            "video/mp4",
        )
        return result


def _asset_store_dependencies() -> PaidMediaAssetStoreDependencies:
    return PaidMediaAssetStoreDependencies(
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda path, directory: os.chmod(
            path, 0o700 if directory else 0o600
        ),
        disk_free=lambda _path: 16 * 1024 * 1024 * 1024,
    )


def _asset_probe(
    path,
    *,
    expected_media_type: str,
    expected_byte_length: int,
    expected_sha256: str,
    **_kwargs,
) -> TrustedMediaProbeResult:
    payload = Path(path).read_bytes()
    assert len(payload) == expected_byte_length
    assert hashlib.sha256(payload).hexdigest() == expected_sha256
    is_image = expected_media_type.startswith("image/")
    return TrustedMediaProbeResult(
        media_type=expected_media_type,
        detected_kind="image" if is_image else "video",
        byte_length=expected_byte_length,
        sha256=expected_sha256,
        codec_name="png" if is_image else "h264",
        audio_codec_name=None,
        video_stream_count=1,
        audio_stream_count=0,
        format_name="png_pipe" if is_image else "mp4",
        width=1 if is_image else 16,
        height=1 if is_image else 16,
        duration_ms=None if is_image else 1000,
        decoded_frames=1,
        ffmpeg_sha256="4" * 64,
        ffprobe_sha256="5" * 64,
    )


class _Router:
    def __init__(
        self,
        provider: _FakeProvider,
        *,
        independence_domain: str = "a" * 64,
        credential_domain: str | None = "e" * 64,
        base_url: str = "https://paid-video.invalid/v1",
    ) -> None:
        provider.base_url = base_url
        provider._headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer paid-video-test-token",
        }
        if credential_domain is None:
            if hasattr(provider, "paid_video_credential_domain"):
                delattr(provider, "paid_video_credential_domain")
        else:
            provider.paid_video_credential_domain = credential_domain
        self.route = SimpleNamespace(
            provider=provider,
            upstream_model="paid-upstream",
            tier="premium",
            independence_domain=independence_domain,
        )

    def resolve(self, model: str):  # noqa: ANN201
        return self.route if model == "paid-model" else None

    async def aclose(self) -> None:
        return None


@pytest.fixture
def media_client(tmp_path, monkeypatch):
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", PAID_MEDIA_SECRET)
    appmod.get_settings.cache_clear()
    store = DurableMediaRequestStore(tmp_path / "paid-media-requests.db")
    asset_store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=INSTALLATION_EPOCH,
        max_capacity_bytes=16 * OPERATION_RESERVATION_BYTES,
        dependencies=_asset_store_dependencies(),
    )
    provider = _FakeProvider()
    image_contexts: list[ProviderCallContext | None] = []
    video_contexts: list[ProviderCallContext | None] = []
    real_image_call = appmod.generate_image_asset_urls_with_accounting
    real_video_call = appmod.generate_video_with_accounting

    async def image_spy(*args, **kwargs):
        image_contexts.append(kwargs.get("call_context"))
        return await real_image_call(*args, **kwargs)

    async def video_spy(*args, **kwargs):
        video_contexts.append(kwargs.get("call_context"))
        return await real_video_call(*args, **kwargs)

    async def trusted_media_ready():
        return {
            "schema": "nachuan.trusted-media-probe.readiness.v2",
            "validatorVersion": "nachuan.trusted-media-probe.v2",
            "validationPolicy": "nachuan.trusted-media-policy.av-closed.v1",
            "ready": True,
            "attestedTools": {
                "ffmpegSha256": "4" * 64,
                "ffprobeSha256": "5" * 64,
            },
        }

    monkeypatch.setattr(
        appmod, "generate_image_asset_urls_with_accounting", image_spy
    )
    monkeypatch.setattr(appmod, "generate_video_with_accounting", video_spy)
    monkeypatch.setattr(
        appmod,
        "trusted_media_readiness_receipt",
        trusted_media_ready,
    )
    if hasattr(appmod, "media_cache"):
        def forbidden_cache(*_args, **_kwargs):
            raise AssertionError("paid create route must not consult media_cache")

        monkeypatch.setattr(appmod.media_cache, "get", forbidden_cache)
        monkeypatch.setattr(appmod.media_cache, "put", forbidden_cache)

    client = TestClient(appmod.app, raise_server_exceptions=False)
    client.app.state.router = _Router(provider)
    client.app.state.media_requests = store
    client.app.state.paid_media_assets = asset_store
    client.app.state.paid_media_epoch = INSTALLATION_EPOCH
    client.app.state.paid_media_authority_mode = "development"
    client.app.state.paid_media_principal = hash_media_principal(PAID_MEDIA_SECRET)
    client.app.state.installation_root_control = None
    client.app.state.usage = SimpleNamespace(log=lambda **_kwargs: None)

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str | None = None,
    ):
        payload, media_type = provider.assets_by_url.get(
            url,
            (
                f"private-provider-asset:{url}".encode(),
                "video/mp4" if url.lower().endswith(".mp4") else "image/png",
            ),
        )
        if media_type.startswith("video/"):
            assert isinstance(prepared_token, str) and prepared_token
        else:
            assert prepared_token is None
        return asset_store.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type=media_type,
            chunks=(base64.b64encode(payload).decode("ascii"),),
            probe=_asset_probe,
            **(
                {"prepared_token": prepared_token}
                if prepared_token is not None
                else {}
            ),
        )

    monkeypatch.setattr(asset_store, "stage_url", local_stage_url)
    appmod.configure_background_job_pool(
        max_global=8,
        max_per_key=4,
        lease_ttl_seconds=300.0,
    )
    try:
        yield SimpleNamespace(
            client=client,
            provider=provider,
            store=store,
            image_contexts=image_contexts,
            video_contexts=video_contexts,
        )
    finally:
        client.close()
        asset_store.close()
        store.close()
        appmod.get_settings.cache_clear()


def test_runtime_bearer_alone_cannot_authorize_paid_media_create(
    media_client, monkeypatch
) -> None:
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", PAID_MEDIA_SECRET)
    appmod.get_settings.cache_clear()
    try:
        response = media_client.client.post(
            "/v1/images/generations",
            headers={
                **_v2_headers(RUNTIME_AUTH),
                "Idempotency-Key": "desktop-a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1",
            },
            json={"model": "paid-model", "prompt": "draw"},
        )
    finally:
        appmod.get_settings.cache_clear()

    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0


def test_packaged_missing_installation_principal_disables_only_paid_create(
    media_client, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority_mode",
        "installation-root",
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_principal",
        None,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        None,
        raising=False,
    )

    blocked = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-10101010-1010-4010-8010-101010101010",
        },
        json={"model": "paid-model", "prompt": "missing root"},
    )

    assert blocked.status_code == 503
    assert blocked.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0
    with closing(sqlite3.connect(media_client.store.path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)


def test_packaged_paid_media_fails_before_long_lived_key_validation(
    media_client, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority_mode",
        "installation-root",
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_principal",
        "c" * 64,
        raising=False,
    )

    blocked = media_client.client.post(
        "/v1/images/generations",
        headers={
            **_v2_headers(),
            "Authorization": "Bearer deliberately-wrong-runtime-key",
            "X-Nachuan-Paid-Media-Key": "deliberately-wrong-paid-key",
            "Idempotency-Key": "desktop-20202020-2020-4020-8020-202020202020",
        },
        json={"model": "paid-model", "prompt": "must stay gated"},
    )

    assert blocked.status_code == 503
    assert blocked.headers["Cache-Control"] == "no-store"
    assert "engine-session" in blocked.text
    assert "deliberately-wrong" not in blocked.text
    assert media_client.provider.image_calls == 0
    with closing(sqlite3.connect(media_client.store.path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)


def test_paid_media_key_cannot_overlap_runtime_bearer(
    media_client, monkeypatch
) -> None:
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", "test-key")
    appmod.get_settings.cache_clear()
    try:
        response = media_client.client.post(
            "/v1/images/generations",
            headers={
                **AUTH,
                "X-Nachuan-Paid-Media-Key": "test-key",
                "Idempotency-Key": "desktop-b2b2b2b2-2222-4222-8222-b2b2b2b2b2b2",
            },
            json={"model": "paid-model", "prompt": "draw"},
        )
    finally:
        appmod.get_settings.cache_clear()

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0


def test_paid_media_key_configuration_requires_a_random_secret_shape(
    media_client, monkeypatch
) -> None:
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", "weak-secret")
    appmod.get_settings.cache_clear()
    try:
        response = media_client.client.post(
            "/v1/images/generations",
            headers={
                **AUTH,
                "X-Nachuan-Paid-Media-Key": "weak-secret",
                "Idempotency-Key": "desktop-c3c3c3c3-3333-4333-8333-c3c3c3c3c3c3",
            },
            json={"model": "paid-model", "prompt": "draw"},
        )
    finally:
        appmod.get_settings.cache_clear()

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0


def test_paid_media_key_cannot_overlap_approval_authority(
    media_client, monkeypatch
) -> None:
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", PAID_MEDIA_SECRET)
    monkeypatch.setenv("APPROVAL_ADMIN_KEY", PAID_MEDIA_SECRET)
    appmod.get_settings.cache_clear()
    try:
        response = media_client.client.post(
            "/v1/images/generations",
            headers={
                **AUTH,
                "X-Nachuan-Paid-Media-Key": PAID_MEDIA_SECRET,
                "Idempotency-Key": "desktop-d4d4d4d4-4444-4444-8444-d4d4d4d4d4d4",
            },
            json={"model": "paid-model", "prompt": "draw"},
        )
    finally:
        appmod.get_settings.cache_clear()

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0


@pytest.mark.parametrize(
    "bridge_env",
    [
        "BRIDGE_API_KEY",
        "NACHUAN_WEIXIN_BRIDGE_API_KEY",
        "NACHUAN_FEISHU_BRIDGE_API_KEY",
    ],
)
def test_paid_media_key_cannot_overlap_channel_authority(
    media_client, monkeypatch, bridge_env
) -> None:
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", PAID_MEDIA_SECRET)
    monkeypatch.setenv(bridge_env, PAID_MEDIA_SECRET)
    appmod.get_settings.cache_clear()
    try:
        response = media_client.client.post(
            "/v1/images/generations",
            headers={
                **AUTH,
                "X-Nachuan-Paid-Media-Key": PAID_MEDIA_SECRET,
                "Idempotency-Key": "desktop-e5e5e5e5-5555-4555-8555-e5e5e5e5e5e5",
            },
            json={"model": "paid-model", "prompt": "draw"},
        )
    finally:
        appmod.get_settings.cache_clear()

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0


def test_duplicate_paid_media_capability_headers_are_rejected(media_client) -> None:
    response = media_client.client.post(
        "/v1/images/generations",
        headers=[
            ("Authorization", "Bearer test-key"),
            ("X-Nachuan-Paid-Media-Key", PAID_MEDIA_SECRET),
            ("X-Nachuan-Paid-Media-Key", PAID_MEDIA_SECRET),
            ("X-Nachuan-Paid-Media-Protocol", "2"),
            (
                "Idempotency-Key",
                "desktop-f6f6f6f6-6666-4666-8666-f6f6f6f6f6f6",
            ),
        ],
        json={"model": "paid-model", "prompt": "draw"},
    )

    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
    assert PAID_MEDIA_SECRET not in response.text
    assert media_client.provider.image_calls == 0


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/images/generations", {"model": "paid-model", "prompt": "draw"}),
        ("/v1/videos/generations", {"model": "paid-model", "prompt": "film"}),
    ],
)
def test_paid_media_requires_a_valid_stable_key(media_client, path, body) -> None:
    missing = media_client.client.post(path, headers=AUTH, json=body)
    malformed = media_client.client.post(
        path,
        headers={**AUTH, "Idempotency-Key": "short"},
        json=body,
    )

    assert missing.status_code == 422
    assert missing.json()["detail"] == {
        "code": "invalid_idempotency_key",
        "message": "A stable Idempotency-Key is required for paid media creation.",
        "retryable": False,
    }
    assert missing.headers["Cache-Control"] == "no-store"
    assert malformed.status_code == 422
    assert media_client.provider.image_calls + media_client.provider.video_calls == 0


@pytest.mark.parametrize(
    "path",
    ["/v1/images/generations", "/v1/videos/generations"],
)
def test_openapi_declares_paid_media_idempotency_key_as_required(path) -> None:
    operation = appmod.app.openapi()["paths"][path]["post"]
    header = next(
        item
        for item in operation["parameters"]
        if item["in"] == "header" and item["name"] == "Idempotency-Key"
    )

    assert header["required"] is True
    assert header["schema"]["type"] == "string"


@pytest.mark.parametrize(
    ("path", "body", "key"),
    [
        (
            "/v1/images/generations",
            {"model": "paid-model", "prompt": "draw", "n": "SECRET-IMAGE-INPUT"},
            "desktop-c3c3c3c3-3333-4333-8333-c3c3c3c3c3c3",
        ),
        (
            "/v1/videos/generations",
            {
                "model": "paid-model",
                "prompt": "film",
                "width": "SECRET-VIDEO-INPUT",
                "height": 64,
            },
            "desktop-d4d4d4d4-4444-4444-8444-d4d4d4d4d4d4",
        ),
    ],
)
def test_invalid_paid_media_body_never_echoes_secret_input(
    media_client, path, body, key
) -> None:
    response = media_client.client.post(
        path,
        headers={**AUTH, "Idempotency-Key": key},
        json=body,
    )

    assert response.status_code == 422
    assert "SECRET-" not in response.text
    assert response.json()["detail"] == {
        "code": "invalid_media_request",
        "message": "Paid media request body is invalid.",
        "retryable": False,
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls + media_client.provider.video_calls == 0


@pytest.mark.parametrize(
    ("path", "body", "key"),
    [
        (
            "/v1/images/generations",
            {
                "model": "paid-model",
                "prompt": "draw",
                "provider_cost_override": {"credits": 99},
            },
            "desktop-acdeabcd-1111-4111-8111-acdeabcdef11",
        ),
        (
            "/v1/videos/generations",
            {
                "model": "paid-model",
                "prompt": "film",
                "extra_body": {
                    "image": ["aGVsbG8="],
                    "hidden_provider_option": {"credits": 99},
                },
            },
            "desktop-acdeabcd-2222-4222-8222-acdeabcdef22",
        ),
    ],
)
def test_paid_media_rejects_non_versioned_provider_parameters_before_claim(
    media_client, path, body, key
) -> None:
    response = media_client.client.post(
        path,
        headers={**AUTH, "Idempotency-Key": key},
        json=body,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "invalid_media_request",
        "message": "Paid media request body is invalid.",
        "retryable": False,
    }
    assert media_client.provider.image_calls + media_client.provider.video_calls == 0
    with closing(sqlite3.connect(media_client.store.path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/v1/images/generations", b'{"prompt":"SECRET-MALFORMED"'),
        ("/v1/videos/generations", b'{"prompt":"SECRET-MALFORMED"'),
        ("/v1/images/generations", b'{"prompt":"\xff"}'),
        ("/v1/videos/generations", b'{"prompt":"\xff"}'),
    ],
)
def test_malformed_paid_media_json_is_fixed_no_store(
    media_client, path, payload
) -> None:
    response = media_client.client.post(
        path,
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-acdeabcd-1234-4abc-8abc-acdeabcdef12",
            "Content-Type": "application/json",
        },
        content=payload,
    )

    assert response.status_code == 422
    assert "SECRET-" not in response.text
    assert response.json()["detail"] == {
        "code": "invalid_media_request",
        "message": "Paid media request body is invalid.",
        "retryable": False,
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls + media_client.provider.video_calls == 0


def test_image_success_replays_and_binds_stable_provider_turn(media_client) -> None:
    headers = {
        **AUTH,
        "Idempotency-Key": "desktop-11111111-aaaa-4111-8111-111111111111",
    }
    first = media_client.client.post(
        "/v1/images/generations",
        headers=headers,
        json={"prompt": "  canonical cat  ", "model": "paid-model"},
    )
    replay = media_client.client.post(
        "/v1/images/generations",
        headers=headers,
        json={"model": "paid-model", "prompt": "canonical cat"},
    )

    assert first.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert media_client.provider.image_calls == 1
    assert len(media_client.image_contexts) == 1
    context = media_client.image_contexts[0]
    assert isinstance(context, ProviderCallContext)
    assert re.fullmatch(r"[0-9a-f]{64}", str(context.turn_id))
    assert context.workflow_id == "paid_media:images.create"


def test_image_success_above_24mib_is_durable_before_first_2xx(
    media_client, monkeypatch
) -> None:
    # Nineteen decoded MiB is below Main's per-image limit, while canonical
    # base64 plus JSON is above the historical 24 MiB Gateway replay ceiling.
    image_bytes = b"\x89PNG\r\n\x1a\n" + (b"\0" * (19 * 1024 * 1024 - 8))
    asset_url = "https://media.invalid/large-image.png"

    async def large_image(_request, _upstream_model):
        media_client.provider.image_calls += 1
        media_client.provider.register_asset(asset_url, image_bytes, "image/png")
        return {"data": [{"url": asset_url}]}

    monkeypatch.setattr(
        media_client.provider, "generate_image_asset_urls", large_image
    )
    headers = {
        **AUTH,
        "Idempotency-Key": "desktop-25252525-2525-4525-8525-252525252525",
    }
    body = {"model": "paid-model", "prompt": "durable large image"}

    first = media_client.client.post(
        "/v1/images/generations", headers=headers, json=body
    )
    replay = media_client.client.post(
        "/v1/images/generations", headers=headers, json=body
    )

    assert first.status_code == replay.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert len(first.content) < 1024 * 1024
    assert first.json()["assets"][0]["byteLength"] == len(image_bytes)
    assert "url" not in first.text
    assert media_client.provider.image_calls == 1


@pytest.mark.parametrize(
    ("path", "body", "key", "counter_name"),
    [
        (
            "/v1/images/generations",
            {"model": "paid-model", "prompt": "route-independent image replay"},
            "desktop-a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1",
            "image_calls",
        ),
        (
            "/v1/videos/generations",
            {"model": "paid-model", "prompt": "route-independent video replay"},
            "desktop-b2b2b2b2-2222-4222-8222-b2b2b2b2b2b2",
            "video_calls",
        ),
    ],
)
def test_success_replays_after_route_is_removed_without_second_provider_call(
    media_client, path, body, key, counter_name
) -> None:
    headers = {**AUTH, "Idempotency-Key": key}
    first = media_client.client.post(path, headers=headers, json=body)
    media_client.client.app.state.router = SimpleNamespace(resolve=lambda _model: None)
    replay = media_client.client.post(path, headers=headers, json=body)

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert getattr(media_client.provider, counter_name) == 1


def test_router_failure_is_sanitized_and_abandons_pre_provider_claim(
    media_client,
) -> None:
    class ExplodingRouter:
        def resolve(self, _model):
            raise RuntimeError("SECRET-ROUTER-FAILURE")

    media_client.client.app.state.router = ExplodingRouter()
    response = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-e5e5e5e5-5555-4555-8555-e5e5e5e5e5e5",
        },
        json={"model": "paid-model", "prompt": "router failure"},
    )

    assert response.status_code == 503
    assert "SECRET-" not in response.text
    assert response.json()["detail"] == {
        "code": "media_route_unavailable",
        "message": "Paid media routing is unavailable; no provider call was made.",
        "retryable": False,
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert media_client.provider.image_calls == 0
    with closing(sqlite3.connect(media_client.store.path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)


def test_same_key_different_payload_is_conflict_without_provider_call(media_client) -> None:
    headers = {
        **AUTH,
        "Idempotency-Key": "desktop-22222222-bbbb-4222-8222-222222222222",
    }
    first = media_client.client.post(
        "/v1/images/generations",
        headers=headers,
        json={"model": "paid-model", "prompt": "first"},
    )
    conflict = media_client.client.post(
        "/v1/images/generations",
        headers=headers,
        json={"model": "paid-model", "prompt": "changed"},
    )

    assert first.status_code == 200
    assert conflict.status_code == 409
    assert conflict.headers["Cache-Control"] == "no-store"
    assert conflict.json()["detail"]["code"] == "idempotency_key_conflict"
    assert media_client.provider.image_calls == 1


def test_different_key_same_image_payload_is_two_paid_authorizations(media_client) -> None:
    body = {"model": "paid-model", "prompt": "intentional rerun"}
    first = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-33333333-cccc-4333-8333-333333333333",
        },
        json=body,
    )
    second = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-44444444-dddd-4444-8444-444444444444",
        },
        json=body,
    )

    assert first.status_code == second.status_code == 200
    assert first.json() != second.json()
    assert media_client.provider.image_calls == 2
    assert len({context.turn_id for context in media_client.image_contexts}) == 2


def test_active_request_returns_425_with_retry_after(media_client) -> None:
    key = "desktop-55555555-eeee-4555-8555-555555555555"
    model = ImageGenerationRequest(
        model="paid-model", prompt="still running"
    ).model_copy(update={"response_format": "url"})
    media_client.store.claim(
        principal_hash=hash_media_principal(PAID_MEDIA_SECRET),
        operation="images.create",
        idempotency_key=key,
        request_sha256=hash_media_request(
            "images.create", model.model_dump(mode="json", exclude_none=True)
        ),
    )

    response = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": key},
        json={"model": "paid-model", "prompt": "still running"},
    )

    assert response.status_code == 425
    assert 1 <= int(response.headers["Retry-After"]) <= 900
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"]["code"] == "media_request_processing"
    assert media_client.provider.image_calls == 0


def test_provider_failure_becomes_non_retryable_recovery_state(media_client) -> None:
    key = "desktop-66666666-ffff-4666-8666-666666666666"
    headers = {**AUTH, "Idempotency-Key": key}
    body = {"model": "paid-model", "prompt": "ambiguous"}
    media_client.provider.fail_image = True

    first = media_client.client.post(
        "/v1/images/generations", headers=headers, json=body
    )
    media_client.provider.fail_image = False
    repeated = media_client.client.post(
        "/v1/images/generations", headers=headers, json=body
    )

    assert first.status_code == 502
    assert "SECRET-UPSTREAM-BODY" not in first.text
    assert first.json()["detail"]["code"] == "media_provider_error"
    assert repeated.status_code == 409
    assert repeated.headers["Cache-Control"] == "no-store"
    assert repeated.json()["detail"] == {
        "code": "media_recovery_required",
        "message": "Provider outcome requires manual recovery; do not auto-retry.",
        "retryable": False,
    }
    assert media_client.provider.image_calls == 1


def test_video_provider_error_is_sanitized_and_capacity_lease_is_bounded(
    media_client,
) -> None:
    pool = appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    clock = [10.0]
    pool._clock = lambda: clock[0]
    media_client.provider.fail_video = True

    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-bcbcbcbc-9999-4cbc-8cbc-bcbcbcbcbcbc",
        },
        json={"model": "paid-model", "prompt": "unknown remote outcome"},
    )

    assert response.status_code == 502
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"]["code"] == "media_provider_error"
    assert "SECRET-VIDEO-UPSTREAM-BODY" not in response.text
    assert pool.counts()["active"] == 1
    clock[0] += 301.0
    assert pool.counts()["active"] == 0


def test_video_asset_v2_is_gated_before_provider_without_separate_video_capability(
    media_client,
) -> None:
    media_client.provider.paid_media_video_asset_protocol_versions = frozenset()
    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **_v2_headers(),
            "Idempotency-Key": "video-v2-gate-1111111111111111111111",
        },
        json={"model": "paid-model", "prompt": "must not call provider"},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == (
        "paid_media_video_protocol_unsupported"
    )
    assert media_client.provider.video_calls == 0
    with sqlite3.connect(media_client.store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)


def test_video_create_requires_trusted_media_probe_before_provider(
    media_client,
    monkeypatch,
) -> None:
    probe_calls = 0
    probe_available = False
    media_client.provider.video_create_status = "queued"

    async def unavailable_probe():
        nonlocal probe_calls, probe_available
        probe_calls += 1
        if not probe_available:
            raise appmod.MediaBinaryUnavailable(
                "FFMPEG_BIN points at C:\\secret\\untrusted-ffmpeg.exe"
            )
        return {
            "schema": "nachuan.trusted-media-probe.readiness.v2",
            "validatorVersion": "nachuan.trusted-media-probe.v2",
            "validationPolicy": "nachuan.trusted-media-policy.av-closed.v1",
            "ready": True,
            "attestedTools": {
                "ffmpegSha256": "4" * 64,
                "ffprobeSha256": "5" * 64,
            },
        }

    monkeypatch.setattr(
        appmod,
        "trusted_media_readiness_receipt",
        unavailable_probe,
    )

    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "video-probe-gate-111111111111111111111111",
        },
        json={"model": "paid-model", "prompt": "must not spend provider quota"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "media_probe_unavailable",
        "message": "Trusted media probe is unavailable; no provider call was made.",
        "retryable": True,
    }
    assert "secret" not in response.text
    assert probe_calls == 1
    assert media_client.provider.video_calls == 0
    with sqlite3.connect(media_client.store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)

    probe_available = True
    recovered = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "video-probe-gate-111111111111111111111111",
        },
        json={"model": "paid-model", "prompt": "must not spend provider quota"},
    )

    assert recovered.status_code == 200
    assert recovered.json()["status"] == "processing"
    assert probe_calls == 2
    assert media_client.provider.video_calls == 1


def test_ambiguous_video_outcome_rebuilds_capacity_before_new_provider_call(
    media_client,
) -> None:
    appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    media_client.provider.fail_video = True
    ambiguous = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-unknown-restart-1111-4111-8111-111111111111",
        },
        json={"model": "paid-model", "prompt": "ambiguous before restart"},
    )
    assert ambiguous.status_code == 502
    assert media_client.provider.video_calls == 1

    media_client.provider.fail_video = False
    restarted_pool = appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    reopened = DurableMediaRequestStore(media_client.store.path)
    original = media_client.client.app.state.media_requests
    media_client.client.app.state.media_requests = reopened
    try:
        blocked = media_client.client.post(
            "/v1/videos/generations",
            headers={
                **AUTH,
                "Idempotency-Key": "desktop-after-unknown-1111-4111-8111-111111111111",
            },
            json={"model": "paid-model", "prompt": "must stay capacity blocked"},
        )
    finally:
        media_client.client.app.state.media_requests = original
        reopened.close()

    assert blocked.status_code == 429
    assert media_client.provider.video_calls == 1
    assert restarted_pool.counts() == {"active": 1, "capacity": 1}


def test_video_recovery_persistence_failure_keeps_only_a_bounded_lease(
    media_client, monkeypatch
) -> None:
    pool = appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    clock = [20.0]
    pool._clock = lambda: clock[0]
    media_client.provider.fail_video = True

    def unavailable(**_kwargs):
        raise DurableMediaRequestUnavailable("disk unavailable")

    monkeypatch.setattr(media_client.store, "mark_recovery_required", unavailable)
    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-cececece-aaaa-4ece-8ece-cececececece",
        },
        json={"model": "paid-model", "prompt": "recovery disk failure"},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["retryable"] is False
    assert pool.counts()["active"] == 1
    clock[0] += 301.0
    assert pool.counts()["active"] == 0


def test_provider_failure_and_recovery_persistence_failure_fails_closed(
    media_client, monkeypatch
) -> None:
    media_client.provider.fail_image = True

    def unavailable(**_kwargs):
        raise DurableMediaRequestUnavailable("disk unavailable")

    monkeypatch.setattr(media_client.store, "mark_recovery_required", unavailable)
    response = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-abababab-4444-4bab-8bab-abababababab",
        },
        json={"model": "paid-model", "prompt": "cannot persist recovery"},
    )

    assert response.status_code == 503
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"] == {
        "code": "media_recovery_persistence_unavailable",
        "message": "Provider outcome could not be finalized; do not auto-retry.",
        "retryable": False,
    }


def test_video_replay_and_new_key_are_distinct_authorizations(media_client) -> None:
    body = {"model": "paid-model", "prompt": "video contract"}
    first_headers = {
        **AUTH,
        "Idempotency-Key": "desktop-77777777-1111-4777-8777-777777777777",
    }
    first = media_client.client.post(
        "/v1/videos/generations", headers=first_headers, json=body
    )
    replay = media_client.client.post(
        "/v1/videos/generations", headers=first_headers, json=body
    )
    intentional_new = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-88888888-2222-4888-8888-888888888888",
        },
        json=body,
    )

    assert first.status_code == replay.status_code == intentional_new.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert intentional_new.json() != first.json()
    assert media_client.provider.video_calls == 2
    assert all(
        context.workflow_id == "paid_media:videos.create"
        for context in media_client.video_contexts
    )


def test_video_poll_is_owner_bound_and_never_follows_a_reconfigured_route(
    media_client, monkeypatch
) -> None:
    media_client.provider.name = "provider-a"
    media_client.provider.video_create_status = "queued"
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-70707070-1111-4707-8707-707070707070",
        },
        json={"model": "paid-model", "prompt": "freeze provider route"},
    )
    assert created.status_code == 200
    task_alias = created.json()["task_id"]
    assert task_alias != "video-1"

    provider_b = _FakeProvider()
    provider_b.name = "provider-b"
    media_client.client.app.state.router = _Router(
        provider_b,
        independence_domain="b" * 64,
    )
    changed = media_client.client.get(
        f"/v1/videos/{task_alias}",
        headers=AUTH,
        params={"model": "paid-model"},
    )

    assert changed.status_code == 409
    assert changed.json()["detail"]["code"] == "video_route_changed"
    assert media_client.provider.video_poll_calls == []
    assert provider_b.video_poll_calls == []

    rotated_paid_secret = "sk-paid-media-" + ("b" * 64)
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", rotated_paid_secret)
    appmod.get_settings.cache_clear()
    wrong_owner = media_client.client.get(
        f"/v1/videos/{task_alias}",
        headers={
            **_v2_headers(RUNTIME_AUTH),
            "X-Nachuan-Paid-Media-Key": rotated_paid_secret,
        },
        params={"model": "paid-model"},
    )
    assert wrong_owner.status_code == 404
    assert media_client.provider.video_poll_calls == []
    assert provider_b.video_poll_calls == []


@pytest.mark.asyncio
async def test_concurrent_video_polls_singleflight_and_terminal_result_is_cached(
    media_client,
) -> None:
    media_client.provider.video_create_status = "queued"
    media_client.provider.video_poll_delay = 0.2
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-71717171-1111-4717-8717-717171717171",
        },
        json={"model": "paid-model", "prompt": "coalesce video polls"},
    )
    assert created.status_code == 200
    task_alias = created.json()["task_id"]

    transport = httpx.ASGITransport(app=appmod.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        first, concurrent = await asyncio.gather(
            client.get(
                f"/v1/videos/{task_alias}",
                headers=AUTH,
                params={"model": "paid-model"},
            ),
            client.get(
                f"/v1/videos/{task_alias}",
                headers=AUTH,
                params={"model": "paid-model"},
            ),
        )
        media_client.client.app.state.router = SimpleNamespace(resolve=lambda _model: None)
        cached = await client.get(
            f"/v1/videos/{task_alias}",
            headers=AUTH,
            params={"model": "paid-model"},
        )

    assert first.status_code == concurrent.status_code == cached.status_code == 200
    assert concurrent.json() == first.json()
    assert cached.json() == first.json()
    assert first.json()["schema"] == "nachuan.paid-media-result.v2"
    assert first.json()["kind"] == "video"
    assert first.json()["turnId"] == task_alias.removeprefix("nvt1_")
    assert len(first.json()["assets"]) == 1
    assert "url" not in first.text
    assert media_client.provider.video_poll_calls == ["video-1"]


def test_video_poll_never_follows_a_rotated_provider_credential(media_client) -> None:
    media_client.provider.video_create_status = "queued"
    media_client.provider.name = "provider-a"
    media_client.client.app.state.router = _Router(
        media_client.provider,
        independence_domain="a" * 64,
        credential_domain="1" * 64,
    )
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-72727272-1111-4727-8727-727272727272",
        },
        json={"model": "paid-model", "prompt": "freeze provider credential"},
    )
    assert created.status_code == 200

    rotated = _FakeProvider()
    rotated.name = "provider-a"
    media_client.client.app.state.router = _Router(
        rotated,
        independence_domain="a" * 64,
        credential_domain="2" * 64,
    )
    response = media_client.client.get(
        f"/v1/videos/{created.json()['task_id']}",
        headers=AUTH,
        params={"model": "paid-model"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "video_route_changed"
    assert rotated.video_poll_calls == []


@pytest.mark.parametrize(
    "changed_url",
    [
        "https://paid-video.invalid/tenant-b/v1",
        "https://paid-video.invalid:8443/v1",
    ],
)
def test_video_poll_rejects_exact_route_path_or_port_change(
    media_client, changed_url
) -> None:
    media_client.provider.video_create_status = "queued"
    media_client.client.app.state.router = _Router(
        media_client.provider,
        independence_domain="a" * 64,
        credential_domain="e" * 64,
        base_url="https://paid-video.invalid/tenant-a/v1",
    )
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-route-path-1111-4111-8111-111111111111",
        },
        json={"model": "paid-model", "prompt": "freeze exact provider endpoint"},
    )
    assert created.status_code == 200

    changed = _FakeProvider()
    changed.name = media_client.provider.name
    media_client.client.app.state.router = _Router(
        changed,
        independence_domain="a" * 64,
        credential_domain="e" * 64,
        base_url=changed_url,
    )
    response = media_client.client.get(
        f"/v1/videos/{created.json()['task_id']}",
        headers=AUTH,
        params={"model": "paid-model"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "video_route_changed"
    assert changed.video_poll_calls == []


def test_video_poll_rejects_tenant_header_change_with_the_same_api_key(
    media_client,
) -> None:
    media_client.provider.video_create_status = "queued"
    media_client.client.app.state.router = _Router(
        media_client.provider,
        credential_domain=None,
        base_url="https://paid-video.invalid/v1",
    )
    media_client.provider._headers["X-Organization"] = "tenant-a"
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-route-tenant-1111-4111-8111-111111111111",
        },
        json={"model": "paid-model", "prompt": "freeze provider tenant"},
    )
    assert created.status_code == 200

    changed = _FakeProvider()
    changed.name = media_client.provider.name
    changed_router = _Router(
        changed,
        credential_domain=None,
        base_url="https://paid-video.invalid/v1",
    )
    changed._headers["X-Organization"] = "tenant-b"
    media_client.client.app.state.router = changed_router
    response = media_client.client.get(
        f"/v1/videos/{created.json()['task_id']}",
        headers=AUTH,
        params={"model": "paid-model"},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "video_route_changed"
    assert changed.video_poll_calls == []


def test_video_create_accepts_real_router_production_identity(
    media_client, monkeypatch
) -> None:
    provider_calls: list[str] = []

    async def local_video_result(_self, _request, upstream_model):
        provider_calls.append(upstream_model)
        return {
            "task_id": "production-shape-task",
            "status": "completed",
            "url": "https://media.invalid/production-shape.mp4",
        }

    monkeypatch.setattr(
        OpenAICompatProvider,
        "paid_media_video_asset_protocol_versions",
        frozenset({"2"}),
    )
    monkeypatch.setattr(OpenAICompatProvider, "generate_video", local_video_result)
    router = object.__new__(appmod.Router)
    router.settings = appmod.get_settings()
    router._catalog = {}
    router.store = None
    router._providers = {}
    router._routes = {}
    router._register_connection(
        "agnes-production-shape",
        {
            "type": "openai_compat",
            "api_key": "sk-production-shaped-test-only",
            "base_url": "https://apihub.agnes-ai.com/v1",
            "enabled_models": [
                {
                    "id": "paid-model",
                    "upstream_model": "agnes-video-upstream",
                    "tier": "premium",
                    "modality": "video",
                }
            ],
        },
    )
    route = router.resolve("paid-model")
    assert route is not None
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", route.independence_domain or "")
    media_client.client.app.state.router = router

    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-prod-domain-1111-4111-8111-111111111111",
        },
        json={"model": "paid-model", "prompt": "accept real router identity shape"},
    )

    assert response.status_code == 200
    assert provider_calls == ["agnes-video-upstream"]


def test_video_poll_canonicalizes_equivalent_endpoint_spellings(media_client) -> None:
    media_client.provider.video_create_status = "queued"
    media_client.client.app.state.router = _Router(
        media_client.provider,
        base_url="HTTPS://PAID-VIDEO.INVALID.:443/v1/",
    )
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-route-canon-1111-4111-8111-111111111111",
        },
        json={"model": "paid-model", "prompt": "canonical endpoint spelling"},
    )
    assert created.status_code == 200

    changed = _FakeProvider()
    changed.name = media_client.provider.name
    media_client.client.app.state.router = _Router(
        changed,
        base_url="https://paid-video.invalid/v1",
    )
    response = media_client.client.get(
        f"/v1/videos/{created.json()['task_id']}",
        headers=AUTH,
        params={"model": "paid-model"},
    )

    assert response.status_code == 200
    assert changed.video_poll_calls == ["video-1"]


def test_video_create_rejects_ambiguous_casefolded_scope_headers(media_client) -> None:
    media_client.client.app.state.router = _Router(
        media_client.provider,
        credential_domain=None,
    )
    media_client.provider._headers["authorization"] = "Bearer another-account"

    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-route-header-1111-4111-8111-111111111111",
        },
        json={"model": "paid-model", "prompt": "reject ambiguous headers"},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "video_route_identity_unavailable"
    assert media_client.provider.video_calls == 0


def test_video_capacity_is_rebuilt_from_durable_registry_after_process_restart(
    media_client,
) -> None:
    media_client.provider.video_create_status = "queued"
    first = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-73737373-1111-4737-8737-737373737373",
        },
        json={"model": "paid-model", "prompt": "survive gateway restart"},
    )
    assert first.status_code == 200
    assert media_client.provider.video_calls == 1

    restarted_pool = appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    monotonic = [10.0]
    restarted_pool._clock = lambda: monotonic[0]
    assert restarted_pool.counts()["active"] == 0
    reopened = DurableMediaRequestStore(media_client.store.path)
    original = media_client.client.app.state.media_requests
    media_client.client.app.state.media_requests = reopened
    try:
        blocked = media_client.client.post(
            "/v1/videos/generations",
            headers={
                **AUTH,
                "Idempotency-Key": "desktop-74747474-1111-4747-8747-747474747474",
            },
            json={"model": "paid-model", "prompt": "must remain capacity blocked"},
        )
        monotonic[0] += 301.0
        assert restarted_pool.counts()["active"] == 0
        blocked_after_ttl = media_client.client.post(
            "/v1/videos/generations",
            headers={
                **AUTH,
                "Idempotency-Key": "desktop-75757575-1111-4757-8757-757575757575",
            },
            json={"model": "paid-model", "prompt": "rebuild after memory lease ttl"},
        )
    finally:
        media_client.client.app.state.media_requests = original
        reopened.close()

    assert blocked.status_code == 429
    assert blocked_after_ttl.status_code == 429
    assert media_client.provider.video_calls == 1
    assert restarted_pool.counts() == {"active": 1, "capacity": 1}
    assert restarted_pool.release_external("video", first.json()["task_id"]) is True


def test_runtime_bearer_rotation_replays_in_same_paid_capability_domain(
    media_client, monkeypatch
) -> None:
    operation_key = "desktop-91919191-1111-4919-8919-919191919191"
    body = {"model": "paid-model", "prompt": "runtime rotation replay"}
    monkeypatch.setenv("GATEWAY_API_KEYS", "runtime-before-rotation")
    appmod.get_settings.cache_clear()
    first = media_client.client.post(
        "/v1/images/generations",
        headers={
            "Authorization": "Bearer runtime-before-rotation",
            "X-Nachuan-Paid-Media-Key": PAID_MEDIA_SECRET,
            "X-Nachuan-Paid-Media-Protocol": "2",
            "Idempotency-Key": operation_key,
        },
        json=body,
    )

    monkeypatch.setenv("GATEWAY_API_KEYS", "runtime-after-rotation")
    appmod.get_settings.cache_clear()
    replay = media_client.client.post(
        "/v1/images/generations",
        headers={
            "Authorization": "Bearer runtime-after-rotation",
            "X-Nachuan-Paid-Media-Key": PAID_MEDIA_SECRET,
            "X-Nachuan-Paid-Media-Protocol": "2",
            "Idempotency-Key": operation_key,
        },
        json=body,
    )

    assert first.status_code == replay.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert media_client.provider.image_calls == 1


def test_paid_capability_rotation_creates_a_distinct_recovery_domain(
    media_client, monkeypatch
) -> None:
    rotated_paid_secret = "sk-paid-media-" + ("b" * 64)
    operation_key = "desktop-92929292-2222-4929-8929-929292929292"
    body = {"model": "paid-model", "prompt": "paid authority rotation"}
    first = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": operation_key},
        json=body,
    )

    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", rotated_paid_secret)
    appmod.get_settings.cache_clear()
    rotated = media_client.client.post(
        "/v1/images/generations",
        headers={
            **_v2_headers(RUNTIME_AUTH),
            "X-Nachuan-Paid-Media-Key": rotated_paid_secret,
            "Idempotency-Key": operation_key,
        },
        json=body,
    )

    assert first.status_code == rotated.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert rotated.headers["Idempotency-Replayed"] == "false"
    assert rotated.json() != first.json()
    assert media_client.provider.image_calls == 2


def _bind_installation_authority(
    monkeypatch,
    control: _InstallationControl,
    *,
    principal: str = "c" * 64,
) -> _AssetInstallationControl:
    control.paid_principal = principal
    asset_control = _AssetInstallationControl()
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority_mode",
        "installation-root",
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_principal",
        principal,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        control,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        asset_control,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_installation_id",
        INSTALLATION_ID,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_epoch",
        INSTALLATION_EPOCH,
        raising=False,
    )
    return asset_control


def test_installation_principal_survives_paid_capability_rotation(
    media_client, monkeypatch
) -> None:
    control = _InstallationControl()
    _bind_installation_authority(monkeypatch, control)
    operation_key = "desktop-93939393-3333-4939-8939-939393939393"
    body = {"model": "paid-model", "prompt": "root principal rotation"}
    first = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": operation_key},
        json=body,
    )

    rotated_paid_secret = "sk-paid-media-" + ("b" * 64)
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", rotated_paid_secret)
    appmod.get_settings.cache_clear()
    replay = media_client.client.post(
        "/v1/images/generations",
        headers={
            **_v2_headers(RUNTIME_AUTH),
            "X-Nachuan-Paid-Media-Key": rotated_paid_secret,
            "Idempotency-Key": operation_key,
        },
        json=body,
    )

    assert first.status_code == replay.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert media_client.provider.image_calls == 1
    assert control.calls == 1


def test_root_outage_keeps_cached_replay_but_rejects_new_key_before_provider(
    media_client, monkeypatch
) -> None:
    control = _InstallationControl()
    _bind_installation_authority(monkeypatch, control)
    original_key = "desktop-94949494-4444-4949-8949-949494949494"
    body = {"model": "paid-model", "prompt": "root outage replay"}
    created = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": original_key},
        json=body,
    )
    assert created.status_code == 200

    control.fail = True

    def reject_mutation() -> None:
        raise DurableMediaRequestUnavailable("root mutation authority is fused")

    monkeypatch.setattr(media_client.store, "_pre_mutation_hook", reject_mutation)
    replay = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": original_key},
        json=body,
    )
    blocked = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-95959595-5555-4959-8959-959595959595",
        },
        json=body,
    )

    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert blocked.status_code == 503
    assert blocked.json()["detail"]["code"] == "media_idempotency_unavailable"
    assert media_client.provider.image_calls == 1
    assert control.calls == 1


def test_asset_manual_only_keeps_real_cached_replay_but_rejects_a_new_key(
    media_client, monkeypatch
) -> None:
    control = _InstallationControl()
    asset_control = _bind_installation_authority(monkeypatch, control)
    original_key = "desktop-asset-manual-4444-4444-8444-444444444444"
    body = {"model": "paid-model", "prompt": "asset manual replay"}
    created = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": original_key},
        json=body,
    )
    assert created.status_code == 200

    asset_control.mode = "manual_only"
    replay = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": original_key},
        json=body,
    )
    blocked = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-asset-manual-5555-4555-8555-555555555555",
        },
        json=body,
    )

    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == created.json()
    assert blocked.status_code == 503
    assert blocked.json()["detail"]["code"] == "paid_media_authority_unavailable"
    assert media_client.provider.image_calls == 1


def test_fresh_root_assert_is_adjacent_and_failure_never_calls_image_provider(
    media_client, monkeypatch
) -> None:
    events: list[str] = []
    control = _InstallationControl(events=events)
    _bind_installation_authority(monkeypatch, control)
    real_enter = media_client.store.enter_provider_phase
    real_generate = media_client.provider.generate_image_asset_urls

    def enter(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        events.append("enter")
        return real_enter(*args, **kwargs)

    async def generate(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        events.append("provider")
        return await real_generate(*args, **kwargs)

    monkeypatch.setattr(media_client.store, "enter_provider_phase", enter)
    monkeypatch.setattr(media_client.provider, "generate_image_asset_urls", generate)
    allowed = media_client.client.post(
        "/v1/images/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-96969696-6666-4969-8969-969696969696",
        },
        json={"model": "paid-model", "prompt": "fresh root order"},
    )
    assert allowed.status_code == 200
    assert events == ["enter", "assert", "provider"]

    control.fail = True
    events.clear()
    blocked_key = "desktop-97979797-7777-4979-8979-979797979797"
    blocked = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": blocked_key},
        json={"model": "paid-model", "prompt": "fresh root failure"},
    )
    repeated = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": blocked_key},
        json={"model": "paid-model", "prompt": "fresh root failure"},
    )

    assert blocked.status_code == 503
    assert blocked.json()["detail"]["code"] == "paid_media_authority_unavailable"
    assert repeated.status_code == 409
    assert repeated.json()["detail"]["code"] == "media_recovery_required"
    assert events == ["enter", "assert"]
    assert media_client.provider.image_calls == 1


def test_fresh_root_failure_blocks_video_create_provider(
    media_client, monkeypatch
) -> None:
    control = _InstallationControl(fail=True)
    _bind_installation_authority(monkeypatch, control)

    blocked = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-98989898-8888-4989-8989-989898989898",
        },
        json={"model": "paid-model", "prompt": "video root failure"},
    )

    assert blocked.status_code == 503
    assert blocked.json()["detail"]["code"] == "paid_media_authority_unavailable"
    assert media_client.provider.video_calls == 0
    assert control.calls == 1


def test_video_poll_reasserts_root_after_begin_poll_and_releases_fence(
    media_client, monkeypatch
) -> None:
    control = _InstallationControl()
    _bind_installation_authority(monkeypatch, control)
    media_client.provider.video_create_status = "queued"
    created = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-99989898-9999-4998-8998-999898989998",
        },
        json={"model": "paid-model", "prompt": "poll root race"},
    )
    assert created.status_code == 200
    task_alias = created.json()["task_id"]

    # Keep the store's policy clock fixed across the failed poll and immediate
    # replay.  Under a loaded suite, real wall time can cross the intentional
    # two-second provider backoff and turn the replay into a legitimate new
    # claim, which is a different behavior from the root-fence contract tested
    # here.  The store already exposes ``now`` specifically for this seam.
    policy_now = appmod.time.time()
    real_begin_video_poll = media_client.store.begin_video_poll
    real_fail_video_poll = media_client.store.fail_video_poll

    def begin_video_poll_at_policy_time(**kwargs):
        return real_begin_video_poll(now=policy_now, **kwargs)

    def fail_video_poll_at_policy_time(**kwargs):
        return real_fail_video_poll(now=policy_now, **kwargs)

    monkeypatch.setattr(
        media_client.store,
        "begin_video_poll",
        begin_video_poll_at_policy_time,
    )
    monkeypatch.setattr(
        media_client.store,
        "fail_video_poll",
        fail_video_poll_at_policy_time,
    )
    control.fail = True

    blocked = media_client.client.get(
        f"/v1/videos/{task_alias}",
        headers=AUTH,
        params={"model": "paid-model"},
    )
    repeated = media_client.client.get(
        f"/v1/videos/{task_alias}",
        headers=AUTH,
        params={"model": "paid-model"},
    )

    assert blocked.status_code == 503
    assert blocked.json()["detail"]["code"] == "paid_media_authority_unavailable"
    assert repeated.status_code == 200
    assert repeated.json()["status"] == "processing"
    assert media_client.provider.video_poll_calls == []
    assert control.calls == 2


def test_media_ledger_never_stores_raw_bearer_or_idempotency_key(media_client) -> None:
    raw_key = "desktop-99999999-3333-4999-8999-999999999999"
    response = media_client.client.post(
        "/v1/images/generations",
        headers={**AUTH, "Idempotency-Key": raw_key},
        json={"model": "paid-model", "prompt": "secret storage check"},
    )
    assert response.status_code == 200

    path = media_client.store.path
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            "SELECT principal_hash,key_hash,request_sha256 FROM durable_media_requests"
        ).fetchone()
    assert row is not None
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in row)
    assert "test-key" not in row
    assert PAID_MEDIA_SECRET not in row
    assert raw_key not in row
    media_client.store.close()
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if candidate.exists():
            payload = candidate.read_bytes()
            assert b"test-key" not in payload
            assert PAID_MEDIA_SECRET.encode("utf-8") not in payload
            assert raw_key.encode("utf-8") not in payload


def test_gateway_lifespan_creates_and_closes_paid_media_store(tmp_path, monkeypatch) -> None:
    created: list[DurableMediaRequestStore] = []

    def factory(_path) -> DurableMediaRequestStore:
        store = DurableMediaRequestStore(tmp_path / "lifespan-media.db")
        created.append(store)
        return store

    monkeypatch.setattr(appmod, "DurableMediaRequestStore", factory, raising=False)
    with TestClient(appmod.app):
        assert created
        assert appmod.app.state.media_requests is created[0]
        assert created[0]._keeper is not None
    assert created[0]._keeper is None


@pytest.mark.parametrize(
    "path",
    ["/v1/images/generations", "/v1/videos/generations"],
)
def test_unknown_model_never_leaves_a_durable_claim(media_client, path) -> None:
    response = media_client.client.post(
        path,
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-efefefef-6666-4fef-8fef-efefefefefef",
        },
        json={"model": "unknown-model", "prompt": "not submitted"},
    )
    assert response.status_code == 404
    assert "unknown-model" not in response.text
    assert response.json()["detail"] == {
        "code": "unknown_media_model",
        "message": "Requested paid media model is unavailable.",
        "retryable": False,
    }
    assert response.headers["Cache-Control"] == "no-store"
    with closing(sqlite3.connect(media_client.store.path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)


def test_video_pool_full_abandons_pre_provider_claim_for_same_key_retry(
    media_client,
) -> None:
    pool = appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    blocker = pool.try_acquire(kind="video")
    assert blocker is not None
    key = "desktop-fafafafa-7777-4afa-8afa-fafafafafafa"
    headers = {**AUTH, "Idempotency-Key": key}
    body = {"model": "paid-model", "prompt": "capacity retry"}

    blocked = media_client.client.post(
        "/v1/videos/generations", headers=headers, json=body
    )
    assert blocked.status_code == 429
    with closing(sqlite3.connect(media_client.store.path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)

    pool.release(blocker)
    retried = media_client.client.post(
        "/v1/videos/generations", headers=headers, json=body
    )
    assert retried.status_code == 200
    assert media_client.provider.video_calls == 1


def test_success_fence_loss_never_returns_unpersisted_paid_result(
    media_client, monkeypatch
) -> None:
    real_mark = media_client.store.mark_recovery_required
    monkeypatch.setattr(media_client.store, "succeed", lambda **_kwargs: False)
    key = "desktop-acacacac-8888-4cac-8cac-acacacacacac"
    headers = {**AUTH, "Idempotency-Key": key}
    body = {"model": "paid-model", "prompt": "lost success fence"}

    failed = media_client.client.post(
        "/v1/images/generations", headers=headers, json=body
    )
    monkeypatch.setattr(media_client.store, "mark_recovery_required", real_mark)
    repeated = media_client.client.post(
        "/v1/images/generations", headers=headers, json=body
    )

    assert failed.status_code == 503
    assert failed.headers["Cache-Control"] == "no-store"
    assert failed.json()["detail"]["code"] == "media_result_persistence_unavailable"
    assert failed.json()["detail"]["retryable"] is False
    assert repeated.status_code == 409
    assert media_client.provider.image_calls == 1


def test_video_success_persistence_failure_releases_terminal_capacity(
    media_client, monkeypatch
) -> None:
    pool = appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    monkeypatch.setattr(
        media_client.store,
        "succeed_video",
        lambda **_kwargs: (False, {}),
    )

    response = media_client.client.post(
        "/v1/videos/generations",
        headers={
            **AUTH,
            "Idempotency-Key": "desktop-dededede-bbbb-4ede-8ede-dededededede",
        },
        json={"model": "paid-model", "prompt": "terminal persistence failure"},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "media_result_persistence_unavailable"
    assert media_client.provider.video_calls == 1
    assert pool.counts()["active"] == 0
