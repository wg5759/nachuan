from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import gateway.app as appmod
from gateway.durable_media_requests import (
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    hash_media_request,
)
from gateway.paid_media_asset_protocol import ACK_SCHEMA
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
)
from gateway.public_media import PublicFetchSecurityError
from gateway.providers.base import ProviderError
from gateway.trusted_media_probe import TrustedMediaProbeResult


PRINCIPAL = "2" * 64
INSTALLATION_ID = "3" * 64


def test_terminal_video_asset_url_accepts_current_official_metadata_shape() -> None:
    url = (
        "https://platform-outputs.agnes-ai.space/videos/"
        "agnes-video-v2.0/task_official.mp4"
    )
    assert appmod._video_terminal_asset_url(
        {
            "status": "completed",
            "metadata": {
                "url": url,
                "size_mapping": {"resolution": "480p"},
            },
        }
    ) == url


@pytest.mark.parametrize("status_code", [408, 429, 500, 502, 503, 504])
def test_transient_video_poll_statuses_remain_retryable(status_code: int) -> None:
    assert appmod._media_provider_poll_retryable(status_code)


def _dependencies() -> PaidMediaAssetStoreDependencies:
    return PaidMediaAssetStoreDependencies(
        assert_acl=lambda path, directory: None,
        harden_acl=lambda path, directory: os.chmod(
            path, 0o700 if directory else 0o600
        ),
        disk_free=lambda _path: 16 * 1024 * 1024 * 1024,
    )


def _probe(
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
    return TrustedMediaProbeResult(
        media_type=expected_media_type,
        detected_kind="video",
        byte_length=expected_byte_length,
        sha256=expected_sha256,
        codec_name="h264",
        audio_codec_name=None,
        video_stream_count=1,
        audio_stream_count=0,
        format_name="mp4",
        width=16,
        height=16,
        duration_ms=1000,
        decoded_frames=1,
        ffmpeg_sha256="4" * 64,
        ffprobe_sha256="5" * 64,
    )


class _VideoProvider:
    name = "provider-a"
    base_url = "https://provider.invalid/v1"
    paid_video_route_domain = "c" * 64
    paid_video_credential_domain = "d" * 64
    paid_media_video_asset_protocol_versions = frozenset({"2"})

    async def generate_video(self, _request, _upstream):
        raise AssertionError("create provider must not run in poll test")

    async def get_video(self, _task_id):
        raise AssertionError("metered poll stub should replace provider method")


def _setup_processing_create(tmp_path: Path, monkeypatch):
    requests = DurableMediaRequestStore(tmp_path / "requests.db")
    assets = PaidMediaAssetStore.provision(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    claim = requests.claim(
        principal_hash=PRINCIPAL,
        operation="videos.create",
        idempotency_key="video-app-flow-11111111111111111111",
        request_sha256=hash_media_request(
            "videos.create", {"model": "video-model", "prompt": "flow"}
        ),
        now=1.0,
    )
    assert requests.reserve_asset_capacity(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=PRINCIPAL,
        operation="videos.create",
        installation_epoch=7,
    )
    assets.reserve(
        turn_id=claim.turn_id,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="videos.create",
    )
    assert requests.enter_provider_phase(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        max_success_bytes=1024 * 1024,
        now=2.0,
    )
    provider = _VideoProvider()
    route = SimpleNamespace(provider=provider, upstream_model="upstream-video")
    monkeypatch.setattr(
        appmod.app.state, "media_requests", requests, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_assets", assets, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state,
        "router",
        SimpleNamespace(resolve=lambda model: route if model == "video-model" else None),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_authority_mode", "development", raising=False
    )
    appmod.configure_background_job_pool(
        max_global=8, max_per_key=4, lease_ttl_seconds=300
    )
    return requests, assets, claim, route


def _setup_nonterminal(tmp_path: Path, monkeypatch):
    requests, assets, claim, _route = _setup_processing_create(
        tmp_path, monkeypatch
    )
    persisted, receipt = requests.succeed_video(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=PRINCIPAL,
        response={"task_id": "upstream-task", "status": "queued"},
        requested_model="video-model",
        provider_name="provider-a",
        provider_domain="c" * 64,
        provider_credential_domain="d" * 64,
        upstream_model="upstream-video",
        upstream_task_id="upstream-task",
        terminal=False,
        now=3.0,
    )
    assert persisted
    return requests, assets, claim, receipt


@pytest.mark.asyncio
async def test_video_poll_terminal_success_stages_private_bytes_then_commits_v2_slot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests, assets, claim, receipt = _setup_nonterminal(tmp_path, monkeypatch)
    payload = b"verified-private-video"

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        assert url == "https://media.invalid/final.mp4"
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    async def terminal_result(*_args, **_kwargs):
        return {
            "task_id": "upstream-task",
            "status": "completed",
            "url": "https://media.invalid/final.mp4",
        }

    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", terminal_result)
    try:
        response = await appmod._poll_paid_video_once(
            principal_hash=PRINCIPAL,
            task_id=str(receipt["task_id"]),
            model="video-model",
        )
        document = json.loads(response.body)
        assert response.headers["X-Nachuan-Paid-Media-Protocol"] == "2"
        assert document["schema"].endswith("result.v2")
        assert document["kind"] == "video"
        assert "url" not in response.body.decode("utf-8")
        assert requests.read_unacked_asset_success_document(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
        ).response == document
    finally:
        assets.close()
        requests.close()


@pytest.mark.asyncio
async def test_video_poll_media_binary_failure_releases_fence_and_recovers_without_repoll(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests, assets, claim, receipt = _setup_nonterminal(tmp_path, monkeypatch)
    payload = b"verified-after-media-binary-recovery"
    provider_calls = 0
    stage_calls = 0
    real_fail_video_poll = requests.fail_video_poll

    def release_before_current_time(**kwargs):
        return real_fail_video_poll(**kwargs, now=time.time() - 10.0)

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal stage_calls
        stage_calls += 1
        if stage_calls == 1:
            raise appmod.MediaBinaryUnavailable(
                "FFPROBE_BIN points at C:\\secret\\untrusted-ffprobe.exe"
            )
        assert url == "https://media.invalid/recoverable.mp4"
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    async def terminal_result(*_args, **_kwargs):
        nonlocal provider_calls
        provider_calls += 1
        if provider_calls != 1:
            raise AssertionError("prepared recovery must not poll the provider twice")
        return {
            "task_id": "upstream-task",
            "status": "completed",
            "url": "https://media.invalid/recoverable.mp4",
        }

    monkeypatch.setattr(requests, "fail_video_poll", release_before_current_time)
    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", terminal_result)
    try:
        with pytest.raises(appmod.HTTPException) as caught:
            await appmod._poll_paid_video_once(
                principal_hash=PRINCIPAL,
                task_id=str(receipt["task_id"]),
                model="video-model",
            )
        assert caught.value.status_code == 503
        assert caught.value.detail == {
            "code": "media_probe_unavailable",
            "message": (
                "Trusted media probe is unavailable; provider work will not be repeated."
            ),
            "retryable": True,
        }
        assert "secret" not in str(caught.value.detail)
        assert provider_calls == 1

        recovered = await appmod._poll_paid_video_once(
            principal_hash=PRINCIPAL,
            task_id=str(receipt["task_id"]),
            model="video-model",
        )
        document = json.loads(recovered.body)
        assert document["schema"].endswith("result.v2")
        assert document["kind"] == "video"
        assert document["turnId"] == claim.turn_id
        assert provider_calls == 1
        assert stage_calls == 2
    finally:
        assets.close()
        requests.close()


@pytest.mark.asyncio
async def test_video_poll_recovers_prepared_private_asset_after_publish_failure_and_restart(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests, assets, claim, receipt = _setup_nonterminal(tmp_path, monkeypatch)
    payload = b"restart-safe-private-video"
    provider_calls = 0
    download_calls = 0
    original_fail_video_poll = requests.fail_video_poll

    def release_before_current_time(**kwargs):
        return original_fail_video_poll(**kwargs, now=time.time() - 10.0)

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal download_calls
        download_calls += 1
        assert url == "https://media.invalid/restart-safe.mp4"
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    async def terminal_result(*_args, **_kwargs):
        nonlocal provider_calls
        provider_calls += 1
        if provider_calls != 1:
            raise AssertionError("prepared recovery must not poll the provider twice")
        return {
            "task_id": "upstream-task",
            "status": "completed",
            "metadata": {"url": "https://media.invalid/restart-safe.mp4"},
        }

    def fail_first_publish(**_kwargs):
        raise DurableMediaRequestUnavailable("injected durable publish failure")

    monkeypatch.setattr(requests, "fail_video_poll", release_before_current_time)
    monkeypatch.setattr(
        requests,
        "commit_prepared_video_poll_asset",
        fail_first_publish,
    )
    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", terminal_result)
    asset_identity = assets.inspect_root_state().database_identity
    try:
        with pytest.raises(appmod.HTTPException) as caught:
            await appmod._poll_paid_video_once(
                principal_hash=PRINCIPAL,
                task_id=str(receipt["task_id"]),
                model="video-model",
            )
        assert caught.value.status_code == 503
        assert provider_calls == 1
        assert download_calls == 1
    finally:
        assets.close()
        requests.close()

    restarted_requests = DurableMediaRequestStore(tmp_path / "requests.db")
    restarted_assets = PaidMediaAssetStore.open_bound(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=asset_identity,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )

    def forbidden_download(**_kwargs):
        raise AssertionError("prepared recovery must reuse the private asset")

    monkeypatch.setattr(
        restarted_assets,
        "stage_url",
        forbidden_download,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "media_requests",
        restarted_requests,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_assets",
        restarted_assets,
        raising=False,
    )
    try:
        response = await appmod._poll_paid_video_once(
            principal_hash=PRINCIPAL,
            task_id=str(receipt["task_id"]),
            model="video-model",
        )
        document = json.loads(response.body)
        assert document["schema"].endswith("result.v2")
        assert document["kind"] == "video"
        assert document["turnId"] == claim.turn_id
        assert provider_calls == 1
        assert download_calls == 1
        assert restarted_requests.read_unacked_asset_success_document(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
        ).response == document
        tokens = [str(asset["token"]) for asset in document["assets"]]
        archive_receipt_sha256 = "e" * 64
        durable_ack = restarted_requests.ack_asset_success(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
            installation_epoch=7,
            tokens=tokens,
            archive_receipt_sha256=archive_receipt_sha256,
        )
        cleanup = restarted_assets.ack(
            ack={
                "schema": ACK_SCHEMA,
                "turnId": claim.turn_id,
                "tokens": tokens,
                "archiveReceiptSha256": archive_receipt_sha256,
            },
            durable_result=document,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="videos.create",
            wait_timeout_seconds=0,
        )
        assert cleanup.cleanup_complete
        assert restarted_requests.complete_asset_ack_cleanup(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
            installation_epoch=7,
            token_set_digest=durable_ack.token_set_digest,
            archive_receipt_sha256=durable_ack.archive_receipt_sha256,
        )
        assert restarted_requests._keeper.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (0,)
        with sqlite3.connect(restarted_assets.database_path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM asset_store_meta"
            ).fetchone() == (0,)
    finally:
        restarted_assets.close()
        restarted_requests.close()


@pytest.mark.asyncio
async def test_immediate_terminal_create_recovers_without_second_provider_call_after_restart(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests, assets, claim, route = _setup_processing_create(
        tmp_path, monkeypatch
    )
    payload = b"immediate-terminal-private-video"
    create_calls = 1
    download_calls = 0
    provider_result = {
        "video_id": "upstream-immediate",
        "status": "completed",
        "metadata": {"url": "https://media.invalid/immediate.mp4"},
    }

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal download_calls
        download_calls += 1
        assert url == "https://media.invalid/immediate.mp4"
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    def fail_after_durable_create_receipt(**_kwargs):
        raise DurableMediaRequestUnavailable("injected crash before local asset work")

    monkeypatch.setattr(
        requests,
        "begin_video_poll",
        fail_after_durable_create_receipt,
    )
    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    asset_identity = assets.inspect_root_state().database_identity
    try:
        with pytest.raises(appmod.HTTPException) as caught:
            await appmod._persist_paid_video_success(
                claim=claim,
                principal_hash=PRINCIPAL,
                requested_model="video-model",
                route=route,
                provider_domain="c" * 64,
                provider_credential_domain="d" * 64,
                asset_store=assets,
                result=provider_result,
            )
        assert caught.value.status_code == 503
        replay = requests.claim(
            principal_hash=PRINCIPAL,
            operation="videos.create",
            idempotency_key="video-app-flow-11111111111111111111",
            request_sha256=hash_media_request(
                "videos.create", {"model": "video-model", "prompt": "flow"}
            ),
        )
        assert replay.state == "succeeded"
        assert replay.response == {
            "task_id": f"nvt1_{claim.turn_id}",
            "status": "processing",
        }
        assert create_calls == 1
        assert download_calls == 0
    finally:
        assets.close()
        requests.close()

    restarted_requests = DurableMediaRequestStore(tmp_path / "requests.db")
    restarted_assets = PaidMediaAssetStore.open_bound(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=asset_identity,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )

    async def forbidden_poll(*_args, **_kwargs):
        raise AssertionError("immediate prepared recovery must not poll Agnes")

    def recovery_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal download_calls
        download_calls += 1
        assert url == "https://media.invalid/immediate.mp4"
        return restarted_assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    monkeypatch.setattr(appmod, "get_video_with_accounting", forbidden_poll)
    monkeypatch.setattr(restarted_assets, "stage_url", recovery_stage_url)
    monkeypatch.setattr(
        appmod.app.state,
        "media_requests",
        restarted_requests,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_assets",
        restarted_assets,
        raising=False,
    )
    try:
        response = await appmod._poll_paid_video_once(
            principal_hash=PRINCIPAL,
            task_id=f"nvt1_{claim.turn_id}",
            model="video-model",
        )
        document = json.loads(response.body)
        assert document["schema"].endswith("result.v2")
        assert document["kind"] == "video"
        assert create_calls == 1
        assert download_calls == 1
    finally:
        restarted_assets.close()
        restarted_requests.close()


@pytest.mark.asyncio
async def test_video_poll_maps_public_asset_security_rejection_to_stable_502(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests, assets, _claim, receipt = _setup_nonterminal(tmp_path, monkeypatch)

    def rejected_stage_url(**_kwargs):
        raise PublicFetchSecurityError("private address must not leak")

    async def terminal_result(*_args, **_kwargs):
        return {
            "task_id": "upstream-task",
            "status": "completed",
            "url": "https://media.invalid/final.mp4",
        }

    monkeypatch.setattr(assets, "stage_url", rejected_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", terminal_result)
    try:
        with pytest.raises(appmod.HTTPException) as caught:
            await appmod._poll_paid_video_once(
                principal_hash=PRINCIPAL,
                task_id=str(receipt["task_id"]),
                model="video-model",
            )
        assert caught.value.status_code == 502
        assert caught.value.detail == {
            "code": "paid_video_asset_ingestion_failed",
            "message": (
                "Terminal video could not be committed as a verified private asset."
            ),
            "retryable": False,
        }
        assert "private address" not in str(caught.value.detail)
    finally:
        assets.close()
        requests.close()


@pytest.mark.parametrize("status_code", [400, 401, 404])
@pytest.mark.asyncio
async def test_video_poll_marks_permanent_provider_4xx_nonretryable(
    tmp_path: Path,
    monkeypatch,
    status_code: int,
) -> None:
    requests, assets, _claim, receipt = _setup_nonterminal(tmp_path, monkeypatch)

    async def permanent_provider_error(*_args, **_kwargs):
        raise ProviderError("provider detail must not leak", status_code=status_code)

    monkeypatch.setattr(
        appmod, "get_video_with_accounting", permanent_provider_error
    )
    try:
        with pytest.raises(appmod.HTTPException) as caught:
            await appmod._poll_paid_video_once(
                principal_hash=PRINCIPAL,
                task_id=str(receipt["task_id"]),
                model="video-model",
            )
        assert caught.value.status_code == status_code
        assert caught.value.detail == {
            "code": "video_provider_poll_error",
            "message": "Paid video provider poll failed.",
            "retryable": False,
        }
    finally:
        assets.close()
        requests.close()


@pytest.mark.asyncio
async def test_video_poll_terminal_failure_cleans_local_then_root_capacity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    requests, assets, _claim, receipt = _setup_nonterminal(tmp_path, monkeypatch)

    async def failed_result(*_args, **_kwargs):
        return {
            "task_id": "upstream-task",
            "status": "failed",
            "url": "https://media.invalid/untrusted-error.mp4",
        }

    monkeypatch.setattr(appmod, "get_video_with_accounting", failed_result)
    try:
        response = await appmod._poll_paid_video_once(
            principal_hash=PRINCIPAL,
            task_id=str(receipt["task_id"]),
            model="video-model",
        )
        assert json.loads(response.body) == {
            "task_id": receipt["task_id"],
            "status": "failed",
        }
        assert requests._keeper.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (0,)
        with sqlite3.connect(assets.database_path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM asset_store_meta"
            ).fetchone() == (0,)
    finally:
        assets.close()
        requests.close()
