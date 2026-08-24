from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

import gateway.app as appmod
import gateway.paid_media_operator_recovery as recoverymod
from gateway.durable_media_requests import (
    DurableMediaAssetConflict,
    DurableMediaRequestStore,
    hash_media_request,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
)
from gateway.paid_media_operator_receipts import PaidMediaOperatorReceiptStore
from gateway.paid_media_operator_recovery import (
    PaidMediaOperatorRecoveryError,
    PaidMediaOperatorRecoveryService,
)
from gateway.paid_media_web import PaidMediaWebLedger
from gateway.paid_media_web_archive import PaidMediaWebAssetArchive
from gateway.trusted_media_probe import TrustedMediaProbeResult


ORIGINAL_PRINCIPAL = "2" * 64
RECIPIENT_PRINCIPAL = "8" * 64
INSTALLATION_ID = "3" * 64


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


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(
        b"nachuan-paid-media-web-result-v1\x00" + payload
    ).hexdigest()


def _prepared_operation(tmp_path: Path):
    requests = DurableMediaRequestStore(tmp_path / "paid_media_requests.db")
    assets = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    web = PaidMediaWebLedger(tmp_path / "paid_media_web_operations.db")
    archive = PaidMediaWebAssetArchive(tmp_path / "paid-media-web-archive")

    request_payload = {
        "model": "agnes-video-v2.0",
        "prompt": "one existing prepared video",
    }
    request_sha256 = hash_media_request("videos.create", request_payload)
    consent = {
        "user_confirmed": True,
        "confirm_summary_sha256": "6" * 64,
        "confirmed_at_ms": 1_000,
        "request_sha256": request_sha256,
    }
    web_row = web.create_claim(
        principal_hash=ORIGINAL_PRINCIPAL,
        path="/v1/videos/generations",
        operation="videos.create",
        idempotency_key="operator-recovery-web-1111111111111111",
        request_sha256=request_sha256,
        request_body_json=json.dumps(
            request_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        consent_json=json.dumps(consent, sort_keys=True, separators=(",", ":")),
        now_ms=1_000,
    )
    assert (
        web.consume_cancel_or_dispatch(web_row["operation_id"], now_ms=1_001)
        == "dispatching"
    )

    claim = requests.claim(
        principal_hash=ORIGINAL_PRINCIPAL,
        operation="videos.create",
        idempotency_key=str(web_row["idempotency_key"]),
        request_sha256=request_sha256,
        now=1.0,
    )
    assert requests.reserve_asset_capacity(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=ORIGINAL_PRINCIPAL,
        operation="videos.create",
        installation_epoch=7,
    )
    assets.reserve(
        turn_id=claim.turn_id,
        principal_hash=ORIGINAL_PRINCIPAL,
        epoch=7,
        operation="videos.create",
    )
    assert requests.enter_provider_phase(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        max_success_bytes=1024 * 1024,
        now=2.0,
    )
    persisted, public_create = requests.succeed_video(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=ORIGINAL_PRINCIPAL,
        response={"video_id": "private-upstream-id", "status": "queued"},
        requested_model="agnes-video-v2.0",
        provider_name="agnes",
        provider_domain="a" * 64,
        provider_credential_domain="b" * 64,
        upstream_model="agnes-video-v2.0",
        upstream_task_id="private-upstream-id",
        terminal=False,
        now=3.0,
    )
    assert persisted

    public_result = {
        "task_id": public_create["task_id"],
        "status": "processing",
    }
    result_sha256 = _canonical_digest(public_result)
    initial_receipt = "7" * 64
    web.mark_result_ready(
        str(web_row["operation_id"]),
        last_status=200,
        result_json=json.dumps(public_result, sort_keys=True, separators=(",", ":")),
        asset_document_json=None,
        result_sha256=result_sha256,
        archive_receipt_sha256=initial_receipt,
        now_ms=1_002,
    )
    web.mark_delivered(
        str(web_row["operation_id"]),
        result_sha256=result_sha256,
        archive_receipt_sha256=initial_receipt,
        now_ms=1_003,
    )

    poll = requests.begin_video_poll(
        task_alias=str(public_create["task_id"]),
        principal_hash=ORIGINAL_PRINCIPAL,
        now=4.0,
    )
    assert poll.state == "claimed"
    prepared = requests.prepare_video_poll_asset(
        task_alias=str(public_create["task_id"]),
        principal_hash=ORIGINAL_PRINCIPAL,
        fencing_token=poll.fencing_token,
        provider_response={
            "video_id": "private-upstream-id",
            "status": "completed",
            "metadata": {"url": "https://media.invalid/existing-prepared.mp4"},
        },
        now=5.0,
    )
    assert prepared.token
    assert requests.fail_video_poll(
        task_alias=str(public_create["task_id"]),
        principal_hash=ORIGINAL_PRINCIPAL,
        fencing_token=poll.fencing_token,
        now=6.0,
    )

    return {
        "requests": requests,
        "assets": assets,
        "web": web,
        "archive": archive,
        "operation_id": str(web_row["operation_id"]),
    }


@pytest.mark.asyncio
async def test_operator_recovery_consumes_only_prepared_owner_without_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared_operation(tmp_path)
    requests = prepared["requests"]
    assets = prepared["assets"]
    web = prepared["web"]
    archive = prepared["archive"]
    payload = b"existing-prepared-video-bytes"
    provider_create_calls = 0
    provider_poll_calls = 0
    download_calls = 0

    async def forbidden_provider_poll(*_args, **_kwargs):
        nonlocal provider_poll_calls
        provider_poll_calls += 1
        raise AssertionError("operator recovery must never poll Agnes")

    async def forbidden_provider_create(*_args, **_kwargs):
        nonlocal provider_create_calls
        provider_create_calls += 1
        raise AssertionError("operator recovery must never create an Agnes task")

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal download_calls
        download_calls += 1
        assert url == "https://media.invalid/existing-prepared.mp4"
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    monkeypatch.setattr(appmod, "get_video_with_accounting", forbidden_provider_poll)
    monkeypatch.setattr(
        appmod, "generate_video_with_accounting", forbidden_provider_create
    )
    monkeypatch.setattr(assets, "stage_url", local_stage_url)

    receipts = PaidMediaOperatorReceiptStore(
        tmp_path / "paid_media_operator_recovery.db"
    )
    service = PaidMediaOperatorRecoveryService(
        web_ledger=web,
        media_requests=requests,
        asset_store=assets,
        web_archive=archive,
        receipt_store=receipts,
        installation_id=INSTALLATION_ID,
        installation_epoch=7,
        assert_local_owner=lambda: None,
    )
    try:
        inspection = service.inspect(
            operation_id=prepared["operation_id"],
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        public_inspection = inspection.public_document()
        encoded_inspection = json.dumps(public_inspection, sort_keys=True)
        assert public_inspection == {
            "schema": "nachuan.local-paid-media-operator-inspection.v1",
            "operationId": prepared["operation_id"],
            "decisionId": inspection.decision_id,
            "candidateSha256": inspection.candidate_sha256,
            "challenge": inspection.challenge,
            "state": "ready",
            "providerCallsAllowed": False,
        }
        assert "private-upstream-id" not in encoded_inspection
        assert "existing-prepared.mp4" not in encoded_inspection
        assert ORIGINAL_PRINCIPAL not in encoded_inspection
        assert prepared["operation_id"] in encoded_inspection

        with pytest.raises(
            PaidMediaOperatorRecoveryError,
            match="confirmation was rejected",
        ):
            await service.execute(
                operation_id=prepared["operation_id"],
                decision_id=inspection.decision_id,
                confirmation="RECOVER PREPARED 000000000000",
                recipient_principal_hash=RECIPIENT_PRINCIPAL,
            )
        assert download_calls == 0
        assert provider_create_calls == 0
        assert provider_poll_calls == 0

        completed = await service.execute(
            operation_id=prepared["operation_id"],
            decision_id=inspection.decision_id,
            confirmation=inspection.challenge,
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        public_receipt = completed.public_document()
        encoded_receipt = json.dumps(public_receipt, sort_keys=True)

        assert public_receipt["schema"] == (
            "nachuan.local-paid-media-operator-recovery-receipt.v1"
        )
        assert public_receipt["operationId"] == prepared["operation_id"]
        assert public_receipt["decisionId"] == inspection.decision_id
        assert public_receipt["state"] == "completed"
        assert public_receipt["providerCreateCalls"] == 0
        assert public_receipt["providerPollCalls"] == 0
        assert public_receipt["assetReference"].startswith(
            "nachuan-paid-media://sha256/"
        )
        assert "private-upstream-id" not in encoded_receipt
        assert "existing-prepared.mp4" not in encoded_receipt
        assert ORIGINAL_PRINCIPAL not in encoded_receipt
        assert RECIPIENT_PRINCIPAL not in encoded_receipt

        row = web.read_operation(prepared["operation_id"])
        assert row is not None
        assert row["state"] == "delivered"
        assert row["asset_document_json"] is not None
        terminal_result = json.loads(str(row["result_json"]))
        assert terminal_result["status"] == "completed"
        assert terminal_result["video_url"] == public_receipt["assetReference"]

        assert provider_create_calls == 0
        assert provider_poll_calls == 0
        assert requests._keeper.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (0,)
        with sqlite3.connect(assets.database_path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM asset_store_meta"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM paid_media_assets"
            ).fetchone() == (0,)
        assert archive.read(
            principal_hash=RECIPIENT_PRINCIPAL,
            asset_sha256=public_receipt["assetSha256"],
        ).payload == payload
        assert (
            archive.read(
                principal_hash=ORIGINAL_PRINCIPAL,
                asset_sha256=public_receipt["assetSha256"],
            )
            is None
        )

        replayed = await service.execute(
            operation_id=prepared["operation_id"],
            decision_id=inspection.decision_id,
            confirmation=inspection.challenge,
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        replay_document = replayed.public_document()
        assert replay_document == {
            **public_receipt,
            "replayed": True,
        }
        assert download_calls == 1
        assert provider_create_calls == 0
        assert provider_poll_calls == 0
    finally:
        archive.close()
        web.close()
        assets.close()
        requests.close()


@pytest.mark.asyncio
async def test_operator_recovery_resumes_after_local_commit_without_redownload_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared_operation(tmp_path)
    requests = prepared["requests"]
    assets = prepared["assets"]
    web = prepared["web"]
    archive = prepared["archive"]
    payload = b"crash-after-local-commit-video"
    download_calls = 0
    provider_calls = 0

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal download_calls
        download_calls += 1
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    async def forbidden_provider(*_args, **_kwargs):
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("operator crash recovery must never call Agnes")

    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", forbidden_provider)
    monkeypatch.setattr(appmod, "generate_video_with_accounting", forbidden_provider)
    receipts = PaidMediaOperatorReceiptStore(
        tmp_path / "paid_media_operator_recovery.db"
    )
    service = PaidMediaOperatorRecoveryService(
        web_ledger=web,
        media_requests=requests,
        asset_store=assets,
        web_archive=archive,
        receipt_store=receipts,
        installation_id=INSTALLATION_ID,
        installation_epoch=7,
        assert_local_owner=lambda: None,
    )
    original_archive = recoverymod.archive_paid_media_document_for_web
    archive_calls = 0

    async def crash_after_local_commit(*_args, **_kwargs):
        nonlocal archive_calls
        archive_calls += 1
        raise OSError("injected crash after local commit")

    try:
        inspection = service.inspect(
            operation_id=prepared["operation_id"],
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        monkeypatch.setattr(
            recoverymod,
            "archive_paid_media_document_for_web",
            crash_after_local_commit,
        )
        with pytest.raises(
            PaidMediaOperatorRecoveryError,
            match="could not be completed",
        ):
            await service.execute(
                operation_id=prepared["operation_id"],
                decision_id=inspection.decision_id,
                confirmation=inspection.challenge,
                recipient_principal_hash=RECIPIENT_PRINCIPAL,
            )
        assert archive_calls == 1
        assert download_calls == 1
        assert provider_calls == 0

        monkeypatch.setattr(
            recoverymod,
            "archive_paid_media_document_for_web",
            original_archive,
        )
        completed = await service.execute(
            operation_id=prepared["operation_id"],
            decision_id=inspection.decision_id,
            confirmation=inspection.challenge,
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        assert completed.public_document()["state"] == "completed"
        assert download_calls == 1
        assert provider_calls == 0
        assert requests._keeper.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (0,)
    finally:
        archive.close()
        web.close()
        assets.close()
        requests.close()


@pytest.mark.asyncio
async def test_operator_recovery_sanitizes_durable_asset_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared_operation(tmp_path)
    requests = prepared["requests"]
    assets = prepared["assets"]
    web = prepared["web"]
    archive = prepared["archive"]

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        assert url == "https://media.invalid/existing-prepared.mp4"
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(b"conflicting-authority-video").decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    async def conflicting_archive(*_args, **_kwargs):
        raise DurableMediaAssetConflict("injected durable authority conflict")

    async def forbidden_provider(*_args, **_kwargs):
        raise AssertionError("operator recovery must never call Agnes")

    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", forbidden_provider)
    monkeypatch.setattr(appmod, "generate_video_with_accounting", forbidden_provider)
    monkeypatch.setattr(
        recoverymod,
        "archive_paid_media_document_for_web",
        conflicting_archive,
    )
    receipts = PaidMediaOperatorReceiptStore(
        tmp_path / "paid_media_operator_recovery.db"
    )
    service = PaidMediaOperatorRecoveryService(
        web_ledger=web,
        media_requests=requests,
        asset_store=assets,
        web_archive=archive,
        receipt_store=receipts,
        installation_id=INSTALLATION_ID,
        installation_epoch=7,
        assert_local_owner=lambda: None,
    )
    try:
        inspection = service.inspect(
            operation_id=prepared["operation_id"],
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        with pytest.raises(
            PaidMediaOperatorRecoveryError,
            match="could not be completed",
        ):
            await service.execute(
                operation_id=prepared["operation_id"],
                decision_id=inspection.decision_id,
                confirmation=inspection.challenge,
                recipient_principal_hash=RECIPIENT_PRINCIPAL,
            )
    finally:
        archive.close()
        web.close()
        assets.close()
        requests.close()


@pytest.mark.asyncio
async def test_operator_recovery_resumes_after_web_transfer_before_receipt_without_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared_operation(tmp_path)
    requests = prepared["requests"]
    assets = prepared["assets"]
    web = prepared["web"]
    archive = prepared["archive"]
    payload = b"crash-after-web-transfer-video"
    download_calls = 0
    provider_calls = 0

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: str,
    ):
        nonlocal download_calls
        download_calls += 1
        return assets.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type="video/mp4",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    async def forbidden_provider(*_args, **_kwargs):
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("operator crash recovery must never call Agnes")

    monkeypatch.setattr(assets, "stage_url", local_stage_url)
    monkeypatch.setattr(appmod, "get_video_with_accounting", forbidden_provider)
    monkeypatch.setattr(appmod, "generate_video_with_accounting", forbidden_provider)
    receipts = PaidMediaOperatorReceiptStore(
        tmp_path / "paid_media_operator_recovery.db"
    )
    service = PaidMediaOperatorRecoveryService(
        web_ledger=web,
        media_requests=requests,
        asset_store=assets,
        web_archive=archive,
        receipt_store=receipts,
        installation_id=INSTALLATION_ID,
        installation_epoch=7,
        assert_local_owner=lambda: None,
    )
    original_complete = receipts.complete
    complete_calls = 0

    def crash_before_receipt(*args, **kwargs):
        nonlocal complete_calls
        complete_calls += 1
        if complete_calls == 1:
            raise OSError("injected crash before operator receipt")
        return original_complete(*args, **kwargs)

    try:
        inspection = service.inspect(
            operation_id=prepared["operation_id"],
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        initial_row = web.read_operation(prepared["operation_id"])
        assert initial_row is not None
        initial_processing_sha256 = str(initial_row["result_sha256"])
        monkeypatch.setattr(receipts, "complete", crash_before_receipt)
        with pytest.raises(
            PaidMediaOperatorRecoveryError,
            match="could not be completed",
        ):
            await service.execute(
                operation_id=prepared["operation_id"],
                decision_id=inspection.decision_id,
                confirmation=inspection.challenge,
                recipient_principal_hash=RECIPIENT_PRINCIPAL,
            )
        transferred = web.read_operation(prepared["operation_id"])
        assert transferred is not None
        assert transferred["principal_hash"] == RECIPIENT_PRINCIPAL
        assert json.loads(str(transferred["result_json"]))["status"] == "completed"
        assert receipts.read_decision(prepared["operation_id"]).state == "executing"
        assert receipts.read_completed(prepared["operation_id"]) is None
        assert download_calls == 1
        assert provider_calls == 0

        transferred_result = json.loads(str(transferred["result_json"]))
        transferred_asset = json.loads(str(transferred["asset_document_json"]))
        transferred_audit = json.loads(str(transferred["reconcile_json"]))
        exact_web_replay = web.complete_prepared_operator_recovery(
            prepared["operation_id"],
            source_principal_hash=ORIGINAL_PRINCIPAL,
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
            expected_request_sha256=str(transferred["request_sha256"]),
            expected_consent_sha256=hashlib.sha256(
                str(transferred["consent_json"]).encode("utf-8")
            ).hexdigest(),
            expected_processing_result_sha256=initial_processing_sha256,
            renderer_result=transferred_result,
            asset_document=transferred_asset,
            archive_receipt_sha256=str(
                transferred["archive_receipt_sha256"]
            ),
            decision_id=inspection.decision_id,
            candidate_sha256=inspection.candidate_sha256,
            ack_receipt_sha256=str(
                transferred_audit["ackReceiptSha256"]
            ),
            now_ms=9_000,
        )
        assert exact_web_replay["principal_hash"] == RECIPIENT_PRINCIPAL
        assert exact_web_replay["reconcile_json"] == transferred["reconcile_json"]

        completed = await service.execute(
            operation_id=prepared["operation_id"],
            decision_id=inspection.decision_id,
            confirmation=inspection.challenge,
            recipient_principal_hash=RECIPIENT_PRINCIPAL,
        )
        assert completed.public_document()["state"] == "completed"
        assert completed.public_document()["replayed"] is True
        assert complete_calls == 2
        assert download_calls == 1
        assert provider_calls == 0
        assert receipts.read_completed(prepared["operation_id"]) is not None
    finally:
        archive.close()
        web.close()
        assets.close()
        requests.close()
