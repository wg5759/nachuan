"""ADR-0013 web paid-media confirmation chain routes (/v1/paid-media/web/*).

The pure-web frontend (desktop/src/web-shim) drives the complete paid-media
operation lifecycle through these routes.  The browser never holds the paid
capability key: the gateway attaches it server-side, while write verbs are
gated by the independent approval trust domain plus durable user consent.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import os
import re
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

import gateway.app as appmod
import gateway.paid_media_web as paidwebmod
from gateway.durable_media_requests import (
    DurableMediaAssetConflict,
    DurableMediaRequestUnavailable,
    DurableMediaRequestStore,
    hash_media_principal,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
)
from gateway.paid_media_asset_protocol import parse_asset_result
from gateway.paid_media_web import PaidMediaWebLedger, PaidMediaWebLedgerUnavailable
from gateway.paid_media_web_archive import (
    PaidMediaWebArchiveUnavailable,
    PaidMediaWebAssetArchive,
    paid_media_web_archive_receipt_sha256,
)
from gateway.providers.base import ProviderError
from gateway.trusted_media_probe import TrustedMediaProbeResult


PAID_MEDIA_SECRET = "sk-paid-media-" + ("a" * 64)
APPROVAL_SECRET = "sk-approval-test-" + ("a" * 64)
RUNTIME_AUTH = {"Authorization": "Bearer test-key"}
WEB_AUTH = {**RUNTIME_AUTH, "X-Nachuan-Approval-Key": APPROVAL_SECRET}
PAID_ASSET_AUTH = {
    **RUNTIME_AUTH,
    "X-Nachuan-Paid-Media-Key": PAID_MEDIA_SECRET,
    "X-Nachuan-Paid-Media-Protocol": "2",
    "Accept-Encoding": "identity",
}
INSTALLATION_ID = "d" * 64
INSTALLATION_EPOCH = 7
OPERATION_ID_RE = re.compile(r"^desktop-op-[0-9a-f-]{36}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ASSET_REF_RE = re.compile(r"^nachuan-paid-media://sha256/[0-9a-f]{64}$")
VIDEO_ALIAS_RE = re.compile(r"^nvt1_[0-9a-f]{64}$")

IMAGE_PATH = "/v1/images/generations"
VIDEO_PATH = "/v1/videos/generations"
WEB_PREFIX = "/v1/paid-media/web"


def _expected_web_archive_receipt(asset_document: object) -> str:
    return paid_media_web_archive_receipt_sha256(
        principal_hash=hash_media_principal(PAID_MEDIA_SECRET),
        result=parse_asset_result(asset_document),
        installation_id=INSTALLATION_ID,
        installation_epoch=INSTALLATION_EPOCH,
    )


def _confirm_digest(path: str, encoded_body: str) -> str:
    body_digest = hashlib.sha256(encoded_body.encode("utf-8")).hexdigest()
    return hashlib.sha256(
        b"nachuan-paid-media-web-confirm-v1\x00"
        + path.encode("utf-8")
        + b"\x00"
        + body_digest.encode("ascii")
    ).hexdigest()


def _claim_body(
    *,
    path: str = IMAGE_PATH,
    payload: dict | None = None,
) -> dict:
    encoded = json.dumps(payload if payload is not None else {"model": "paid-model", "prompt": "draw"})
    return {
        "path": path,
        "encodedBody": encoded,
        "user_confirmed": True,
        "confirm_summary_sha256": _confirm_digest(path, encoded),
    }


def _assert_public_operation(
    operation: dict, *, path: str, state: str, dispatch_count: int
) -> None:
    assert OPERATION_ID_RE.fullmatch(operation["operationId"])
    assert operation["path"] == path
    assert operation["state"] == state
    assert isinstance(operation["createdAt"], int) and operation["createdAt"] > 0
    assert isinstance(operation["updatedAt"], int)
    assert operation["updatedAt"] >= operation["createdAt"]
    assert operation["dispatchCount"] == dispatch_count


class _FakeProvider:
    name = "paid-media-web-fake"
    paid_media_asset_protocol_versions = frozenset({"2"})
    paid_media_video_asset_protocol_versions = frozenset({"2"})

    def __init__(self) -> None:
        self.image_calls = 0
        self.video_calls = 0
        self.video_poll_calls: list[str] = []
        self.fail_image = False
        self.video_create_status = "processing"
        self.assets_by_url: dict[str, tuple[bytes, str]] = {}

    def register_asset(self, url: str, payload: bytes, media_type: str) -> None:
        self.assets_by_url[url] = (payload, media_type)

    async def generate_image_asset_urls(self, _request, _upstream_model):
        self.image_calls += 1
        if self.fail_image:
            raise ProviderError("provider outcome unavailable", status_code=502)
        url = f"https://media.invalid/image-{self.image_calls}.png"
        self.register_asset(
            url, f"private-image-{self.image_calls}".encode(), "image/png"
        )
        return {"data": [{"url": url}]}

    async def generate_video(self, _request, _upstream_model):
        self.video_calls += 1
        result: dict[str, object] = {
            "task_id": f"video-{self.video_calls}",
            "status": self.video_create_status,
        }
        if self.video_create_status == "completed":
            url = f"https://media.invalid/video-{self.video_calls}.mp4"
            self.register_asset(
                url, f"private-video-{self.video_calls}".encode(), "video/mp4"
            )
            result["url"] = url
        return result

    async def get_video(self, task_id: str):
        self.video_poll_calls.append(task_id)
        url = f"https://media.invalid/{self.name}/{task_id}.mp4"
        self.register_asset(url, f"private-video-poll-{task_id}".encode(), "video/mp4")
        return {"task_id": task_id, "status": "completed", "url": url}


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
    def __init__(self, provider: _FakeProvider) -> None:
        provider.base_url = "https://paid-video.invalid/v1"
        provider._headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer paid-video-test-token",
        }
        provider.paid_video_credential_domain = "e" * 64
        self.route = SimpleNamespace(
            provider=provider,
            upstream_model="paid-upstream",
            tier="premium",
            independence_domain="a" * 64,
        )

    def resolve(self, model: str):  # noqa: ANN201
        return self.route if model == "paid-model" else None

    async def aclose(self) -> None:
        return None


@pytest.fixture
def web_client(tmp_path, monkeypatch, request):
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", PAID_MEDIA_SECRET)
    monkeypatch.setenv("APPROVAL_ADMIN_KEY", APPROVAL_SECRET)
    appmod.get_settings.cache_clear()
    store = DurableMediaRequestStore(tmp_path / "paid-media-requests.db")
    max_capacity_bytes = getattr(
        request, "param", 16 * OPERATION_RESERVATION_BYTES
    )
    asset_store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=INSTALLATION_EPOCH,
        max_capacity_bytes=max_capacity_bytes,
        dependencies=_asset_store_dependencies(),
    )
    ledger = PaidMediaWebLedger(tmp_path / "paid-media-web-operations.db")
    web_archive = PaidMediaWebAssetArchive(tmp_path / "paid-media-web-archive")
    provider = _FakeProvider()
    readiness_calls: list[str] = []

    async def trusted_media_ready():
        readiness_calls.append("ready")
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
        trusted_media_ready,
    )
    client = TestClient(appmod.app, raise_server_exceptions=False)
    client.app.state.router = _Router(provider)
    client.app.state.media_requests = store
    client.app.state.paid_media_assets = asset_store
    client.app.state.paid_media_epoch = INSTALLATION_EPOCH
    client.app.state.paid_media_authority_mode = "development"
    client.app.state.paid_media_principal = hash_media_principal(PAID_MEDIA_SECRET)
    client.app.state.installation_root_control = None
    client.app.state.paid_media_web_ledger = ledger
    client.app.state.paid_media_web_archive = web_archive
    client.app.state.paid_media_installation_id = INSTALLATION_ID
    client.app.state.usage = SimpleNamespace(log=lambda **_kwargs: None)

    def local_stage_url(
        *,
        turn_id: str,
        ordinal: int,
        url: str,
        prepared_token: object | None = None,
    ):
        payload, media_type = provider.assets_by_url.get(
            url,
            (
                f"private-provider-asset:{url}".encode(),
                "video/mp4" if url.lower().endswith(".mp4") else "image/png",
            ),
        )
        return asset_store.stage_base64_chunks(
            turn_id=turn_id,
            ordinal=ordinal,
            media_type=media_type,
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_asset_probe,
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
            asset_store=asset_store,
            ledger=ledger,
            web_archive=web_archive,
            readiness_calls=readiness_calls,
        )
    finally:
        client.close()
        web_archive.close()
        ledger.close()
        asset_store.close()
        store.close()
        appmod.get_settings.cache_clear()


def _claim(web_client, **overrides) -> dict:
    body = _claim_body(**overrides)
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )
    assert response.status_code == 200, response.text
    return response.json()


def _execute(web_client, operation: dict, *, body: dict | None = None) -> dict:
    claim_body = _claim_body() if body is None else body
    response = web_client.client.post(
        f"{WEB_PREFIX}/execute",
        headers=WEB_AUTH,
        json={
            "operationId": operation["operationId"],
            "path": operation["path"],
            "encodedBody": claim_body["encodedBody"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _execute_image_ok(web_client) -> tuple[dict, dict]:
    operation = _claim(web_client)
    result = _execute(web_client, operation)
    assert result["ok"] is True, result
    return operation, result


def test_web_ledger_migrates_the_exact_v1_schema_before_serving_assets(tmp_path) -> None:
    path = tmp_path / "paid-media-web-v1.db"
    with sqlite3.connect(path) as connection:
        connection.execute(paidwebmod._META_V1_DDL)
        connection.execute(paidwebmod._TABLE_DDL)
        connection.execute(
            "INSERT INTO paid_media_web_operations_meta VALUES(1,1,?)",
            (paidwebmod._SCHEMA_V1_FINGERPRINT,),
        )
        connection.execute(f"PRAGMA application_id={paidwebmod._APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")

    ledger = PaidMediaWebLedger(path)
    ledger.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT schema_version,schema_fingerprint "
            "FROM paid_media_web_operations_meta WHERE singleton=1"
        ).fetchone() == (2, paidwebmod._SCHEMA_FINGERPRINT)
        assert connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='paid_media_web_asset_references'"
        ).fetchone() == ("paid_media_web_asset_references",)


def test_web_ledger_concurrent_v1_initializers_both_converge(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "paid-media-web-v1-race.db"
    with sqlite3.connect(path) as connection:
        connection.execute(paidwebmod._META_V1_DDL)
        connection.execute(paidwebmod._TABLE_DDL)
        connection.execute(
            "INSERT INTO paid_media_web_operations_meta VALUES(1,1,?)",
            (paidwebmod._SCHEMA_V1_FINGERPRINT,),
        )
        connection.execute(f"PRAGMA application_id={paidwebmod._APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")

    original_connect = sqlite3.connect
    pre_migration_barrier = threading.Barrier(2)

    class BarrierConnection(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):  # noqa: ANN001, ANN201
            cursor = super().execute(sql, parameters)
            if "SELECT schema_version,schema_fingerprint" in " ".join(sql.split()):
                try:
                    pre_migration_barrier.wait(timeout=2.0)
                except threading.BrokenBarrierError:
                    pass
            return cursor

    def barrier_connect(*args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        kwargs["factory"] = BarrierConnection
        return original_connect(*args, **kwargs)

    monkeypatch.setattr(paidwebmod.sqlite3, "connect", barrier_connect)
    errors: list[BaseException] = []

    def initialize() -> None:
        try:
            PaidMediaWebLedger(path).close()
        except BaseException as exc:  # preserve the exact competing failure
            errors.append(exc)

    threads = [threading.Thread(target=initialize) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20.0)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    with original_connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT schema_version,schema_fingerprint "
            "FROM paid_media_web_operations_meta WHERE singleton=1"
        ).fetchone() == (2, paidwebmod._SCHEMA_FINGERPRINT)


def test_web_ledger_rejects_v1_schema_with_drifted_ddl(tmp_path) -> None:
    path = tmp_path / "paid-media-web-v1-drift.db"
    drifted_operations_ddl = paidwebmod._TABLE_DDL.replace(
        ") WITHOUT ROWID", ")", 1
    )
    assert drifted_operations_ddl != paidwebmod._TABLE_DDL
    with sqlite3.connect(path) as connection:
        connection.execute(paidwebmod._META_V1_DDL)
        connection.execute(drifted_operations_ddl)
        connection.execute(
            "INSERT INTO paid_media_web_operations_meta VALUES(1,1,?)",
            (paidwebmod._SCHEMA_V1_FINGERPRINT,),
        )
        connection.execute(f"PRAGMA application_id={paidwebmod._APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")

    with pytest.raises(PaidMediaWebLedgerUnavailable):
        PaidMediaWebLedger(path)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='paid_media_web_asset_references'"
        ).fetchone() is None


def test_web_ledger_rejects_v2_schema_with_drifted_ddl(tmp_path) -> None:
    path = tmp_path / "paid-media-web-v2-drift.db"
    PaidMediaWebLedger(path).close()
    drifted_index_ddl = paidwebmod._ASSET_INDEX_DDL.replace(
        ") WITHOUT ROWID", ")", 1
    )
    assert drifted_index_ddl != paidwebmod._ASSET_INDEX_DDL
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE paid_media_web_asset_references")
        connection.execute(drifted_index_ddl)

    with pytest.raises(PaidMediaWebLedgerUnavailable):
        PaidMediaWebLedger(path)


def test_web_ledger_v1_migration_backfills_existing_asset_documents(tmp_path) -> None:
    path = tmp_path / "paid-media-web-v1-assets.db"
    principal = "4" * 64
    digest = "2" * 64
    token = "nma1_" + "A" * 43
    asset_document = {
        "schema": "nachuan.paid-media-result.v2",
        "kind": "image",
        "created": 1,
        "turnId": "1" * 64,
        "assets": [
            {
                "token": token,
                "mediaType": "image/png",
                "byteLength": 3,
                "sha256": digest,
                "validationReceiptSha256": "3" * 64,
            }
        ],
    }
    with sqlite3.connect(path) as connection:
        connection.execute(paidwebmod._META_V1_DDL)
        connection.execute(paidwebmod._TABLE_DDL)
        connection.execute(
            "INSERT INTO paid_media_web_operations_meta VALUES(1,1,?)",
            (paidwebmod._SCHEMA_V1_FINGERPRINT,),
        )
        connection.execute(
            "INSERT INTO paid_media_web_operations "
            "(operation_id,principal_hash,path,operation,idempotency_key,"
            "request_sha256,request_body_json,consent_json,state,dispatch_count,"
            "last_status,result_json,asset_document_json,result_sha256,"
            "archive_receipt_sha256,archived_at_ms,created_at_ms,updated_at_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,1,200,?,?,?,?,1,1,1)",
            (
                "desktop-op-00000000-0000-4000-8000-000000000000",
                principal,
                IMAGE_PATH,
                "images.create",
                "webop-" + "5" * 24,
                "6" * 64,
                "{}",
                "{}",
                "result_ready",
                "{}",
                json.dumps(asset_document, sort_keys=True, separators=(",", ":")),
                "7" * 64,
                "8" * 64,
            ),
        )
        connection.execute(f"PRAGMA application_id={paidwebmod._APPLICATION_ID}")
        connection.execute("PRAGMA user_version=1")

    ledger = PaidMediaWebLedger(path)
    try:
        assert ledger.find_asset_token(principal, digest) == token
    finally:
        ledger.close()


def test_read_asset_keeps_the_raw_capability_server_side_and_survives_web_ack(
    web_client,
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    assert ASSET_REF_RE.fullmatch(reference)
    assert "nma1_" not in json.dumps(result)

    missing_runtime = web_client.client.post(
        f"{WEB_PREFIX}/read-asset", json={"reference": reference}
    )
    assert missing_runtime.status_code == 401

    def read() -> object:
        return web_client.client.post(
            f"{WEB_PREFIX}/read-asset",
            headers=RUNTIME_AUTH,
            json={"reference": reference},
        )

    first = read()
    assert first.status_code == 200, first.text
    assert first.content == b"private-image-1"
    assert first.headers["content-type"] == "image/png"
    assert first.headers["content-length"] == str(len(first.content))
    assert first.headers["x-content-sha256"] == reference.rsplit("/", 1)[-1]
    assert first.headers["cache-control"] == "no-store"
    assert first.headers["x-content-type-options"] == "nosniff"
    assert "accept-ranges" not in first.headers

    acknowledged = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=result["deliveryProof"],
    )
    assert acknowledged.status_code == 200, acknowledged.text
    web_client.client.app.state.media_requests = None
    web_client.client.app.state.paid_media_assets = None
    second = read()
    assert second.status_code == 200, second.text
    assert second.content == first.content


def test_verified_historical_archive_survives_absent_live_ack_authority(
    web_client,
    monkeypatch,
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]

    first = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )
    assert first.status_code == 200, first.text

    def no_live_authority(**_kwargs):
        raise DurableMediaAssetConflict(
            "injected archive-only historical principal"
        )

    monkeypatch.setattr(
        web_client.store,
        "ack_asset_success",
        no_live_authority,
    )
    historical = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )

    assert historical.status_code == 200, historical.text
    assert historical.content == first.content
    assert historical.headers["x-content-sha256"] == reference.rsplit("/", 1)[-1]


def test_first_materialization_maps_live_ack_conflict_to_stable_503(
    web_client,
    monkeypatch,
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]

    def conflicting_live_authority(**_kwargs):
        raise DurableMediaAssetConflict(
            "injected first-materialization authority conflict"
        )

    monkeypatch.setattr(
        web_client.store,
        "ack_asset_success",
        conflicting_live_authority,
    )
    interrupted = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )

    assert interrupted.status_code == 503, interrupted.text
    assert interrupted.json()["detail"] == {
        "code": "paid_media_web_asset_authority_unavailable",
        "message": "Paid media asset authority could not be verified.",
        "retryable": False,
    }


@pytest.mark.parametrize(
    "web_client", [OPERATION_RESERVATION_BYTES], indirect=True
)
def test_web_materialization_archives_then_releases_capacity_for_the_next_operation(
    web_client,
) -> None:
    _first_operation, first = _execute_image_ok(web_client)
    first_reference = first["result"]["data"][0]["url"]

    materialized = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": first_reference},
    )
    assert materialized.status_code == 200, materialized.text
    assert materialized.content == b"private-image-1"

    acknowledged = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=first["deliveryProof"],
    )
    assert acknowledged.status_code == 200, acknowledged.text

    _second_operation, second = _execute_image_ok(web_client)
    assert second["result"]["data"][0]["url"] != first_reference

    historical = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": first_reference},
    )
    assert historical.status_code == 200, historical.text
    assert historical.content == b"private-image-1"


def test_wrong_delivery_proof_has_no_archive_or_underlying_ack_side_effect(
    web_client,
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    digest = reference.rsplit("/", 1)[-1]
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    bad_proof = {**result["deliveryProof"], "resultSha256": "f" * 64}

    rejected = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=bad_proof,
    )

    assert rejected.status_code == 409, rejected.text
    assert web_client.web_archive.read(
        principal_hash=principal, asset_sha256=digest
    ) is None
    document = web_client.ledger.find_asset_document(principal, digest)
    assert document is not None
    assert web_client.store.read_unacked_asset_success_document(
        turn_id=document["turnId"],
        principal_hash=principal,
        operation="images.create",
    ) is not None


@pytest.mark.parametrize(
    "web_client", [OPERATION_RESERVATION_BYTES], indirect=True
)
def test_ack_retry_converges_after_archive_commit_precedes_durable_ack(
    web_client, monkeypatch
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    original_ack = web_client.store.ack_asset_success

    def fail_after_archive_commit(**_kwargs):
        raise DurableMediaRequestUnavailable("injected post-archive ACK failure")

    monkeypatch.setattr(web_client.store, "ack_asset_success", fail_after_archive_commit)
    interrupted = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )
    assert interrupted.status_code == 503, interrupted.text
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    archived = web_client.web_archive.read(
        principal_hash=principal,
        asset_sha256=reference.rsplit("/", 1)[-1],
    )
    assert archived is not None
    assert archived.payload == b"private-image-1"

    monkeypatch.setattr(web_client.store, "ack_asset_success", original_ack)
    acknowledged = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=result["deliveryProof"],
    )
    assert acknowledged.status_code == 200, acknowledged.text
    _next_operation, next_result = _execute_image_ok(web_client)
    assert next_result["ok"] is True


@pytest.mark.asyncio
async def test_concurrent_first_reads_share_one_archive_transition(
    web_client, monkeypatch
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    original_transition = paidwebmod.archive_paid_media_document_for_web
    transition_calls = 0

    async def counted_transition(*args, **kwargs):
        nonlocal transition_calls
        transition_calls += 1
        return await original_transition(*args, **kwargs)

    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", counted_transition
    )
    transport = httpx.ASGITransport(
        app=web_client.client.app, raise_app_exceptions=False
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        responses = await asyncio.gather(
            *(
                client.post(
                    f"{WEB_PREFIX}/read-asset",
                    headers=RUNTIME_AUTH,
                    json={"reference": reference},
                )
                for _ in range(2)
            )
        )

    assert [response.status_code for response in responses] == [200, 200]
    assert [response.content for response in responses] == [
        b"private-image-1",
        b"private-image-1",
    ]
    assert transition_calls == 1


@pytest.mark.asyncio
async def test_cancelled_read_callers_keep_materialization_capacity_until_flights_finish(
    web_client, monkeypatch
) -> None:
    documents = []
    for ordinal in range(3):
        operation, result = _execute_image_ok(web_client)
        row = web_client.ledger.get_for_principal(
            operation["operationId"], hash_media_principal(PAID_MEDIA_SECRET)
        )
        assert row is not None and row["asset_document_json"]
        documents.append(json.loads(row["asset_document_json"]))
        if ordinal < 2:
            proof = result["deliveryProof"]
            web_client.ledger.mark_delivered(
                operation["operationId"],
                result_sha256=proof["resultSha256"],
                archive_receipt_sha256=proof["archiveReceiptSha256"],
                now_ms=paidwebmod._now_ms(),
            )
    release_transitions = asyncio.Event()
    two_transitions_entered = asyncio.Event()
    started_turns: list[str] = []

    async def blocked_transition(*args, **kwargs):
        asset_document = kwargs["asset_document"]
        started_turns.append(asset_document["turnId"])
        if len(started_turns) == 2:
            two_transitions_entered.set()
        await release_transitions.wait()
        return _expected_web_archive_receipt(asset_document)

    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", blocked_transition
    )
    request = SimpleNamespace(app=web_client.client.app)
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    # Two callers for one turn must share one flight; the other turn consumes
    # the second process permit.
    cancelled_callers = [
        asyncio.create_task(
            paidwebmod._ensure_web_asset_archive(
                request,
                principal_hash=principal,
                asset_document=document,
            )
        )
        for document in (documents[0], documents[0], documents[1])
    ]
    await asyncio.wait_for(two_transitions_entered.wait(), timeout=10)
    assert started_turns.count(documents[0]["turnId"]) == 1
    assert started_turns.count(documents[1]["turnId"]) == 1
    for caller in cancelled_callers:
        caller.cancel()
    cancelled_results = await asyncio.gather(
        *cancelled_callers, return_exceptions=True
    )
    assert all(isinstance(result, asyncio.CancelledError) for result in cancelled_results)

    try:
        with pytest.raises(HTTPException) as exhausted:
            await paidwebmod._ensure_web_asset_archive(
                request,
                principal_hash=principal,
                asset_document=documents[2],
            )
        assert exhausted.value.status_code == 503
        assert exhausted.value.detail == {
                "code": "paid_media_web_asset_archive_capacity_exhausted",
                "message": "Paid media Web asset materialization capacity is exhausted.",
                "retryable": True,
            }
        assert exhausted.value.headers == {"Cache-Control": "no-store", "Retry-After": "1"}
        assert len(started_turns) == 2
    finally:
        release_transitions.set()
    loop_identity = id(asyncio.get_running_loop())
    flights = [
        flight
        for key, flight in paidwebmod._WEB_ARCHIVE_FLIGHTS.items()
        if key[0] == loop_identity
        and key[1] == id(web_client.web_archive)
        and key[2] == principal
    ]
    await asyncio.gather(*flights)
    recovered = await paidwebmod._ensure_web_asset_archive(
        request,
        principal_hash=principal,
        asset_document=documents[2],
    )

    assert recovered == _expected_web_archive_receipt(documents[2])
    assert len(started_turns) == 3


@pytest.mark.asyncio
async def test_acknowledge_and_terminal_poll_share_materialization_capacity(
    web_client, monkeypatch
) -> None:
    blocker_documents = []
    for _ in range(2):
        operation, result = _execute_image_ok(web_client)
        row = web_client.ledger.get_for_principal(
            operation["operationId"], hash_media_principal(PAID_MEDIA_SECRET)
        )
        assert row is not None and row["asset_document_json"]
        blocker_documents.append(json.loads(row["asset_document_json"]))
        proof = result["deliveryProof"]
        web_client.ledger.mark_delivered(
            operation["operationId"],
            result_sha256=proof["resultSha256"],
            archive_receipt_sha256=proof["archiveReceiptSha256"],
            now_ms=paidwebmod._now_ms(),
        )

    video_operation = _claim(web_client, path=VIDEO_PATH)
    video_result = _execute(
        web_client, video_operation, body=_claim_body(path=VIDEO_PATH)
    )
    task_alias = video_result["result"]["task_id"]
    metadata_ack = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=video_result["deliveryProof"],
    )
    assert metadata_ack.status_code == 200, metadata_ack.text

    _ack_operation, ack_result = _execute_image_ok(web_client)
    release_transitions = asyncio.Event()
    two_transitions_entered = asyncio.Event()
    started_turns: list[str] = []

    async def blocked_transition(*args, **kwargs):
        asset_document = kwargs["asset_document"]
        started_turns.append(asset_document["turnId"])
        if len(started_turns) == 2:
            two_transitions_entered.set()
        await release_transitions.wait()
        return _expected_web_archive_receipt(asset_document)

    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", blocked_transition
    )
    request = SimpleNamespace(app=web_client.client.app)
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    blockers = [
        asyncio.create_task(
            paidwebmod._ensure_web_asset_archive(
                request,
                principal_hash=principal,
                asset_document=document,
            )
        )
        for document in blocker_documents
    ]
    # These wall-clock limits only guard against a deadlocked test.  Capacity
    # semantics are asserted by the responses below; full-suite CPU/AV jitter
    # must not be mistaken for a product deadline failure.
    watchdog_seconds = 60
    await asyncio.wait_for(two_transitions_entered.wait(), timeout=watchdog_seconds)
    try:
        acknowledge = await asyncio.wait_for(
            asyncio.to_thread(
                web_client.client.post,
                    f"{WEB_PREFIX}/acknowledge",
                    headers=RUNTIME_AUTH,
                    json=ack_result["deliveryProof"],
            ),
            timeout=watchdog_seconds,
        )
        poll = await asyncio.wait_for(
            asyncio.to_thread(
                web_client.client.post,
                    f"{WEB_PREFIX}/poll-video",
                    headers=RUNTIME_AUTH,
                    json={"taskAlias": task_alias, "model": "paid-model"},
            ),
            timeout=watchdog_seconds,
        )
        for response in (acknowledge, poll):
            assert response.status_code == 503, response.text
            assert response.json()["detail"] == {
                "code": "paid_media_web_asset_archive_capacity_exhausted",
                "message": (
                    "Paid media Web asset materialization capacity is exhausted."
                ),
                "retryable": True,
            }
            assert response.headers["retry-after"] == "1"
        assert len(started_turns) == 2
    finally:
        release_transitions.set()
    completed = await asyncio.gather(*blockers)

    assert completed == [
        _expected_web_archive_receipt(document) for document in blocker_documents
    ]


@pytest.mark.asyncio
async def test_materialization_exceptions_release_the_process_permits(
    web_client, monkeypatch
) -> None:
    documents = []
    for ordinal in range(3):
        operation, result = _execute_image_ok(web_client)
        row = web_client.ledger.get_for_principal(
            operation["operationId"], hash_media_principal(PAID_MEDIA_SECRET)
        )
        assert row is not None and row["asset_document_json"]
        documents.append(json.loads(row["asset_document_json"]))
        if ordinal < 2:
            proof = result["deliveryProof"]
            web_client.ledger.mark_delivered(
                operation["operationId"],
                result_sha256=proof["resultSha256"],
                archive_receipt_sha256=proof["archiveReceiptSha256"],
                now_ms=paidwebmod._now_ms(),
            )

    async def fail_transition(*_args, **_kwargs):
        raise OSError("synthetic archive failure")

    request = SimpleNamespace(app=web_client.client.app)
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", fail_transition
    )
    for document in documents[:2]:
        with pytest.raises(OSError, match="synthetic archive failure"):
            await paidwebmod._ensure_web_asset_archive(
                request,
                principal_hash=principal,
                asset_document=document,
            )

    async def succeed_transition(*_args, **kwargs):
        return _expected_web_archive_receipt(kwargs["asset_document"])

    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", succeed_transition
    )
    assert await paidwebmod._ensure_web_asset_archive(
        request,
        principal_hash=principal,
        asset_document=documents[2],
    ) == _expected_web_archive_receipt(documents[2])


@pytest.mark.asyncio
async def test_read_asset_rejects_excess_server_side_materializations(
    web_client, monkeypatch
) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    initial = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )
    assert initial.status_code == 200, initial.text

    original_read = web_client.web_archive.read
    two_reads_entered = threading.Event()
    release_reads = threading.Event()
    read_calls = 0
    read_calls_lock = threading.Lock()

    def block_first_two_reads(**kwargs):
        nonlocal read_calls
        with read_calls_lock:
            read_calls += 1
            ordinal = read_calls
            if ordinal == 2:
                two_reads_entered.set()
        if ordinal <= 2 and not release_reads.wait(timeout=10):
            raise TimeoutError("test did not release archive reads")
        return original_read(**kwargs)

    monkeypatch.setattr(web_client.web_archive, "read", block_first_two_reads)
    transport = httpx.ASGITransport(
        app=web_client.client.app, raise_app_exceptions=False
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        admitted = [
            asyncio.create_task(
                client.post(
                    f"{WEB_PREFIX}/read-asset",
                    headers=RUNTIME_AUTH,
                    json={"reference": reference},
                )
            )
            for _ in range(2)
        ]
        assert await asyncio.to_thread(two_reads_entered.wait, 10)
        rejected = await client.post(
            f"{WEB_PREFIX}/read-asset",
            headers=RUNTIME_AUTH,
            json={"reference": reference},
        )
        assert rejected.status_code == 503, rejected.text
        assert rejected.json()["detail"] == {
            "code": "paid_media_web_asset_read_capacity_exhausted",
            "message": "Paid media Web asset read capacity is exhausted.",
            "retryable": True,
        }
        assert rejected.headers["retry-after"] == "1"
        assert read_calls == 2
        release_reads.set()
        completed = await asyncio.gather(*admitted)

        assert [response.status_code for response in completed] == [200, 200]
        recovered = await client.post(
            f"{WEB_PREFIX}/read-asset",
            headers=RUNTIME_AUTH,
            json={"reference": reference},
        )
        assert recovered.status_code == 200, recovered.text


@pytest.mark.parametrize(
    "web_client", [OPERATION_RESERVATION_BYTES], indirect=True
)
def test_duplicate_content_assets_archive_all_tokens_and_release_one_reservation(
    web_client,
) -> None:
    async def duplicate_images(_request, _upstream_model):
        web_client.provider.image_calls += 1
        url = "https://media.invalid/duplicate.png"
        web_client.provider.register_asset(url, b"same-private-image", "image/png")
        return {"data": [{"url": url}, {"url": url}]}

    web_client.provider.generate_image_asset_urls = duplicate_images
    _operation, result = _execute_image_ok(web_client)
    references = [item["url"] for item in result["result"]["data"]]
    assert len(references) == 2
    assert references[0] == references[1]

    first = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": references[0]},
    )
    assert first.status_code == 200, first.text
    assert first.content == b"same-private-image"
    acknowledged = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=result["deliveryProof"],
    )
    assert acknowledged.status_code == 200, acknowledged.text

    web_client.provider.generate_image_asset_urls = _FakeProvider.generate_image_asset_urls.__get__(
        web_client.provider, _FakeProvider
    )
    _next_operation, next_result = _execute_image_ok(web_client)
    assert next_result["ok"] is True


def test_read_asset_rejects_non_closed_or_non_content_addressed_requests(web_client) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    for body in (
        {},
        {"reference": reference, "token": "nma1_" + "a" * 43},
        {"reference": "https://example.invalid/private.png"},
        {"reference": f"nachuan-paid-media://sha256/{'0' * 64}"},
    ):
        response = web_client.client.post(
            f"{WEB_PREFIX}/read-asset", headers=RUNTIME_AUTH, json=body
        )
        assert response.status_code in {404, 422}


def test_read_asset_rejects_partial_transfer_requests(web_client) -> None:
    _operation, result = _execute_image_ok(web_client)
    reference = result["result"]["data"][0]["url"]
    response = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers={**RUNTIME_AUTH, "Range": "bytes=0-3"},
        json={"reference": reference},
    )
    assert response.status_code == 400


def test_original_paid_asset_route_preserves_shared_delivery_contract(web_client) -> None:
    operation, _result = _execute_image_ok(web_client)
    row = web_client.ledger.read_operation(operation["operationId"])
    assert row is not None
    document = json.loads(row["asset_document_json"])
    token = document["assets"][0]["token"]

    response = web_client.client.get(
        f"/v1/paid-media/assets/{token}", headers=PAID_ASSET_AUTH
    )

    assert response.status_code == 200, response.text
    assert response.content == b"private-image-1"
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-length"] == str(len(response.content))
    assert response.headers["x-content-sha256"] == document["assets"][0]["sha256"]
    assert response.headers["x-nachuan-paid-media-protocol"] == "2"


def test_original_paid_asset_route_closes_pin_when_authority_drifts(
    web_client, monkeypatch
) -> None:
    operation, _result = _execute_image_ok(web_client)
    row = web_client.ledger.read_operation(operation["operationId"])
    assert row is not None
    document = json.loads(row["asset_document_json"])
    token = document["assets"][0]["token"]
    original_read = web_client.store.read_unacked_asset_success_document
    reads = 0

    def drift_after_pin(**kwargs):  # noqa: ANN003, ANN201
        nonlocal reads
        reads += 1
        return original_read(**kwargs) if reads == 1 else None

    monkeypatch.setattr(
        web_client.store, "read_unacked_asset_success_document", drift_after_pin
    )
    response = web_client.client.get(
        f"/v1/paid-media/assets/{token}", headers=PAID_ASSET_AUTH
    )

    assert response.status_code == 404
    with sqlite3.connect(web_client.asset_store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_read_leases"
        ).fetchone() == (0,)


# ── claim：显式确认与 durable consent ────────────────────────────────


def test_claim_without_confirmation_is_rejected(web_client) -> None:
    body = _claim_body()
    del body["user_confirmed"]
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )

    assert response.status_code == 422
    assert web_client.provider.image_calls == 0
    assert web_client.ledger.count_operations() == 0


def test_claim_with_false_confirmation_is_rejected(web_client) -> None:
    body = _claim_body()
    body["user_confirmed"] = False
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )

    assert response.status_code == 422
    assert web_client.ledger.count_operations() == 0


def test_claim_with_wrong_confirm_digest_is_rejected(web_client) -> None:
    body = _claim_body()
    body["confirm_summary_sha256"] = "0" * 64
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )

    assert response.status_code == 422
    assert web_client.ledger.count_operations() == 0


def test_claim_confirm_digest_is_bound_to_the_exact_body(web_client) -> None:
    body = _claim_body()
    other = _claim_body(payload={"model": "paid-model", "prompt": "other"})
    body["confirm_summary_sha256"] = other["confirm_summary_sha256"]
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )

    assert response.status_code == 422
    assert web_client.ledger.count_operations() == 0


def test_claim_creates_operation_with_durable_consent(web_client) -> None:
    operation = _claim(web_client)

    _assert_public_operation(
        operation, path=IMAGE_PATH, state="claimed", dispatch_count=0
    )
    row = web_client.ledger.read_operation(operation["operationId"])
    assert row is not None
    consent = json.loads(row["consent_json"])
    assert consent["user_confirmed"] is True
    assert DIGEST_RE.fullmatch(consent["confirm_summary_sha256"])
    assert consent["confirmed_at_ms"] > 0
    # 浏览器从不持有付费 Key：请求头里没有它，consent 里也没有它。
    assert PAID_MEDIA_SECRET not in json.dumps(row)


def test_claim_retry_returns_the_same_operation(web_client) -> None:
    operation = _claim(web_client)
    body = _claim_body()
    body = {
        "path": body["path"],
        "encodedBody": body["encodedBody"],
        "retryOperationId": operation["operationId"],
    }
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )

    assert response.status_code == 200, response.text
    replayed = response.json()
    assert replayed["operationId"] == operation["operationId"]
    assert replayed["state"] == "claimed"
    assert web_client.ledger.count_operations() == 1


def test_claim_retry_with_different_body_is_a_mismatch(web_client) -> None:
    operation = _claim(web_client)
    other = json.dumps({"model": "paid-model", "prompt": "changed"})
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim",
        headers=WEB_AUTH,
        json={
            "path": IMAGE_PATH,
            "encodedBody": other,
            "retryOperationId": operation["operationId"],
        },
    )

    assert response.status_code == 409
    assert web_client.provider.image_calls == 0


def test_claim_is_blocked_while_another_operation_is_unresolved(web_client) -> None:
    _claim(web_client)
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=_claim_body()
    )

    assert response.status_code == 409
    assert "unresolved" in response.text
    assert web_client.ledger.count_operations() == 1


@pytest.mark.parametrize(
    "payload",
    [
        {"model": "paid-model", "prompt": "draw", "provider_cost_override": {"credits": 1}},
        {"model": "paid-model", "prompt": "draw", "response_format": "b64_json"},
        {"model": "unknown-model", "prompt": "draw"},
        {"prompt": "draw"},
    ],
)
def test_claim_rejects_closed_set_violations(web_client, payload) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=_claim_body(payload=payload)
    )

    assert response.status_code in {404, 422}
    assert web_client.ledger.count_operations() == 0
    assert web_client.provider.image_calls == 0


def test_claim_rejects_unknown_paths_and_extra_keys(web_client) -> None:
    bad_path = _claim_body(path="/v1/chat/completions")
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=bad_path
    )
    assert response.status_code == 422

    extra = _claim_body()
    extra["unexpected"] = True
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=extra
    )
    assert response.status_code == 422
    assert web_client.ledger.count_operations() == 0


def test_claim_rejects_malformed_encoded_body(web_client) -> None:
    body = _claim_body()
    body["encodedBody"] = "not-json"
    body["confirm_summary_sha256"] = _confirm_digest(IMAGE_PATH, "not-json")
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=WEB_AUTH, json=body
    )

    assert response.status_code == 422
    assert web_client.ledger.count_operations() == 0


# ── 鉴权：runtime Bearer + 审批信任域 + 网关侧付费能力 ────────────────


@pytest.mark.parametrize(
    ("verb", "body"),
    [
        ("claim", _claim_body()),
        ("execute", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "path": IMAGE_PATH, "encodedBody": "{}"}),
        ("abandon", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "evidence": "e"}),
        ("reconcile", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "reason": "r", "evidence": "e", "user_confirmed": True, "confirm_final": True}),
        ("import-legacy", None),
    ],
)
def test_write_verbs_require_the_approval_trust_domain(web_client, verb, body) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/{verb}", headers=RUNTIME_AUTH, json=body
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("verb", "body"),
    [
        ("claim", _claim_body()),
        ("poll-video", {"taskAlias": "nvt1_" + "0" * 64, "model": "paid-model"}),
        ("recover-archive", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000"}),
        ("list-archives", {}),
        ("cancel", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000"}),
        ("list", {}),
        ("acknowledge", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "resultSha256": "0" * 64, "archiveReceiptSha256": "0" * 64}),
    ],
)
def test_all_verbs_require_runtime_bearer(web_client, verb, body) -> None:
    response = web_client.client.post(f"{WEB_PREFIX}/{verb}", json=body)

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("verb", "body"),
    [
        ("claim", _claim_body()),
        ("execute", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "path": IMAGE_PATH, "encodedBody": "{}"}),
        ("poll-video", {"taskAlias": "nvt1_" + "0" * 64, "model": "paid-model"}),
        ("list", {}),
        ("list-archives", {}),
        ("recover-archive", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000"}),
        ("cancel", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000"}),
        ("acknowledge", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "resultSha256": "0" * 64, "archiveReceiptSha256": "0" * 64}),
        ("abandon", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "evidence": "e"}),
        ("reconcile", {"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000", "reason": "r", "evidence": "e", "user_confirmed": True, "confirm_final": True}),
        ("import-legacy", None),
    ],
)
def test_verbs_fail_closed_without_paid_key(web_client, monkeypatch, verb, body) -> None:
    monkeypatch.delenv("NACHUAN_PAID_MEDIA_API_KEY", raising=False)
    appmod.get_settings.cache_clear()
    try:
        response = web_client.client.post(
            f"{WEB_PREFIX}/{verb}", headers=WEB_AUTH, json=body
        )
    finally:
        appmod.get_settings.cache_clear()

    assert response.status_code == 503
    assert "付费媒体 Key 未配置" in response.text
    assert response.headers["Cache-Control"] == "no-store"


def test_web_claim_never_requires_the_paid_key_header(web_client) -> None:
    # 浏览器永远不持有付费 Key：只带 runtime Bearer + 审批头即可 claim。
    headers = dict(WEB_AUTH)
    assert "X-Nachuan-Paid-Media-Key" not in headers
    response = web_client.client.post(
        f"{WEB_PREFIX}/claim", headers=headers, json=_claim_body()
    )

    assert response.status_code == 200, response.text
    assert PAID_MEDIA_SECRET not in response.text


# ── execute：authority 链、幂等重放、恢复态 ──────────────────────────


def test_execute_drives_the_paid_authority_chain_and_archives(web_client) -> None:
    operation, result = _execute_image_ok(web_client)

    assert result["status"] == 200
    assert set(result["result"]) == {"data"}
    assert len(result["result"]["data"]) == 1
    assert ASSET_REF_RE.fullmatch(result["result"]["data"][0]["url"])
    proof = result["deliveryProof"]
    assert proof["operationId"] == operation["operationId"]
    assert DIGEST_RE.fullmatch(proof["resultSha256"])
    assert DIGEST_RE.fullmatch(proof["archiveReceiptSha256"])
    _assert_public_operation(
        result["operation"], path=IMAGE_PATH, state="result_ready", dispatch_count=1
    )
    assert web_client.provider.image_calls == 1
    # 大 base64 绝不出现在响应里。
    assert "base64" not in json.dumps(result).lower()
    with closing(sqlite3.connect(web_client.store.path)) as connection:
        row = connection.execute(
            "SELECT status,provider_phase FROM durable_media_requests"
        ).fetchone()
    assert row == ("succeeded", 1)


def test_delivery_proof_archive_document_and_durable_ack_share_one_receipt(
    web_client,
) -> None:
    operation, result = _execute_image_ok(web_client)
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    ledger_row = web_client.ledger.get_for_principal(
        operation["operationId"], principal
    )
    assert ledger_row is not None and ledger_row["asset_document_json"]
    asset_document = json.loads(ledger_row["asset_document_json"])
    parsed_result = parse_asset_result(asset_document)
    expected = paid_media_web_archive_receipt_sha256(
        principal_hash=principal,
        result=parsed_result,
        installation_id=INSTALLATION_ID,
        installation_epoch=INSTALLATION_EPOCH,
    )

    assert result["deliveryProof"]["archiveReceiptSha256"] == expected
    assert ledger_row["archive_receipt_sha256"] == expected
    reference = result["result"]["data"][0]["url"]
    materialized = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )
    assert materialized.status_code == 200, materialized.text
    assert web_client.web_archive.receipt_for_document(
        principal_hash=principal,
        result=parsed_result,
        installation_id=INSTALLATION_ID,
        installation_epoch=INSTALLATION_EPOCH,
    ) == expected
    with closing(sqlite3.connect(web_client.store.path)) as connection:
        durable_ack = connection.execute(
            "SELECT state,archive_receipt_sha256 "
            "FROM durable_media_asset_authority WHERE turn_id=?",
            (parsed_result.turn_id,),
        ).fetchone()
    assert durable_ack == ("acked", expected)


@pytest.mark.asyncio
async def test_materialization_rejects_a_returned_archive_receipt_drift(
    web_client, monkeypatch
) -> None:
    operation, _result = _execute_image_ok(web_client)
    principal = hash_media_principal(PAID_MEDIA_SECRET)
    row = web_client.ledger.get_for_principal(operation["operationId"], principal)
    assert row is not None and row["asset_document_json"]
    asset_document = json.loads(row["asset_document_json"])

    async def drifted_transition(*_args, **_kwargs):
        return "f" * 64

    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", drifted_transition
    )
    with pytest.raises(PaidMediaWebArchiveUnavailable, match="receipt"):
        await paidwebmod._ensure_web_asset_archive(
            SimpleNamespace(app=web_client.client.app),
            principal_hash=principal,
            asset_document=asset_document,
        )


def test_acknowledge_rejects_a_ledger_receipt_drift_before_materialization(
    web_client, monkeypatch
) -> None:
    operation, result = _execute_image_ok(web_client)
    drifted_receipt = "f" * 64
    original_get = web_client.ledger.get_for_principal

    def drifted_ledger_read(operation_id, principal_hash):
        row = original_get(operation_id, principal_hash)
        if row is None:
            return None
        return {**row, "archive_receipt_sha256": drifted_receipt}

    monkeypatch.setattr(web_client.ledger, "get_for_principal", drifted_ledger_read)

    transition_calls = 0

    async def counted_transition(*_args, **_kwargs):
        nonlocal transition_calls
        transition_calls += 1
        return drifted_receipt

    monkeypatch.setattr(
        paidwebmod, "archive_paid_media_document_for_web", counted_transition
    )
    response = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json={**result["deliveryProof"], "archiveReceiptSha256": drifted_receipt},
    )

    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "operation_proof_conflict"
    assert transition_calls == 0
    current = original_get(
        operation["operationId"], hash_media_principal(PAID_MEDIA_SECRET)
    )
    assert current is not None and current["state"] == "result_ready"


def test_execute_replay_never_calls_the_provider_twice(web_client) -> None:
    operation, first = _execute_image_ok(web_client)
    second = _execute(web_client, operation)

    assert second["ok"] is True
    assert second["result"] == first["result"]
    assert second["deliveryProof"] == first["deliveryProof"]
    assert web_client.provider.image_calls == 1


def test_execute_rejects_a_body_that_does_not_match_the_claim(web_client) -> None:
    operation = _claim(web_client)
    response = web_client.client.post(
        f"{WEB_PREFIX}/execute",
        headers=WEB_AUTH,
        json={
            "operationId": operation["operationId"],
            "path": IMAGE_PATH,
            "encodedBody": json.dumps({"model": "paid-model", "prompt": "tampered"}),
        },
    )

    assert response.status_code == 409
    assert web_client.provider.image_calls == 0


def test_execute_unknown_operation_is_not_found(web_client) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/execute",
        headers=WEB_AUTH,
        json={
            "operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000",
            "path": IMAGE_PATH,
            "encodedBody": _claim_body()["encodedBody"],
        },
    )

    assert response.status_code == 404
    assert web_client.provider.image_calls == 0


def test_execute_fails_closed_when_the_durable_authority_is_missing(web_client) -> None:
    operation = _claim(web_client)
    web_client.client.app.state.media_requests = None
    result = _execute(web_client, operation)

    assert result["ok"] is False
    assert result["recoverable"] is True
    assert web_client.provider.image_calls == 0
    _assert_public_operation(
        result["operation"], path=IMAGE_PATH, state="recoverable", dispatch_count=1
    )


def test_execute_provider_failure_marks_the_operation_recoverable(web_client) -> None:
    web_client.provider.fail_image = True
    operation = _claim(web_client)
    result = _execute(web_client, operation)

    assert result["ok"] is False
    assert result["recoverable"] is True
    assert result["status"] == 502
    _assert_public_operation(
        result["operation"], path=IMAGE_PATH, state="recoverable", dispatch_count=1
    )
    with closing(sqlite3.connect(web_client.store.path)) as connection:
        row = connection.execute(
            "SELECT status FROM durable_media_requests"
        ).fetchone()
    assert row == ("recovery_required",)


def test_execute_provider_failure_reuses_the_same_diagnostic_id_without_redispatch(
    web_client,
) -> None:
    web_client.provider.fail_image = True
    operation = _claim(web_client)

    first = _execute(web_client, operation)
    replay = _execute(web_client, operation)

    assert first["ok"] is False
    assert replay["ok"] is False
    assert first["operation"]["operationId"] == operation["operationId"]
    assert replay["operation"]["operationId"] == operation["operationId"]
    assert web_client.provider.image_calls == 1


def test_execute_after_provider_failure_recovers_via_manual_reconcile(web_client) -> None:
    web_client.provider.fail_image = True
    operation = _claim(web_client)
    failed = _execute(web_client, operation)
    assert failed["ok"] is False

    reconcile = web_client.client.post(
        f"{WEB_PREFIX}/reconcile",
        headers=WEB_AUTH,
        json={
            "operationId": operation["operationId"],
            "reason": "provider-console-checked",
            "evidence": "provider dashboard shows no charge",
            "user_confirmed": True,
            "confirm_final": True,
        },
    )
    assert reconcile.status_code == 200, reconcile.text
    _assert_public_operation(
        reconcile.json(), path=IMAGE_PATH, state="reconciled", dispatch_count=1
    )


def test_cancel_before_dispatch_blocks_execution(web_client) -> None:
    operation = _claim(web_client)
    cancelled = web_client.client.post(
        f"{WEB_PREFIX}/cancel",
        headers=RUNTIME_AUTH,
        json={"operationId": operation["operationId"]},
    )
    assert cancelled.status_code == 200
    assert cancelled.json() == {"ok": True}

    result = _execute(web_client, operation)

    assert result["ok"] is False
    assert "cancel" in result["detail"].lower()
    assert web_client.provider.image_calls == 0
    _assert_public_operation(
        result["operation"], path=IMAGE_PATH, state="recoverable", dispatch_count=0
    )


def test_cancel_is_fire_and_forget_for_unknown_operations(web_client) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/cancel",
        headers=RUNTIME_AUTH,
        json={"operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000"},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": False}


# ── acknowledge：proof 三字段 ────────────────────────────────────────


def test_acknowledge_requires_the_exact_three_field_proof(web_client) -> None:
    operation, result = _execute_image_ok(web_client)
    proof = result["deliveryProof"]

    for field in ("resultSha256", "archiveReceiptSha256"):
        wrong = dict(proof)
        wrong[field] = "0" * 64
        response = web_client.client.post(
            f"{WEB_PREFIX}/acknowledge", headers=RUNTIME_AUTH, json=wrong
        )
        assert response.status_code == 409

    unknown = dict(proof)
    unknown["operationId"] = "desktop-op-123e4567-e89b-42d3-a456-426614174000"
    response = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge", headers=RUNTIME_AUTH, json=unknown
    )
    assert response.status_code == 404

    acknowledged = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge", headers=RUNTIME_AUTH, json=proof
    )
    assert acknowledged.status_code == 200, acknowledged.text
    _assert_public_operation(
        acknowledged.json(), path=IMAGE_PATH, state="delivered", dispatch_count=1
    )
    # 精确重放幂等；不同 proof 冲突。
    replay = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge", headers=RUNTIME_AUTH, json=proof
    )
    assert replay.status_code == 200
    drifted = dict(proof)
    drifted["resultSha256"] = "1" * 64
    conflict = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge", headers=RUNTIME_AUTH, json=drifted
    )
    assert conflict.status_code == 409


def test_acknowledge_requires_result_ready_state(web_client) -> None:
    operation = _claim(web_client)
    response = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json={
            "operationId": operation["operationId"],
            "resultSha256": "0" * 64,
            "archiveReceiptSha256": "0" * 64,
        },
    )

    assert response.status_code == 409


# ── list / list-archives / recover-archive ───────────────────────────


def test_list_shows_only_unresolved_operations(web_client) -> None:
    operation, result = _execute_image_ok(web_client)
    listed = web_client.client.post(f"{WEB_PREFIX}/list", headers=RUNTIME_AUTH, json={})
    assert listed.status_code == 200
    operations = listed.json()
    assert len(operations) == 1
    _assert_public_operation(
        operations[0], path=IMAGE_PATH, state="result_ready", dispatch_count=1
    )

    web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=result["deliveryProof"],
    )
    listed = web_client.client.post(f"{WEB_PREFIX}/list", headers=RUNTIME_AUTH, json={})
    assert listed.json() == []


def test_recover_archive_returns_the_archived_result_and_proof(web_client) -> None:
    operation, result = _execute_image_ok(web_client)
    recovered = web_client.client.post(
        f"{WEB_PREFIX}/recover-archive",
        headers=RUNTIME_AUTH,
        json={"operationId": operation["operationId"]},
    )

    assert recovered.status_code == 200, recovered.text
    archive = recovered.json()
    assert archive["operationId"] == operation["operationId"]
    assert archive["path"] == IMAGE_PATH
    assert archive["model"] == "paid-model"
    assert archive["status"] == 200
    assert archive["result"] == result["result"]
    assert archive["deliveryProof"] == result["deliveryProof"]
    assert DIGEST_RE.fullmatch(archive["archive"]["receiptSha256"])
    assert DIGEST_RE.fullmatch(archive["archive"]["responseSha256"])
    assert archive["archive"]["responseByteLength"] > 0
    assert len(archive["archive"]["assets"]) == 1
    asset = archive["archive"]["assets"][0]
    assert ASSET_REF_RE.fullmatch(asset["reference"])
    assert asset["mediaType"] == "image/png"
    assert asset["byteLength"] > 0
    assert DIGEST_RE.fullmatch(asset["sha256"])


def test_recover_archive_rejects_operations_without_an_archive(web_client) -> None:
    operation = _claim(web_client)
    response = web_client.client.post(
        f"{WEB_PREFIX}/recover-archive",
        headers=RUNTIME_AUTH,
        json={"operationId": operation["operationId"]},
    )

    assert response.status_code == 409


def test_list_archives_paginates_newest_first(web_client) -> None:
    first_operation, first_result = _execute_image_ok(web_client)
    web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=first_result["deliveryProof"],
    )
    _execute_image_ok(web_client)

    page = web_client.client.post(
        f"{WEB_PREFIX}/list-archives", headers=RUNTIME_AUTH, json={"limit": 1}
    )
    assert page.status_code == 200, page.text
    body = page.json()
    assert len(body["items"]) == 1
    assert body["nextCursor"]
    first_item = body["items"][0]
    assert first_item["operationId"] != first_operation["operationId"]
    assert first_item["path"] == IMAGE_PATH
    assert first_item["model"] == "paid-model"
    assert first_item["kind"] == "image"
    assert isinstance(first_item["archivedAt"], int)
    assert DIGEST_RE.fullmatch(first_item["receiptSha256"])
    assert first_item["responseByteLength"] > 0
    assert len(first_item["assets"]) == 1

    rest = web_client.client.post(
        f"{WEB_PREFIX}/list-archives",
        headers=RUNTIME_AUTH,
        json={"cursor": body["nextCursor"], "limit": 10},
    )
    remaining = rest.json()
    assert len(remaining["items"]) == 1
    assert remaining["items"][0]["operationId"] == first_operation["operationId"]
    assert "nextCursor" not in remaining


def test_list_archives_rejects_invalid_pagination(web_client) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/list-archives", headers=RUNTIME_AUTH, json={"limit": 0}
    )
    assert response.status_code == 422
    response = web_client.client.post(
        f"{WEB_PREFIX}/list-archives", headers=RUNTIME_AUTH, json={"cursor": "bad"}
    )
    assert response.status_code == 422


# ── abandon / reconcile 状态机 ───────────────────────────────────────


def test_abandon_terminalizes_only_a_never_dispatched_claim(web_client) -> None:
    operation = _claim(web_client)
    abandoned = web_client.client.post(
        f"{WEB_PREFIX}/abandon",
        headers=WEB_AUTH,
        json={"operationId": operation["operationId"], "evidence": "user changed mind"},
    )

    assert abandoned.status_code == 200, abandoned.text
    _assert_public_operation(
        abandoned.json(), path=IMAGE_PATH, state="reconciled", dispatch_count=0
    )

    again = web_client.client.post(
        f"{WEB_PREFIX}/abandon",
        headers=WEB_AUTH,
        json={"operationId": operation["operationId"], "evidence": "second"},
    )
    assert again.status_code == 409


def test_abandon_rejects_a_dispatched_operation(web_client) -> None:
    operation, _result = _execute_image_ok(web_client)
    response = web_client.client.post(
        f"{WEB_PREFIX}/abandon",
        headers=WEB_AUTH,
        json={"operationId": operation["operationId"], "evidence": "too late"},
    )

    assert response.status_code == 409


def test_reconcile_requires_double_confirmation(web_client) -> None:
    operation = _claim(web_client)
    base = {
        "operationId": operation["operationId"],
        "reason": "provider-console-checked",
        "evidence": "no charge visible",
    }
    for extra in (
        {},
        {"user_confirmed": True},
        {"confirm_final": True},
        {"user_confirmed": False, "confirm_final": True},
    ):
        response = web_client.client.post(
            f"{WEB_PREFIX}/reconcile",
            headers=WEB_AUTH,
            json={**base, **extra},
        )
        assert response.status_code == 422, extra

    reconciled = web_client.client.post(
        f"{WEB_PREFIX}/reconcile",
        headers=WEB_AUTH,
        json={**base, "user_confirmed": True, "confirm_final": True},
    )
    assert reconciled.status_code == 200, reconciled.text
    _assert_public_operation(
        reconciled.json(), path=IMAGE_PATH, state="reconciled", dispatch_count=0
    )


def test_reconcile_unknown_operation_is_not_found(web_client) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/reconcile",
        headers=WEB_AUTH,
        json={
            "operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000",
            "reason": "r",
            "evidence": "e",
            "user_confirmed": True,
            "confirm_final": True,
        },
    )

    assert response.status_code == 404


# ── import-legacy：一次性消费 ────────────────────────────────────────


def _legacy_import(operation_id: str = "desktop-op-123e4567-e89b-42d3-a456-426614174000") -> dict:
    return {
        "operationId": operation_id,
        "path": IMAGE_PATH,
        "requestSha256": "a" * 64,
        "createdAt": 1784200000000,
        "updatedAt": 1784200000001,
        "state": "recoverable",
        "lastStatus": 502,
    }


def test_import_legacy_is_consumed_exactly_once(web_client) -> None:
    imported = web_client.client.post(
        f"{WEB_PREFIX}/import-legacy", headers=WEB_AUTH, json=_legacy_import()
    )
    assert imported.status_code == 200, imported.text
    _assert_public_operation(
        imported.json()["operation"], path=IMAGE_PATH, state="recoverable", dispatch_count=0
    )

    duplicate = web_client.client.post(
        f"{WEB_PREFIX}/import-legacy", headers=WEB_AUTH, json=_legacy_import()
    )
    assert duplicate.status_code == 409

    listed = web_client.client.post(f"{WEB_PREFIX}/list", headers=RUNTIME_AUTH, json={})
    assert [item["operationId"] for item in listed.json()] == [
        "desktop-op-123e4567-e89b-42d3-a456-426614174000"
    ]


def test_imported_legacy_operation_cannot_dispatch_without_its_body(web_client) -> None:
    web_client.client.post(
        f"{WEB_PREFIX}/import-legacy", headers=WEB_AUTH, json=_legacy_import()
    )
    response = web_client.client.post(
        f"{WEB_PREFIX}/execute",
        headers=WEB_AUTH,
        json={
            "operationId": "desktop-op-123e4567-e89b-42d3-a456-426614174000",
            "path": IMAGE_PATH,
            "encodedBody": json.dumps({"model": "paid-model", "prompt": "draw"}),
        },
    )

    assert response.status_code == 409
    assert web_client.provider.image_calls == 0


def test_import_legacy_accepts_null_and_migrated_markers(web_client) -> None:
    # httpx 的 json=None 等价于「无正文」；shim 实际发送的是 JSON 文本 "null"。
    null_marker = web_client.client.post(
        f"{WEB_PREFIX}/import-legacy",
        headers={**WEB_AUTH, "Content-Type": "application/json"},
        content="null",
    )
    assert null_marker.status_code == 200, null_marker.text
    migrated = web_client.client.post(
        f"{WEB_PREFIX}/import-legacy", headers=WEB_AUTH, json={"kind": "migrated"}
    )
    assert migrated.status_code == 200, migrated.text
    assert web_client.ledger.count_operations() == 0


@pytest.mark.parametrize(
    "record",
    [
        {"operationId": "not-an-operation", "path": IMAGE_PATH, "requestSha256": "a" * 64, "createdAt": 1, "updatedAt": 1, "state": "recoverable"},
        {**_legacy_import(), "requestSha256": "not-a-digest"},
        {**_legacy_import(), "state": "delivered"},
        {**_legacy_import(), "unexpected": True},
    ],
)
def test_import_legacy_rejects_invalid_records(web_client, record) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/import-legacy", headers=WEB_AUTH, json=record
    )

    assert response.status_code == 422
    assert web_client.ledger.count_operations() == 0


# ── poll-video ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_web_video_polls_share_one_owner_bound_flight(
    web_client, monkeypatch
) -> None:
    task_alias = "nvt1_" + ("f" * 64)
    entered = asyncio.Event()
    release = asyncio.Event()
    poll_calls = 0

    async def blocked_poll_once(*, principal_hash, task_id, model):
        nonlocal poll_calls
        poll_calls += 1
        assert principal_hash == hash_media_principal(PAID_MEDIA_SECRET)
        assert task_id == task_alias
        assert model == "paid-model"
        entered.set()
        await release.wait()
        return appmod._paid_video_poll_response(
            {"task_id": task_alias, "status": "processing"}
        )

    monkeypatch.setattr(appmod, "_poll_paid_video_once", blocked_poll_once)
    route = next(
        route
        for route in web_client.client.app.routes
        if getattr(route, "path", None) == f"{WEB_PREFIX}/poll-video"
    )
    payload = json.dumps(
        {"taskAlias": task_alias, "model": "paid-model"}
    ).encode("utf-8")

    def route_request() -> Request:
        delivered = False

        async def receive():
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": payload, "more_body": False}

        return Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": f"{WEB_PREFIX}/poll-video",
                "raw_path": f"{WEB_PREFIX}/poll-video".encode("ascii"),
                "query_string": b"",
                "headers": [],
                "client": ("127.0.0.1", 1),
                "server": ("testserver", 80),
                "app": web_client.client.app,
            },
            receive,
        )

    first = asyncio.create_task(route.endpoint(route_request(), _runtime="test-key"))
    await asyncio.wait_for(entered.wait(), timeout=10)
    second = asyncio.create_task(route.endpoint(route_request(), _runtime="test-key"))
    for _ in range(20):
        await asyncio.sleep(0)
    calls_while_both_waited = poll_calls
    release.set()
    responses = await asyncio.gather(first, second)

    assert [response.status_code for response in responses] == [200, 200]
    assert [json.loads(response.body)["status"] for response in responses] == [
        "processing",
        "processing",
    ]
    assert calls_while_both_waited == 1
    assert poll_calls == 1
    assert web_client.readiness_calls == []


def test_immediate_terminal_video_create_archives_and_acks_without_provider_poll(
    web_client,
) -> None:
    appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300.0,
    )
    web_client.provider.video_create_status = "completed"
    operation = _claim(web_client, path=VIDEO_PATH)
    result = _execute(web_client, operation, body=_claim_body(path=VIDEO_PATH))

    assert result["status"] == 200
    assert result["result"]["status"] == "completed"
    assert ASSET_REF_RE.fullmatch(result["result"]["video_url"])
    assert web_client.provider.video_calls == 1
    assert web_client.provider.video_poll_calls == []

    materialized = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": result["result"]["video_url"]},
    )
    assert materialized.status_code == 200, materialized.text
    assert materialized.content == b"private-video-1"

    acknowledged = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=result["deliveryProof"],
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["state"] == "delivered"
    assert web_client.provider.video_calls == 1
    assert web_client.provider.video_poll_calls == []

    # A terminal provider result must release the only background slot even
    # though the public response has been replaced by a private asset result.
    second_operation = _claim(web_client, path=VIDEO_PATH)
    second = _execute(
        web_client,
        second_operation,
        body=_claim_body(path=VIDEO_PATH),
    )
    assert second["status"] == 200
    assert web_client.provider.video_calls == 2
    second_ack = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=second["deliveryProof"],
    )
    assert second_ack.status_code == 200, second_ack.text


def test_video_create_poll_lifecycle(web_client) -> None:
    appmod.configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300.0,
    )
    operation = _claim(web_client, path=VIDEO_PATH)
    created = _execute(web_client, operation, body=_claim_body(path=VIDEO_PATH))

    assert created["ok"] is True, created
    task_alias = created["result"]["task_id"]
    assert VIDEO_ALIAS_RE.fullmatch(task_alias)
    _assert_public_operation(
        created["operation"], path=VIDEO_PATH, state="result_ready", dispatch_count=1
    )
    metadata_ack = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=created["deliveryProof"],
    )
    assert metadata_ack.status_code == 200, metadata_ack.text

    poll = web_client.client.post(
        f"{WEB_PREFIX}/poll-video",
        headers=RUNTIME_AUTH,
        json={"taskAlias": task_alias, "model": "paid-model"},
    )
    assert poll.status_code == 200, poll.text
    status = poll.json()
    assert status["task_id"] == task_alias
    assert status["status"] == "completed"
    assert ASSET_REF_RE.fullmatch(status["video_url"])
    assert web_client.provider.video_poll_calls
    materialized = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": status["video_url"]},
    )
    assert materialized.status_code == 200, materialized.text
    assert materialized.headers["content-type"] == "video/mp4"
    assert materialized.content.startswith(b"private-video-poll-")

    # The persisted local alias is the background-lease identity used by poll.
    # A terminal poll must therefore free the only slot for the next create.
    next_operation = _claim(web_client, path=VIDEO_PATH)
    next_created = _execute(
        web_client,
        next_operation,
        body=_claim_body(path=VIDEO_PATH),
    )
    assert next_created["status"] == 200
    assert web_client.provider.video_calls == 2
    assert web_client.readiness_calls == ["ready", "ready"]


@pytest.mark.parametrize(
    "web_client", [OPERATION_RESERVATION_BYTES], indirect=True
)
def test_terminal_video_poll_archives_then_releases_capacity(web_client) -> None:
    operation = _claim(web_client, path=VIDEO_PATH)
    created = _execute(web_client, operation, body=_claim_body(path=VIDEO_PATH))
    task_alias = created["result"]["task_id"]

    metadata_ack = web_client.client.post(
        f"{WEB_PREFIX}/acknowledge",
        headers=RUNTIME_AUTH,
        json=created["deliveryProof"],
    )
    assert metadata_ack.status_code == 200, metadata_ack.text
    poll = web_client.client.post(
        f"{WEB_PREFIX}/poll-video",
        headers=RUNTIME_AUTH,
        json={"taskAlias": task_alias, "model": "paid-model"},
    )
    assert poll.status_code == 200, poll.text
    reference = poll.json()["video_url"]
    historical = web_client.client.post(
        f"{WEB_PREFIX}/read-asset",
        headers=RUNTIME_AUTH,
        json={"reference": reference},
    )
    assert historical.status_code == 200, historical.text

    _next_operation, next_result = _execute_image_ok(web_client)
    assert next_result["ok"] is True
    assert web_client.readiness_calls == ["ready"]


def test_poll_video_rejects_a_route_model_mismatch(web_client) -> None:
    operation = _claim(web_client, path=VIDEO_PATH)
    created = _execute(web_client, operation, body=_claim_body(path=VIDEO_PATH))
    task_alias = created["result"]["task_id"]

    response = web_client.client.post(
        f"{WEB_PREFIX}/poll-video",
        headers=RUNTIME_AUTH,
        json={"taskAlias": task_alias, "model": "another-model"},
    )

    assert response.status_code == 409


def test_poll_video_rejects_malformed_task_alias(web_client) -> None:
    response = web_client.client.post(
        f"{WEB_PREFIX}/poll-video",
        headers=RUNTIME_AUTH,
        json={"taskAlias": "bogus", "model": "paid-model"},
    )

    assert response.status_code == 422
