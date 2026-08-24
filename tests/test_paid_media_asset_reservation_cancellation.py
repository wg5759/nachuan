from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi import HTTPException

import gateway.app as appmod
from gateway.durable_media_requests import (
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
    PaidMediaAssetStoreError,
)


PRINCIPAL = "2" * 64
INSTALLATION_ID = "3" * 64


def _dependencies() -> PaidMediaAssetStoreDependencies:
    def harden(path: Path, directory: bool) -> None:
        os.chmod(path, 0o700 if directory else 0o600)

    def assert_acl(path: Path, directory: bool) -> None:
        assert Path(path).is_dir() is directory

    return PaidMediaAssetStoreDependencies(
        assert_acl=assert_acl,
        harden_acl=harden,
        disk_free=lambda _path: 16 * 1024 * 1024 * 1024,
    )


def _claimed(store: DurableMediaRequestStore, suffix: str):
    claim = store.claim(
        principal_hash=PRINCIPAL,
        operation="images.create",
        idempotency_key=f"cancel-reservation-{suffix}-1111111111111111",
        request_sha256="4" * 64,
    )
    assert claim.state == "claimed"
    return claim


def _assert_reopened_capacity_is_zero(
    request_path: Path,
    asset_path: Path,
    dependencies: PaidMediaAssetStoreDependencies,
) -> None:
    reopened_requests = DurableMediaRequestStore(request_path)
    reopened_assets = PaidMediaAssetStore.open_bound(
        asset_path,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    try:
        with sqlite3.connect(request_path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity "
                "WHERE singleton=1"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_requests"
            ).fetchone() == (0,)
        with sqlite3.connect(reopened_assets.database_path) as connection:
            assert connection.execute(
                "SELECT COALESCE(SUM(reserved_bytes),0) FROM asset_reservations"
            ).fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM asset_reservations"
            ).fetchone() == (0,)
    finally:
        reopened_assets.close()
        reopened_requests.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_stage", ["durable", "mirror"])
async def test_asset_reservation_cancellation_drains_stage_and_compensates_both_ledgers(
    tmp_path: Path,
    monkeypatch,
    cancel_stage: str,
) -> None:
    request_path = tmp_path / "paid-media-requests.db"
    asset_path = tmp_path / "paid-media-assets"
    dependencies = _dependencies()
    request_store = DurableMediaRequestStore(request_path)
    asset_store = PaidMediaAssetStore.provision(
        asset_path,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    claim = _claimed(request_store, cancel_stage)
    committed = asyncio.Event()
    release = threading.Event()
    loop = asyncio.get_running_loop()

    if cancel_stage == "durable":
        original = request_store.reserve_asset_capacity

        def reserve_with_barrier(**kwargs):
            result = original(**kwargs)
            loop.call_soon_threadsafe(committed.set)
            release.wait(timeout=5)
            return result

        monkeypatch.setattr(request_store, "reserve_asset_capacity", reserve_with_barrier)
    else:
        original = asset_store.reserve

        def reserve_with_barrier(**kwargs):
            result = original(**kwargs)
            loop.call_soon_threadsafe(committed.set)
            release.wait(timeout=5)
            return result

        monkeypatch.setattr(asset_store, "reserve", reserve_with_barrier)

    monkeypatch.setattr(
        appmod.app.state, "media_requests", request_store, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_assets", asset_store, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", 7, raising=False)

    task = asyncio.create_task(
        appmod._reserve_paid_media_asset_capacity(
            claim=claim,
            principal_hash=PRINCIPAL,
            operation="images.create",
        )
    )
    await asyncio.wait_for(committed.wait(), timeout=10)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)

    asset_store.close()
    request_store.close()
    _assert_reopened_capacity_is_zero(request_path, asset_path, dependencies)


@pytest.mark.asyncio
@pytest.mark.parametrize("release_succeeds", [True, False])
async def test_post_commit_mirror_error_requires_positive_local_release_before_durable_abandon(
    tmp_path: Path,
    monkeypatch,
    release_succeeds: bool,
) -> None:
    request_store = DurableMediaRequestStore(tmp_path / "requests.db")
    asset_store = PaidMediaAssetStore.provision(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    claim = _claimed(request_store, f"postcommit-{release_succeeds}")
    original_reserve = asset_store.reserve
    original_release = asset_store.release_pre_provider

    def post_commit_failure(**kwargs):
        original_reserve(**kwargs)
        raise PaidMediaAssetStoreError("injected after mirror commit")

    def release(**kwargs):
        if release_succeeds:
            return original_release(**kwargs)
        return False

    monkeypatch.setattr(asset_store, "reserve", post_commit_failure)
    monkeypatch.setattr(asset_store, "release_pre_provider", release)
    monkeypatch.setattr(
        appmod.app.state, "media_requests", request_store, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_assets", asset_store, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", 7, raising=False)

    with pytest.raises(HTTPException):
        await appmod._reserve_paid_media_asset_capacity(
            claim=claim,
            principal_hash=PRINCIPAL,
            operation="images.create",
        )

    with sqlite3.connect(request_store.path) as connection:
        assert connection.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == ((0,) if release_succeeds else (OPERATION_RESERVATION_BYTES,))
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == ((0,) if release_succeeds else (1,))
    with sqlite3.connect(asset_store.database_path) as connection:
        assert connection.execute(
            "SELECT COALESCE(SUM(reserved_bytes),0) FROM asset_reservations"
        ).fetchone() == ((0,) if release_succeeds else (OPERATION_RESERVATION_BYTES,))
    asset_store.close()
    request_store.close()


@pytest.mark.asyncio
async def test_durable_reservation_error_cleans_exact_preexisting_local_row(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request_store = DurableMediaRequestStore(tmp_path / "requests.db")
    asset_store = PaidMediaAssetStore.provision(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    claim = _claimed(request_store, "preexisting-local")
    asset_store.reserve(
        turn_id=claim.turn_id,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    monkeypatch.setattr(
        request_store,
        "reserve_asset_capacity",
        lambda **_kwargs: (_ for _ in ()).throw(
            DurableMediaRequestUnavailable("injected durable failure")
        ),
    )
    monkeypatch.setattr(
        appmod.app.state, "media_requests", request_store, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_assets", asset_store, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", 7, raising=False)

    with pytest.raises(HTTPException):
        await appmod._reserve_paid_media_asset_capacity(
            claim=claim,
            principal_hash=PRINCIPAL,
            operation="images.create",
        )

    with sqlite3.connect(request_store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM durable_media_requests"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (0,)
    with sqlite3.connect(asset_store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_reservations"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT reserved_total_bytes FROM asset_store_meta"
        ).fetchone() == (0,)
    asset_store.close()
    request_store.close()


@pytest.mark.asyncio
async def test_explicit_pre_provider_release_keeps_durable_hold_when_local_release_is_unconfirmed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request_store = DurableMediaRequestStore(tmp_path / "requests.db")
    asset_store = PaidMediaAssetStore.provision(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    claim = _claimed(request_store, "explicit-release")
    monkeypatch.setattr(
        appmod.app.state, "media_requests", request_store, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_assets", asset_store, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", 7, raising=False)
    await appmod._reserve_paid_media_asset_capacity(
        claim=claim,
        principal_hash=PRINCIPAL,
        operation="images.create",
    )
    monkeypatch.setattr(asset_store, "release_pre_provider", lambda **_kwargs: False)

    with pytest.raises(HTTPException):
        await appmod._release_paid_media_assets_pre_provider(
            claim=claim,
            principal_hash=PRINCIPAL,
            asset_store=asset_store,
        )

    with sqlite3.connect(request_store.path) as connection:
        assert connection.execute(
            "SELECT status,provider_phase FROM durable_media_requests"
        ).fetchone() == ("processing", 0)
        assert connection.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (OPERATION_RESERVATION_BYTES,)
    asset_store.close()
    request_store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("local_release_succeeds", [True, False])
async def test_enter_provider_phase_cancellation_drains_commit_and_uses_local_first_cleanup(
    tmp_path: Path,
    monkeypatch,
    local_release_succeeds: bool,
) -> None:
    request_store = DurableMediaRequestStore(tmp_path / "requests.db")
    asset_store = PaidMediaAssetStore.provision(
        tmp_path / "assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    claim = _claimed(request_store, f"enter-{local_release_succeeds}")
    monkeypatch.setattr(
        appmod.app.state, "media_requests", request_store, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_assets", asset_store, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", 7, raising=False)
    await appmod._reserve_paid_media_asset_capacity(
        claim=claim,
        principal_hash=PRINCIPAL,
        operation="images.create",
    )

    entered = threading.Event()
    release = threading.Event()
    original_enter = request_store.enter_provider_phase
    original_local_release = asset_store.release_pre_provider

    def enter_with_barrier(**kwargs):
        result = original_enter(**kwargs)
        entered.set()
        release.wait(timeout=5)
        return result

    def local_release(**kwargs):
        if local_release_succeeds:
            return original_local_release(**kwargs)
        return False

    monkeypatch.setattr(request_store, "enter_provider_phase", enter_with_barrier)
    monkeypatch.setattr(asset_store, "release_pre_provider", local_release)
    task = asyncio.create_task(
        appmod._enter_paid_media_provider_phase(
            claim,
            principal_hash=PRINCIPAL,
            asset_store=asset_store,
        )
    )
    assert await asyncio.wait_for(asyncio.to_thread(entered.wait), timeout=2)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)

    expected_capacity = 0 if local_release_succeeds else OPERATION_RESERVATION_BYTES
    with sqlite3.connect(request_store.path) as connection:
        assert connection.execute(
            "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
        ).fetchone() == (expected_capacity,)
        row = connection.execute(
            "SELECT status,provider_phase FROM durable_media_requests"
        ).fetchone()
        assert row is None if local_release_succeeds else row == ("processing", 1)
    with sqlite3.connect(asset_store.database_path) as connection:
        assert connection.execute(
            "SELECT COALESCE(SUM(reserved_bytes),0) FROM asset_reservations"
        ).fetchone() == (expected_capacity,)
    asset_store.close()
    request_store.close()
