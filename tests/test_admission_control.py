from __future__ import annotations

import asyncio
import base64
import hashlib
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gateway.admission import (
    AdmissionControlMiddleware,
    AdmissionStoreUnavailable,
    BackgroundJobLeasePool,
    BackgroundJobLimitExceeded,
    configure_background_job_pool,
    current_admission_bucket,
    get_background_job_pool,
    hash_api_keys,
    hash_bearer_token,
    is_expensive_request,
)
from gateway.config import Settings
from gateway.trusted_media_probe import TrustedMediaProbeResult


async def _invoke(
    middleware,
    *,
    key: str,
    path: str = "/v1/chat/completions",
    method: str = "POST",
    authorization_values: list[str] | None = None,
):
    sent: list[dict] = []
    request_messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        if request_messages:
            return request_messages.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await middleware(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [
                (b"authorization", value.encode("latin-1"))
                for value in (
                    authorization_values
                    if authorization_values is not None
                    else [f"Bearer {key}"]
                )
            ],
        },
        receive,
        send,
    )
    start = next(item for item in sent if item["type"] == "http.response.start")
    headers = {
        bytes(name).decode("latin-1").lower(): bytes(value).decode("latin-1")
        for name, value in start.get("headers", [])
    }
    body = b"".join(
        item.get("body", b"") for item in sent if item["type"] == "http.response.body"
    )
    return int(start["status"]), headers, body


async def _empty_response_app(_scope, _receive, send):
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def _middleware(tmp_path: Path, app=_empty_response_app, **kwargs):
    keys = kwargs.pop("keys", {"key-a"})
    return AdmissionControlMiddleware(
        app,
        db_path=tmp_path / "admission.db",
        valid_key_hashes=hash_api_keys(keys),
        **kwargs,
    )


def test_path_classifier_charges_post_by_default_with_tiny_cheap_allowlist() -> None:
    charged = {
        "/v1/chat/completions",
        "/v1/agent/chat",
        "/v1/agent/exec",
        "/v1/agent/job",
        "/v1/agent/job/job-1/resume",
        "/v1/agent/run",
        "/v1/agent/reflect",
        "/v1/orchestrate/panel",
        "/v1/images/generations",
        "/v1/videos/generations",
        "/v1/audio/transcriptions",
        "/v1/studio/execute",
        "/v1/workflows/daily-video/start",
        "/v1/vision",
        "/v1/translate",
        "/v1/lapian/url",
        "/v1/local/select",
        "/v1/intent",
        "/v1/web/read",
        "/v1/kb/query",
        "/v1/route",
        "/v1/kb/docs",
        "/v1/future-model-endpoint",
        "/v1/videos/task-1",
        "/v1/studio/execute/job-1",
    }
    for path in charged:
        assert is_expensive_request("POST", path), path
        if not path.startswith("/v1/videos/"):
            assert not is_expensive_request("GET", path), path

    excluded_post = {
        "/v1/approvals/1/resolve",
        "/v1/agent/inject",
        "/v1/agent/feedback",
        "/v1/agent/undo",
        "/v1/paid-media/probe",
        "/v1/paid-media/web/list-archives",
        "/v1/paid-media/web/list",
        "/v1/paid-media/web/import-legacy",
        "/v1/paid-media/web/recover-archive",
        "/v1/paid-media/web/read-asset",
    }
    assert all(not is_expensive_request("POST", path) for path in excluded_post)
    for path in ("/health", "/v1/sync/status", "/v1/studio/execute/job-1"):
        assert not is_expensive_request("GET", path)
    assert is_expensive_request("GET", "/v1/videos/fetch")
    assert is_expensive_request("GET", "/v1/videos/task-1")
    assert is_expensive_request("GET", "/v1/studio/video/job-1")
    assert not is_expensive_request("HEAD", "/v1/videos/fetch")
    assert not is_expensive_request("GET", "/v1/videos/task-1/nested")


def test_per_key_concurrency_is_global_across_overlapping_requests(tmp_path: Path) -> None:
    async def scenario() -> None:
        entered: asyncio.Queue[str] = asyncio.Queue()
        release = asyncio.Event()

        async def blocking_app(scope, _receive, send):
            auth = dict(scope["headers"])[b"authorization"].decode("latin-1")
            await entered.put(auth.rsplit(" ", 1)[-1])
            await release.wait()
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = _middleware(
            tmp_path,
            blocking_app,
            keys={"key-a", "key-b"},
            max_concurrency_per_key=1,
            rolling_minute_per_key=20,
            daily_expensive_per_key=0,
        )
        first = asyncio.create_task(_invoke(middleware, key="key-a"))
        assert await asyncio.wait_for(entered.get(), 1) == "key-a"

        same_key = await _invoke(middleware, key="key-a")
        assert same_key[0] == 429
        assert same_key[1]["retry-after"] == "1"

        other = asyncio.create_task(_invoke(middleware, key="key-b"))
        assert await asyncio.wait_for(entered.get(), 1) == "key-b"
        release.set()
        assert (await first)[0] == 204
        assert (await other)[0] == 204

    asyncio.run(scenario())


def test_system_concurrency_limit_applies_across_different_keys(tmp_path: Path) -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocking_app(_scope, _receive, send):
            entered.set()
            await release.wait()
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = _middleware(
            tmp_path,
            blocking_app,
            keys={"key-a", "key-b"},
            max_concurrency_per_key=1,
            max_concurrency_global=1,
            rolling_minute_per_key=20,
            daily_expensive_per_key=0,
        )
        first = asyncio.create_task(_invoke(middleware, key="key-a"))
        await asyncio.wait_for(entered.wait(), 1)
        assert (await _invoke(middleware, key="key-b"))[0] == 429
        release.set()
        assert (await first)[0] == 204
        assert (await _invoke(middleware, key="key-b"))[0] == 204

    asyncio.run(scenario())


def test_dynamic_key_hash_source_cannot_lag_authentication(tmp_path: Path) -> None:
    current = set(hash_api_keys({"key-a"}))
    middleware = AdmissionControlMiddleware(
        _empty_response_app,
        db_path=tmp_path / "admission.db",
        valid_key_hashes_provider=lambda: frozenset(current),
        rolling_minute_per_key=1,
        daily_expensive_per_key=0,
    )
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204
    current.add(hash_bearer_token("key-b"))
    assert asyncio.run(_invoke(middleware, key="key-b"))[0] == 204
    assert asyncio.run(_invoke(middleware, key="key-b"))[0] == 429


def test_dynamic_key_source_failure_is_503_not_unmetered(tmp_path: Path) -> None:
    called = False

    async def app(_scope, _receive, send):
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    def broken():
        raise RuntimeError("key source unavailable")

    middleware = AdmissionControlMiddleware(
        app,
        db_path=tmp_path / "admission.db",
        valid_key_hashes_provider=broken,
        daily_expensive_per_key=0,
    )
    response = asyncio.run(_invoke(middleware, key="newly-valid-key"))
    assert response[0] == 503
    assert called is False


def test_duplicate_or_long_valid_authorization_cannot_bypass_admission(
    tmp_path: Path,
) -> None:
    long_key = "k" * 9000
    middleware = _middleware(
        tmp_path,
        keys={long_key},
        rolling_minute_per_key=1,
        daily_expensive_per_key=0,
    )
    ambiguous = asyncio.run(
        _invoke(
            middleware,
            key=long_key,
            authorization_values=[f"Bearer {long_key}", f"Bearer {long_key}"],
        )
    )
    assert ambiguous[0] == 400
    assert "retry-after" not in ambiguous[1]
    assert asyncio.run(_invoke(middleware, key=long_key))[0] == 204
    assert asyncio.run(_invoke(middleware, key=long_key))[0] == 429


def test_authenticated_bucket_context_propagates_to_spawned_tasks(tmp_path: Path) -> None:
    async def scenario() -> None:
        observed: asyncio.Future[str] = asyncio.get_running_loop().create_future()

        async def app(_scope, _receive, send):
            async def child() -> None:
                observed.set_result(current_admission_bucket())

            asyncio.create_task(child())
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = _middleware(tmp_path, app, daily_expensive_per_key=0)
        assert (await _invoke(middleware, key="key-a"))[0] == 204
        assert await asyncio.wait_for(observed, 1) == hash_bearer_token("key-a")

    asyncio.run(scenario())


def test_streaming_slot_is_held_until_final_body_then_released(tmp_path: Path) -> None:
    async def scenario() -> None:
        first_chunk = asyncio.Event()
        release = asyncio.Event()

        async def streaming_app(_scope, _receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send(
                {"type": "http.response.body", "body": b"first", "more_body": True}
            )
            first_chunk.set()
            await release.wait()
            await send({"type": "http.response.body", "body": b"last"})

        middleware = _middleware(
            tmp_path,
            streaming_app,
            max_concurrency_per_key=1,
            rolling_minute_per_key=20,
            daily_expensive_per_key=0,
        )
        first = asyncio.create_task(_invoke(middleware, key="key-a"))
        await asyncio.wait_for(first_chunk.wait(), 1)
        assert (await _invoke(middleware, key="key-a"))[0] == 429
        release.set()
        assert (await first)[0] == 200
        assert (await _invoke(middleware, key="key-a"))[0] == 200

    asyncio.run(scenario())


def test_cancellation_releases_concurrency_slot(tmp_path: Path) -> None:
    async def scenario() -> None:
        calls = 0
        entered = asyncio.Event()
        never = asyncio.Event()

        async def block_once(_scope, _receive, send):
            nonlocal calls
            calls += 1
            if calls == 1:
                entered.set()
                await never.wait()
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        middleware = _middleware(
            tmp_path,
            block_once,
            max_concurrency_per_key=1,
            rolling_minute_per_key=20,
            daily_expensive_per_key=0,
        )
        pending = asyncio.create_task(_invoke(middleware, key="key-a"))
        await asyncio.wait_for(entered.wait(), 1)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert (await _invoke(middleware, key="key-a"))[0] == 204

    asyncio.run(scenario())


def test_downstream_exception_releases_concurrency_slot(tmp_path: Path) -> None:
    calls = 0

    async def fail_once(_scope, _receive, send):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("downstream failed")
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = _middleware(
        tmp_path,
        fail_once,
        max_concurrency_per_key=1,
        rolling_minute_per_key=20,
        daily_expensive_per_key=0,
    )
    with pytest.raises(RuntimeError, match="downstream failed"):
        asyncio.run(_invoke(middleware, key="key-a"))
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204


def test_rolling_minute_limit_and_retry_after(tmp_path: Path) -> None:
    class Clock:
        value = 100.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    middleware = _middleware(
        tmp_path,
        max_concurrency_per_key=8,
        rolling_minute_per_key=2,
        daily_expensive_per_key=0,
        monotonic_clock=clock,
    )
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204
    limited = asyncio.run(_invoke(middleware, key="key-a"))
    assert limited[0] == 429
    assert limited[1]["retry-after"] == "60"
    clock.value += 60.001
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204


def test_daily_limit_is_atomic_across_instances_and_process_restart_state(
    tmp_path: Path,
) -> None:
    kwargs = {
        "max_concurrency_per_key": 8,
        "rolling_minute_per_key": 20,
        "daily_expensive_per_key": 2,
    }
    first_instance = _middleware(tmp_path, **kwargs)
    second_instance = _middleware(tmp_path, **kwargs)
    assert asyncio.run(_invoke(first_instance, key="key-a"))[0] == 204
    assert asyncio.run(_invoke(second_instance, key="key-a"))[0] == 204
    assert asyncio.run(_invoke(first_instance, key="key-a"))[0] == 429

    # A brand-new object (the relevant restart boundary) sees the same SQLite row.
    after_restart = _middleware(tmp_path, **kwargs)
    blocked = asyncio.run(_invoke(after_restart, key="key-a"))
    assert blocked[0] == 429
    assert int(blocked[1]["retry-after"]) > 0


def test_health_probes_storage_without_consuming_daily_quota(tmp_path: Path) -> None:
    middleware = _middleware(
        tmp_path,
        rolling_minute_per_key=20,
        daily_expensive_per_key=1,
    )
    health = asyncio.run(
        _invoke(middleware, key="key-a", path="/health", method="GET")
    )
    assert health[0] == 204
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 429
    assert asyncio.run(
        _invoke(middleware, key="key-a", path="/health", method="GET")
    )[0] == 204


def test_daily_limit_has_no_cross_instance_check_then_increment_race(tmp_path: Path) -> None:
    async def scenario() -> None:
        first = _middleware(
            tmp_path,
            rolling_minute_per_key=20,
            daily_expensive_per_key=1,
        )
        second = _middleware(
            tmp_path,
            rolling_minute_per_key=20,
            daily_expensive_per_key=1,
        )
        responses = await asyncio.gather(
            _invoke(first, key="key-a"),
            _invoke(second, key="key-a"),
        )
        assert sorted(response[0] for response in responses) == [204, 429]

    asyncio.run(scenario())


def test_only_hash_is_persisted_and_rejection_never_echoes_key(tmp_path: Path) -> None:
    secret = "sk-local-plaintext-must-never-be-stored"
    middleware = _middleware(
        tmp_path,
        keys={secret},
        max_concurrency_per_key=8,
        rolling_minute_per_key=20,
        daily_expensive_per_key=1,
    )
    assert asyncio.run(_invoke(middleware, key=secret))[0] == 204
    rejected = asyncio.run(_invoke(middleware, key=secret))
    assert rejected[0] == 429
    assert secret.encode() not in rejected[2]

    connection = sqlite3.connect(tmp_path / "admission.db")
    rows = connection.execute(
        "SELECT bucket_hash, day, request_count FROM admission_daily"
    ).fetchall()
    connection.close()
    assert rows == [(hash_bearer_token(secret), datetime.now().date().isoformat(), 1)]
    for candidate in tmp_path.glob("admission.db*"):
        assert secret.encode() not in candidate.read_bytes()


def test_unrecognized_bearer_does_not_allocate_or_consume_quota(tmp_path: Path) -> None:
    middleware = _middleware(
        tmp_path,
        keys={"configured"},
        daily_expensive_per_key=1,
    )
    # Authentication is downstream; this test app permits the request solely so
    # we can prove the admission layer did not treat an arbitrary token as valid.
    assert asyncio.run(_invoke(middleware, key="attacker-chosen"))[0] == 204
    connection = sqlite3.connect(tmp_path / "admission.db")
    count = connection.execute("SELECT COUNT(*) FROM admission_daily").fetchone()[0]
    connection.close()
    assert count == 0


def test_midnight_opens_a_new_persistent_day_bucket(tmp_path: Path) -> None:
    cn = timezone(timedelta(hours=8))

    class WallClock:
        value = datetime(2026, 7, 13, 23, 59, 59, 500_000, tzinfo=cn)

        def __call__(self) -> datetime:
            return self.value

    clock = WallClock()
    middleware = _middleware(
        tmp_path,
        rolling_minute_per_key=20,
        daily_expensive_per_key=1,
        wall_clock=clock,
    )
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204
    blocked = asyncio.run(_invoke(middleware, key="key-a"))
    assert blocked[0] == 429
    assert blocked[1]["retry-after"] == "1"

    clock.value += timedelta(seconds=1)
    assert asyncio.run(_invoke(middleware, key="key-a"))[0] == 204
    connection = sqlite3.connect(tmp_path / "admission.db")
    days = connection.execute(
        "SELECT day, request_count FROM admission_daily ORDER BY day"
    ).fetchall()
    connection.close()
    assert days == [("2026-07-13", 1), ("2026-07-14", 1)]


def test_locked_database_fails_closed_with_explicit_503(tmp_path: Path) -> None:
    called = False

    async def app(_scope, _receive, send):
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = _middleware(
        tmp_path,
        app,
        daily_expensive_per_key=5,
        sqlite_busy_timeout_ms=20,
    )
    locker = sqlite3.connect(tmp_path / "admission.db", isolation_level=None)
    locker.execute("BEGIN IMMEDIATE")
    try:
        response = asyncio.run(_invoke(middleware, key="key-a"))
        health_while_locked = asyncio.run(
            _invoke(middleware, key="key-a", path="/health", method="GET")
        )
    finally:
        locker.rollback()
        locker.close()
    assert response[0] == 503
    assert response[1]["retry-after"] == "5"
    assert health_while_locked[0] == 503
    assert called is False
    assert middleware.storage_healthy is False
    assert asyncio.run(
        _invoke(middleware, key="key-a", path="/health", method="GET")
    )[0] == 204
    assert middleware.storage_healthy is True


def test_corrupt_database_refuses_to_start_and_daily_zero_needs_no_database(
    tmp_path: Path,
) -> None:
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not sqlite")
    with pytest.raises(AdmissionStoreUnavailable):
        AdmissionControlMiddleware(
            _empty_response_app,
            db_path=corrupt,
            valid_key_hashes=hash_api_keys({"key-a"}),
            daily_expensive_per_key=1,
        )

    disabled = AdmissionControlMiddleware(
        _empty_response_app,
        db_path=tmp_path / "missing" / "ignored.db",
        valid_key_hashes=hash_api_keys({"key-a"}),
        daily_expensive_per_key=0,
    )
    assert asyncio.run(_invoke(disabled, key="key-a"))[0] == 204
    assert not (tmp_path / "missing").exists()


def test_background_job_pool_holds_per_key_and_global_leases_to_release() -> None:
    pool = BackgroundJobLeasePool(max_global=2, max_per_key=1, lease_ttl_seconds=300)
    a = hash_bearer_token("key-a")
    b = hash_bearer_token("key-b")
    first = pool.try_acquire(kind="video", bucket_hash=a, external_ids=("v1",))
    assert first
    assert pool.try_acquire(kind="studio", bucket_hash=a) is None
    second = pool.try_acquire(kind="studio", bucket_hash=b, external_ids=("s1",))
    assert second
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("key-c")) is None
    assert pool.counts() == {"active": 2, "capacity": 2}
    assert pool.renew_external("video", "v1") is True
    assert pool.release_external("video", "v1") is True
    assert pool.release(second) is True
    assert pool.counts()["active"] == 0
    assert "key-a" not in repr(pool._leases)  # noqa: SLF001 -- secret-regression assertion


def test_background_job_pool_restores_durable_jobs_even_above_new_capacity() -> None:
    pool = BackgroundJobLeasePool(max_global=1, max_per_key=1, lease_ttl_seconds=300)
    owner = hash_bearer_token("paid-owner")

    first = pool.restore(
        kind="video", bucket_hash=owner, external_ids=("nvt1_" + "a" * 64,)
    )
    second = pool.restore(
        kind="video", bucket_hash=owner, external_ids=("nvt1_" + "b" * 64,)
    )

    assert first != second
    assert pool.counts() == {"active": 2, "capacity": 1}
    assert (
        pool.restore(
            kind="video", bucket_hash=owner, external_ids=("nvt1_" + "a" * 64,)
        )
        == first
    )
    assert pool.counts()["active"] == 2
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("new")) is None
    assert pool.release_external("video", "nvt1_" + "a" * 64) is True
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("new")) is None
    assert pool.release_external("video", "nvt1_" + "b" * 64) is True
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("new"))


def test_background_job_pool_prunes_stale_unpolled_remote_job() -> None:
    class Clock:
        value = 10.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    pool = BackgroundJobLeasePool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
        monotonic_clock=clock,
    )
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("key-a"))
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("key-b")) is None
    clock.value += 301
    assert pool.try_acquire(kind="video", bucket_hash=hash_bearer_token("key-b"))


@pytest.mark.parametrize("status", ["incomplete", "not_successful", "failure_pending"])
def test_video_nonterminal_statuses_never_release_background_capacity(status: str) -> None:
    import gateway.app as appmod
    from gateway.providers.openai_compat import _video_job_terminal as provider_terminal

    payload = {"status": status}
    assert appmod._video_job_terminal(payload) is False
    assert provider_terminal(payload) is False


@pytest.mark.parametrize(
    "payload",
    [
        {"status": " completed "},
        {"data": {"status": "FAILED"}},
        {"url": "https://cdn.invalid/final.mp4"},
    ],
)
def test_video_terminal_evidence_uses_exact_status_or_media_url(payload: dict) -> None:
    import gateway.app as appmod
    from gateway.providers.openai_compat import _video_job_terminal as provider_terminal

    assert appmod._video_job_terminal(payload) is True
    assert provider_terminal(payload) is True


def test_studio_background_lease_is_held_until_real_task_terminal(monkeypatch) -> None:
    import orchestrator.studio as studio

    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()

        async def fake_run(*_args, **_kwargs):
            entered.set()
            await release.wait()

        monkeypatch.setattr(studio, "_run_execution", fake_run)
        monkeypatch.setattr(studio, "_persist", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(studio, "require_media_binary", lambda _tool: object())
        configure_background_job_pool(
            max_global=1,
            max_per_key=1,
            lease_ttl_seconds=300,
        )
        first = studio.start_execution(None, {"shots": [{}]}, ".")
        assert first
        await asyncio.wait_for(entered.wait(), 1)
        with pytest.raises(BackgroundJobLimitExceeded):
            studio.start_execution(None, {"shots": [{}]}, ".")
        release.set()
        for _ in range(20):
            if get_background_job_pool().counts()["active"] == 0:
                break
            await asyncio.sleep(0)
        assert get_background_job_pool().counts()["active"] == 0
        assert studio.start_execution(None, {"shots": [{}]}, ".")
        release.set()

    try:
        asyncio.run(scenario())
    finally:
        configure_background_job_pool(
            max_global=8,
            max_per_key=4,
            lease_ttl_seconds=21_600,
        )


def test_video_endpoint_lease_blocks_creation_until_terminal_poll(
    monkeypatch, paid_media_auth_headers
) -> None:
    from fastapi.testclient import TestClient

    import gateway.app as appmod

    class Provider:
        name = "video-provider-a"
        base_url = "https://video-provider-a.invalid/v1"
        paid_video_credential_domain = "e" * 64
        paid_media_video_asset_protocol_versions = frozenset({"2"})
        _headers = {"Authorization": "Bearer test-only-video-provider"}
        status = "processing"
        created = 0

        async def generate_video(self, _request, _model):
            self.created += 1
            return {"task_id": f"video-{self.created}", "status": "queued"}

        async def get_video(self, task_id):
            result = {"task_id": task_id, "status": self.status}
            if self.status == "completed":
                result["url"] = (
                    f"https://video-provider-a.invalid/assets/{task_id}.mp4"
                )
            return result

    class Route:
        upstream_model = "upstream-video"
        independence_domain = "d" * 64
        provider = Provider()

    auth = {
        **paid_media_auth_headers,
        "X-Nachuan-Paid-Media-Protocol": "2",
    }
    first_key = f"admission-video-{uuid4()}"
    blocked_key = f"admission-video-{uuid4()}"
    third_key = f"admission-video-{uuid4()}"

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
        appmod,
        "trusted_media_readiness_receipt",
        trusted_media_ready,
    )
    with TestClient(appmod.app) as client:
        monkeypatch.setattr(appmod.app.state.router, "resolve", lambda _model: Route())
        asset_store = appmod.app.state.paid_media_assets
        stage_base64_chunks = asset_store.stage_base64_chunks

        def trusted_video_probe(
            path,
            *,
            expected_media_type,
            expected_byte_length,
            expected_sha256,
            **_kwargs,
        ):
            payload = Path(path).read_bytes()
            assert expected_media_type == "video/mp4"
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

        def stage_local_video(*, turn_id, ordinal, url, prepared_token):
            assert url.startswith("https://video-provider-a.invalid/assets/")
            assert isinstance(prepared_token, str) and prepared_token
            payload = b"test-only-video-asset"
            return stage_base64_chunks(
                turn_id=turn_id,
                ordinal=ordinal,
                media_type="video/mp4",
                chunks=(base64.b64encode(payload).decode("ascii"),),
                prepared_token=prepared_token,
                probe=trusted_video_probe,
            )

        monkeypatch.setattr(asset_store, "stage_url", stage_local_video)
        configure_background_job_pool(
            max_global=1,
            max_per_key=1,
            lease_ttl_seconds=300,
        )
        first = client.post(
            "/v1/videos/generations",
            headers={**auth, "Idempotency-Key": first_key},
            json={"model": "video-model", "prompt": "first"},
        )
        assert first.status_code == 200, first.text
        task_alias = first.json()["task_id"]
        assert get_background_job_pool().counts()["active"] == 1
        blocked = client.post(
            "/v1/videos/generations",
            headers={**auth, "Idempotency-Key": blocked_key},
            json={"model": "video-model", "prompt": "second"},
        )
        assert blocked.status_code == 429
        processing = client.get(
            f"/v1/videos/{task_alias}?model=video-model",
            headers=auth,
        )
        assert processing.status_code == 200
        assert get_background_job_pool().counts()["active"] == 1
        Route.provider.status = "completed"
        time.sleep(2.1)
        terminal = client.get(
            f"/v1/videos/{task_alias}?model=video-model",
            headers=auth,
        )
        assert terminal.status_code == 200
        assert get_background_job_pool().counts()["active"] == 0
        third = client.post(
            "/v1/videos/generations",
            headers={**auth, "Idempotency-Key": third_key},
            json={"model": "video-model", "prompt": "third"},
        )
        assert third.status_code == 200
    configure_background_job_pool(
        max_global=8,
        max_per_key=4,
        lease_ttl_seconds=21_600,
    )


def test_direct_video_provider_holds_and_cleans_terminal_lease(monkeypatch) -> None:
    from gateway.providers.openai_compat import OpenAICompatProvider
    from gateway.schemas import VideoGenerationRequest

    async def scenario() -> None:
        provider = OpenAICompatProvider(
            name="video-test",
            base_url="https://video.invalid/v1",
            api_key="",
        )
        created = 0

        async def fake_request(method, _url, *, what, json_body=None):
            del what, json_body
            nonlocal created
            if method == "POST":
                created += 1
                return {"task_id": f"direct-{created}", "status": "queued"}
            return {"task_id": "direct-1", "status": "completed"}

        monkeypatch.setattr(provider, "_video_request_with_retry", fake_request)
        request = VideoGenerationRequest(model="video-model", prompt="test")
        try:
            first = await provider.generate_video(request, "upstream-video")
            assert first["task_id"] == "direct-1"
            assert get_background_job_pool().counts()["active"] == 1
            assert len(provider._background_video_leases) == 1  # noqa: SLF001

            with pytest.raises(BackgroundJobLimitExceeded):
                await provider.generate_video(request, "upstream-video")

            result = await provider.get_video("direct-1")
            assert result["status"] == "completed"
            assert get_background_job_pool().counts()["active"] == 0
            assert not provider._background_video_leases  # noqa: SLF001

            second = await provider.generate_video(request, "upstream-video")
            assert second["task_id"] == "direct-2"
        finally:
            await provider.aclose()

    configure_background_job_pool(
        max_global=1,
        max_per_key=1,
        lease_ttl_seconds=300,
    )
    try:
        asyncio.run(scenario())
    finally:
        configure_background_job_pool(
            max_global=8,
            max_per_key=4,
            lease_ttl_seconds=21_600,
        )


def test_settings_defaults_are_bounded_and_only_daily_accepts_zero() -> None:
    settings = Settings(_env_file=None)
    assert settings.admission_max_concurrency_per_key == 8
    assert settings.admission_max_concurrency_global == 32
    assert settings.admission_rolling_minute_per_key == 120
    assert settings.admission_daily_expensive_per_key == 2000
    assert settings.admission_background_jobs_global == 8
    assert settings.admission_background_jobs_per_key == 4
    assert settings.admission_background_job_ttl_sec == 21_600
    disabled = Settings(_env_file=None, admission_daily_expensive_per_key=0)
    assert disabled.admission_daily_expensive_per_key == 0
    with pytest.raises(ValidationError):
        Settings(_env_file=None, admission_max_concurrency_per_key=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, admission_rolling_minute_per_key=0)
