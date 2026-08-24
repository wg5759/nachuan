"""Gateway shutdown must drain every owned resource after a close failure."""

from __future__ import annotations

import asyncio
import logging
import threading
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import gateway.app as appmod
import gateway.router as router_mod
from gateway.provider_call_ledger import NoopProviderCallLedger


def test_clean_lifespan_generation_detaches_before_next_early_gate(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clean generation cannot be closed again by the next early failure."""

    from orchestrator import cloud_sync, embedder

    target = FastAPI()
    settings = appmod.get_settings().model_copy(
        update={
            "usage_db_path": str(tmp_path / "usage.db"),
            "sync_server_url": "",
        }
    )
    settings_calls = 0
    local_model_stop_count = 0
    provider_ledgers: list[CloseableProviderLedger] = []
    usages: list[CloseableUsage] = []

    class CloseableProviderLedger(NoopProviderCallLedger):
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1

    class CloseableUsage:
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1

    def settings_then_fail() -> object:
        nonlocal settings_calls
        settings_calls += 1
        if settings_calls == 1:
            return settings
        raise RuntimeError("SECOND GENERATION EARLY GATE")

    def open_provider_ledger() -> CloseableProviderLedger:
        ledger = CloseableProviderLedger()
        provider_ledgers.append(ledger)
        return ledger

    def open_usage(_path: object) -> CloseableUsage:
        usage = CloseableUsage()
        usages.append(usage)
        return usage

    def stop_local_model() -> None:
        nonlocal local_model_stop_count
        local_model_stop_count += 1

    async def exercise() -> None:
        async with appmod.lifespan(target):
            pass
        detached = (
            "provider_call_ledger",
            "router",
            "store",
            "usage",
            "conversations",
            "privacy_rights",
            "weixin_idempotency",
            "memory",
            "cases",
            "kb",
            "approvals",
            "ledger",
            "undo_receipts",
            "local_model_worker",
            "local_model_stop_event",
            "gateway_service_tasks",
            "background_tasks",
            "background_jobs",
            "guard",
        )
        assert all(getattr(target.state, name, None) is None for name in detached)
        with pytest.raises(RuntimeError, match="SECOND GENERATION EARLY GATE"):
            async with appmod.lifespan(target):
                raise AssertionError("the second generation must fail before yield")

    monkeypatch.delenv("NACHUAN_WARM_AUDIO", raising=False)
    monkeypatch.delenv("SAVERS_WARM", raising=False)
    monkeypatch.setattr(appmod, "get_settings", settings_then_fail)
    monkeypatch.setattr(appmod, "configured_provider_call_ledger", open_provider_ledger)
    monkeypatch.setattr(appmod, "UsageLogger", open_usage)
    monkeypatch.setattr(appmod, "initialize_privacy_rights", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "bind_data_dir", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "load_cfg", lambda: None)
    monkeypatch.setattr(
        appmod,
        "read_protected_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr(embedder, "start_warmup", lambda: None)
    monkeypatch.setattr(appmod.semcache, "enabled", lambda: False)
    monkeypatch.setattr(appmod.local_model, "should_autodownload", lambda: False)
    monkeypatch.setattr(appmod.local_model, "start", lambda _event: False)
    monkeypatch.setattr(appmod.local_model, "stop", stop_local_model)

    asyncio.run(exercise())

    assert settings_calls == 2
    assert local_model_stop_count == 1
    assert len(provider_ledgers) == 1
    assert provider_ledgers[0].close_count == 1
    assert len(usages) == 1
    assert usages[0].close_count == 1


def test_failed_generation_is_retried_before_settings_and_blocks_replacement(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed close remains reachable and fences every next-generation gate."""

    from orchestrator import cloud_sync, embedder

    target = FastAPI()
    settings = appmod.get_settings().model_copy(
        update={
            "usage_db_path": str(tmp_path / "usage.db"),
            "sync_server_url": "",
        }
    )
    settings_calls = 0
    provider_open_count = 0
    usage_open_count = 0

    class PersistentUsageCloseFailure:
        def __init__(self) -> None:
            self.close_count = 0

        def close(self) -> None:
            self.close_count += 1
            raise OSError("SECRET stale usage handle")

    usage = PersistentUsageCloseFailure()

    def settings_must_only_run_for_first_generation() -> object:
        nonlocal settings_calls
        settings_calls += 1
        if settings_calls > 1:
            raise AssertionError("settings gate ran before stale generation drain")
        return settings

    def open_provider_ledger() -> NoopProviderCallLedger:
        nonlocal provider_open_count
        provider_open_count += 1
        return NoopProviderCallLedger()

    def open_usage(_path: object) -> PersistentUsageCloseFailure:
        nonlocal usage_open_count
        usage_open_count += 1
        return usage

    async def exercise() -> tuple[appmod.GatewayShutdownError, appmod.GatewayShutdownError]:
        with pytest.raises(appmod.GatewayShutdownError) as first_error:
            async with appmod.lifespan(target):
                pass
        assert target.state.usage is usage
        with pytest.raises(appmod.GatewayShutdownError) as second_error:
            async with appmod.lifespan(target):
                raise AssertionError("a stale handle must fence the next generation")
        return first_error.value, second_error.value

    monkeypatch.delenv("NACHUAN_WARM_AUDIO", raising=False)
    monkeypatch.delenv("SAVERS_WARM", raising=False)
    monkeypatch.setattr(
        appmod,
        "get_settings",
        settings_must_only_run_for_first_generation,
    )
    monkeypatch.setattr(appmod, "configured_provider_call_ledger", open_provider_ledger)
    monkeypatch.setattr(appmod, "UsageLogger", open_usage)
    monkeypatch.setattr(appmod, "initialize_privacy_rights", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "bind_data_dir", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "load_cfg", lambda: None)
    monkeypatch.setattr(
        appmod,
        "read_protected_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr(embedder, "start_warmup", lambda: None)
    monkeypatch.setattr(appmod.semcache, "enabled", lambda: False)
    monkeypatch.setattr(appmod.local_model, "should_autodownload", lambda: False)
    monkeypatch.setattr(appmod.local_model, "start", lambda _event: False)
    monkeypatch.setattr(appmod.local_model, "stop", lambda: None)

    first, second = asyncio.run(exercise())

    assert first.failed_resources == ("usage",)
    assert second.failed_resources == ("usage",)
    assert target.state.usage is usage
    assert usage.close_count == 2
    assert settings_calls == 1
    assert provider_open_count == 1
    assert usage_open_count == 1


def test_live_optional_warmups_are_retained_reported_and_fence_replacement(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live warmups remain reachable and block an in-process replacement."""

    from orchestrator import cloud_sync, compress, embedder

    target = FastAPI()
    settings = appmod.get_settings().model_copy(
        update={
            "usage_db_path": str(tmp_path / "usage.db"),
            "sync_server_url": "",
        }
    )
    settings_calls = 0
    provider_open_count = 0
    release = threading.Event()
    audio_started = threading.Event()
    savers_started = threading.Event()
    embedding_started = threading.Event()

    def settings_must_only_run_for_first_generation() -> object:
        nonlocal settings_calls
        settings_calls += 1
        if settings_calls > 1:
            raise AssertionError("settings gate ran before live warmup drain")
        return settings

    def open_provider_ledger() -> NoopProviderCallLedger:
        nonlocal provider_open_count
        provider_open_count += 1
        return NoopProviderCallLedger()

    def block_audio_warmup() -> None:
        audio_started.set()
        release.wait(timeout=5.0)

    def block_savers_warmup() -> None:
        savers_started.set()
        release.wait(timeout=5.0)

    def start_embedding_warmup() -> threading.Thread:
        def block_embedding_warmup() -> None:
            embedding_started.set()
            release.wait(timeout=5.0)

        worker = threading.Thread(
            target=block_embedding_warmup,
            name="test-embedding-warmup",
            daemon=True,
        )
        worker.start()
        return worker

    async def exercise() -> tuple[appmod.GatewayShutdownError, appmod.GatewayShutdownError]:
        with pytest.raises(appmod.GatewayShutdownError) as first_error:
            async with appmod.lifespan(target):
                assert audio_started.wait(timeout=1.0)
                assert savers_started.wait(timeout=1.0)
                assert embedding_started.wait(timeout=1.0)
        workers = getattr(target.state, "gateway_warmup_workers", None)
        assert isinstance(workers, dict) and len(workers) == 3
        assert all(worker.is_alive() for worker in workers.values())
        with pytest.raises(appmod.GatewayShutdownError) as second_error:
            async with appmod.lifespan(target):
                raise AssertionError("live warmups must fence a replacement")
        return first_error.value, second_error.value

    monkeypatch.setenv("NACHUAN_WARM_AUDIO", "1")
    monkeypatch.setenv("SAVERS_WARM", "1")
    monkeypatch.setattr(appmod, "_GATEWAY_THREAD_DRAIN_TIMEOUT_SEC", 0.02, raising=False)
    monkeypatch.setattr(
        appmod,
        "get_settings",
        settings_must_only_run_for_first_generation,
    )
    monkeypatch.setattr(appmod, "configured_provider_call_ledger", open_provider_ledger)
    monkeypatch.setattr(appmod, "initialize_privacy_rights", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "bind_data_dir", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "load_cfg", lambda: None)
    monkeypatch.setattr(
        appmod,
        "read_protected_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr(appmod.audio_mod, "warm", block_audio_warmup)
    monkeypatch.setattr(embedder, "start_warmup", start_embedding_warmup)
    monkeypatch.setattr(compress, "enabled", lambda: True)
    monkeypatch.setattr(compress, "warm", block_savers_warmup)
    monkeypatch.setattr(appmod.semcache, "enabled", lambda: False)
    monkeypatch.setattr(appmod.local_model, "should_autodownload", lambda: False)
    monkeypatch.setattr(appmod.local_model, "start", lambda _event: False)
    monkeypatch.setattr(appmod.local_model, "stop", lambda: None)

    try:
        first, second = asyncio.run(exercise())
    finally:
        release.set()

    assert first.failed_resources == ("optional_warmup_workers",)
    assert second.failed_resources == ("optional_warmup_workers",)
    assert settings_calls == 1
    assert provider_open_count == 1


def test_optional_warmup_workers_share_one_total_join_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shutdown bound is global, not multiplied by the worker count."""

    target = FastAPI()
    join_timeouts: list[float | None] = []
    policy_now = [100.0]

    class AlwaysAliveWorker:
        def __init__(self, elapsed: float) -> None:
            self.elapsed = elapsed

        def join(self, timeout: float | None = None) -> None:
            join_timeouts.append(timeout)
            assert timeout is not None
            policy_now[0] += min(self.elapsed, max(0.0, timeout))

        @staticmethod
        def is_alive() -> bool:
            return True

    workers = {
        label: AlwaysAliveWorker(elapsed)
        for label, elapsed in (
            ("audio", 0.03),
            ("savers", 0.04),
            ("embedding", 0.04),
        )
    }
    target.state.gateway_warmup_workers = workers
    monkeypatch.setattr(appmod, "_GATEWAY_THREAD_DRAIN_TIMEOUT_SEC", 0.08)
    monkeypatch.setattr(
        appmod,
        "_gateway_thread_drain_now",
        lambda: policy_now[0],
        raising=False,
    )
    monkeypatch.setattr(appmod.undo_receipts, "configure", lambda _value: None)

    with pytest.raises(appmod.GatewayShutdownError) as error_info:
        asyncio.run(
            appmod._close_gateway_resources(target, NoopProviderCallLedger())
        )

    assert error_info.value.failed_resources == ("optional_warmup_workers",)
    assert target.state.gateway_warmup_workers == workers
    assert join_timeouts == pytest.approx((0.08, 0.05, 0.01))


def test_embedder_start_warmup_returns_the_single_reachable_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one-shot embedding loader exposes one lifecycle-owned handle."""

    from orchestrator import embedder

    instance = embedder._Embedder()
    started = 0

    class FakeThread:
        def __init__(self, *, target, daemon):
            assert daemon is True
            self._target = target

        def start(self) -> None:
            nonlocal started
            started += 1

    monkeypatch.setattr(
        embedder,
        "threading",
        SimpleNamespace(Thread=FakeThread),
    )

    first = instance.start_warmup()
    second = instance.start_warmup()

    assert first is second
    assert first is not None
    assert started == 1


def test_startup_failure_before_yield_closes_every_constructed_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mid-startup exception must not strand resources created before yield."""

    from orchestrator import cloud_sync

    events: list[str] = []
    local_started = threading.Event()
    local_finished = threading.Event()
    local_stop_event: list[threading.Event] = []
    target = FastAPI()

    class CloseableProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider_call_ledger")

    class Closeable:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            events.append(self.name)

    class CloseableRouter:
        async def aclose(self) -> None:
            events.append("router")

    def start_local(stop_event: threading.Event) -> bool:
        local_stop_event.append(stop_event)
        local_started.set()
        try:
            stop_event.wait(timeout=5.0)
            return True
        finally:
            local_finished.set()

    def fail_cloud_config_load() -> None:
        # Give the old implementation a deterministic chance to prove that it
        # launched optional local work before mandatory startup finished.
        local_started.wait(timeout=0.5)
        raise RuntimeError("SECRET startup failure")

    async def enter_lifespan() -> None:
        async with appmod.lifespan(target):
            raise AssertionError("startup failure should prevent yield")

    monkeypatch.setattr(
        appmod,
        "configured_provider_call_ledger",
        lambda: CloseableProviderLedger(),
    )
    monkeypatch.setattr(appmod, "Router", lambda *, store: CloseableRouter())
    monkeypatch.setattr(appmod, "UsageLogger", lambda _path: Closeable("usage"))
    monkeypatch.setattr(
        appmod,
        "ConversationStore",
        lambda **_kwargs: Closeable("conversations"),
    )
    monkeypatch.setattr(appmod, "initialize_privacy_rights", lambda _path: None)
    monkeypatch.setattr(appmod.local_model, "should_autodownload", lambda: False)
    monkeypatch.setattr(appmod.local_model, "start", start_local)
    monkeypatch.setattr(
        appmod.local_model,
        "stop",
        lambda: events.append("local_model"),
    )
    monkeypatch.setattr(cloud_sync, "bind_data_dir", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "load_cfg", fail_cloud_config_load)

    try:
        with pytest.raises(RuntimeError, match="SECRET startup failure"):
            asyncio.run(enter_lifespan())

        assert not local_started.is_set()
        assert target.state.local_model_stop_event is None
        assert {
            "local_model",
            "router",
            "usage",
            "conversations",
            "provider_call_ledger",
        }.issubset(events)
        assert target.state.gateway_shutdown_failures == ()
    finally:
        # Keep any regressed implementation from leaving the deliberately
        # blocked daemon thread alive after the assertion proves the leak.
        if local_stop_event:
            local_stop_event[0].set()
        local_finished.wait(timeout=2.0)


def test_mandatory_startup_rejection_prevents_all_optional_warmups(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No optional thread may start before mandatory startup gates pass."""

    from orchestrator import cloud_sync, compress, embedder

    called: list[str] = []
    target = FastAPI()
    settings = appmod.get_settings().model_copy(
        update={
            "usage_db_path": str(tmp_path / "usage.db"),
            "sync_server_url": "https://disabled.invalid",
        }
    )

    async def enter_lifespan() -> None:
        async with appmod.lifespan(target):
            raise AssertionError("mandatory startup rejection should prevent yield")

    monkeypatch.setenv("NACHUAN_WARM_AUDIO", "1")
    monkeypatch.setenv("SAVERS_WARM", "1")
    monkeypatch.setattr(appmod, "get_settings", lambda: settings)
    monkeypatch.setattr(
        appmod,
        "configured_provider_call_ledger",
        lambda: NoopProviderCallLedger(),
    )
    monkeypatch.setattr(cloud_sync, "bind_data_dir", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "load_cfg", lambda: None)
    monkeypatch.setattr(
        appmod,
        "read_protected_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr(appmod.audio_mod, "warm", lambda: called.append("audio"))
    monkeypatch.setattr(embedder, "start_warmup", lambda: called.append("embedder"))
    monkeypatch.setattr(compress, "enabled", lambda: True)
    monkeypatch.setattr(compress, "warm", lambda: called.append("compress"))
    monkeypatch.setattr(appmod.semcache, "enabled", lambda: True)
    monkeypatch.setattr(appmod.semcache, "warm", lambda: called.append("semcache"))
    monkeypatch.setattr(appmod.local_model, "should_autodownload", lambda: False)
    monkeypatch.setattr(
        appmod.local_model,
        "start",
        lambda _event: called.append("local_model"),
    )
    monkeypatch.setattr(appmod.local_model, "stop", lambda: None)

    with pytest.raises(RuntimeError, match="SYNC_SERVER_URL is disabled"):
        asyncio.run(enter_lifespan())

    # Old daemon targets are tiny in this test; give a regressed launch a
    # deterministic chance to publish its call before checking the fence.
    threading.Event().wait(0.2)
    assert called == []


def test_local_worker_start_failure_drains_owned_resources_exactly_once(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inner startup cleanup must prevent the outer guard from closing twice."""

    from orchestrator import cloud_sync

    closes: list[str] = []
    target = FastAPI()
    settings = appmod.get_settings().model_copy(
        update={
            "usage_db_path": str(tmp_path / "usage.db"),
            "sync_server_url": "",
        }
    )
    original_thread_start = threading.Thread.start
    original_ledger_close = appmod.TaskLedger.close

    class CloseableProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            closes.append("provider")

    def fail_only_local_worker(self) -> None:  # noqa: ANN001
        if self.name == "nachuan-local-model":
            raise RuntimeError("simulated local worker start failure")
        original_thread_start(self)

    def fail_ledger_close(self) -> None:  # noqa: ANN001
        original_ledger_close(self)
        raise OSError("SECRET ledger close failure")

    async def enter_lifespan() -> None:
        async with appmod.lifespan(target):
            raise AssertionError("failed local worker must prevent yield")

    monkeypatch.delenv("NACHUAN_WARM_AUDIO", raising=False)
    monkeypatch.delenv("SAVERS_WARM", raising=False)
    monkeypatch.setattr(appmod, "get_settings", lambda: settings)
    monkeypatch.setattr(
        appmod,
        "configured_provider_call_ledger",
        lambda: CloseableProviderLedger(),
    )
    monkeypatch.setattr(cloud_sync, "bind_data_dir", lambda _path: None)
    monkeypatch.setattr(cloud_sync, "load_cfg", lambda: None)
    monkeypatch.setattr(
        appmod,
        "read_protected_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr(threading.Thread, "start", fail_only_local_worker)
    monkeypatch.setattr(appmod.TaskLedger, "close", fail_ledger_close)
    monkeypatch.setattr(
        appmod.local_model,
        "stop",
        lambda: closes.append("local_model"),
    )

    with pytest.raises(RuntimeError, match="simulated local worker start failure"):
        asyncio.run(enter_lifespan())

    assert closes.count("provider") == 1
    assert closes.count("local_model") == 1
    assert target.state.gateway_shutdown_failures == ("ledger",)


def test_lifespan_reentry_drains_failed_media_handles_before_opening_replacements(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed close from the prior lifespan fences the matching new authority."""

    opened: list[str] = []
    target = FastAPI()

    class PersistentCloseFailure:
        def __init__(self, name: str) -> None:
            self.name = name
            self.attempts = 0

        def close(self) -> None:
            self.attempts += 1
            raise OSError(f"SECRET stale {self.name} handle")

    paid_pending = PersistentCloseFailure("paid")
    channel_pending = PersistentCloseFailure("channel")
    target.state.paid_media_close_pending = (paid_pending,)
    target.state.channel_media_close_pending = (channel_pending,)

    def open_paid(_path):  # noqa: ANN001, ANN202
        opened.append("paid")
        return SimpleNamespace(close=lambda: None)

    def open_channel(_path):  # noqa: ANN001, ANN202
        opened.append("channel")
        return SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(appmod, "_is_packaged_runtime", lambda: False)
    monkeypatch.setattr(appmod, "DurableMediaRequestStore", open_paid)
    monkeypatch.setattr(
        appmod.PaidMediaAssetStore,
        "provision",
        classmethod(
            lambda _cls, *_args, **_kwargs: SimpleNamespace(close=lambda: None)
        ),
    )
    monkeypatch.setattr(appmod, "DurableChannelMediaRequestStore", open_channel)

    paid_status = appmod._initialize_paid_media_authority(target, tmp_path)
    channel_status = appmod._initialize_channel_media_authority(target, tmp_path)

    assert opened == []
    assert paid_pending.attempts == 1
    assert channel_pending.attempts == 1
    assert target.state.paid_media_close_pending == (paid_pending,)
    assert target.state.channel_media_close_pending == (channel_pending,)
    assert paid_status["mode"] == "disabled"
    assert paid_status["reason_code"] == "store-close-incomplete"
    assert channel_status["mode"] == "disabled"
    assert channel_status["reason_code"] == "store-close-incomplete"


def test_shutdown_closes_channel_controller_once_and_continues_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    target = FastAPI()

    class ProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider")

    def fail_controller_close() -> None:
        events.append("channel-controller")
        raise OSError("SECRET controller path")

    def raw_store_close() -> None:
        events.append("raw-store")

    def closed(name: str):  # noqa: ANN202
        return lambda: events.append(name)

    async def close_router() -> None:
        events.append("router")

    class LocalWorker:
        def join(self, timeout: float) -> None:
            assert timeout > 0
            events.append("local-worker")

        def is_alive(self) -> bool:
            return False

    target.state.router = SimpleNamespace(aclose=close_router)
    target.state.local_model_worker = LocalWorker()
    target.state.usage = SimpleNamespace(close=closed("usage"))
    target.state.memory = SimpleNamespace(close=closed("memory"))
    target.state.cases = SimpleNamespace(close=closed("cases"))
    target.state.kb = SimpleNamespace(close=closed("knowledge"))
    target.state.approvals = SimpleNamespace(close=closed("approvals"))
    target.state.conversations = SimpleNamespace(close=closed("conversations"))
    target.state.ledger = SimpleNamespace(close=closed("ledger"))
    target.state.weixin_idempotency = SimpleNamespace(close=closed("weixin"))
    target.state.channel_media_installation_control = SimpleNamespace(
        close=fail_controller_close
    )
    target.state.channel_media_requests = SimpleNamespace(close=raw_store_close)
    target.state.channel_media_close_pending = ()
    target.state.undo_receipts = SimpleNamespace(close=closed("undo"))
    monkeypatch.setattr(appmod.local_model, "stop", closed("local"))
    monkeypatch.setattr(
        appmod,
        "_close_paid_media_authority",
        lambda _target: events.append("paid"),
    )
    monkeypatch.setattr(appmod.undo_receipts, "configure", lambda _value: None)

    with pytest.raises(appmod.GatewayShutdownError) as error_info:
        asyncio.run(appmod._close_gateway_resources(target, ProviderLedger()))

    assert "raw-store" not in events
    assert "local-worker" in events
    assert "ledger" in events
    assert events[-2:] == ["undo", "provider"]
    assert error_info.value.failed_resources == ("channel_media_requests",)


def test_partial_shutdown_continues_after_base_close_interruption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a BaseException from one close cannot strand later peers."""

    events: list[str] = []
    target = FastAPI()

    class CloseInterruption(BaseException):
        pass

    class ProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider")

    def interrupt_usage_close() -> None:
        events.append("usage")
        raise CloseInterruption("SECRET close interruption")

    target.state.usage = SimpleNamespace(close=interrupt_usage_close)
    target.state.conversations = SimpleNamespace(
        close=lambda: events.append("conversations")
    )
    target.state.undo_receipts = object()
    monkeypatch.setattr(appmod.local_model, "stop", lambda: None)
    monkeypatch.setattr(appmod.undo_receipts, "configure", lambda _value: None)

    with pytest.raises(appmod.GatewayShutdownError) as error_info:
        asyncio.run(appmod._close_gateway_resources(target, ProviderLedger()))

    assert events == ["usage", "conversations", "provider"]
    assert error_info.value.failed_resources == ("usage",)
    assert "SECRET" not in str(error_info.value)


def test_paid_pending_close_failure_is_reported_by_gateway_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained paid handle is a shutdown failure, not a successful close."""

    events: list[str] = []
    target = FastAPI()

    class PendingPaidHandle:
        def __init__(self) -> None:
            self.attempts = 0

        def close(self) -> None:
            self.attempts += 1
            raise OSError("SECRET paid close failure")

    class ProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider")

    pending = PendingPaidHandle()
    target.state.paid_media_close_pending = (pending,)
    monkeypatch.setattr(appmod.local_model, "stop", lambda: None)
    monkeypatch.setattr(appmod.undo_receipts, "configure", lambda _value: None)

    with pytest.raises(appmod.GatewayShutdownError) as error_info:
        asyncio.run(appmod._close_gateway_resources(target, ProviderLedger()))

    assert error_info.value.failed_resources == ("paid_media_authority",)
    assert pending.attempts == 1
    assert target.state.paid_media_close_pending == (pending,)
    assert target.state.paid_media_authority["reason_code"] == "store-close-incomplete"
    assert events == ["provider"]
    assert "SECRET" not in str(error_info.value)


def test_router_provider_close_is_sanitized_and_continues_after_base_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One hostile provider close cannot skip its peer or leak exception text."""

    events: list[str] = []
    secret = "SECRET provider credential in close failure"

    class CloseInterruption(BaseException):
        pass

    class Provider:
        def __init__(self, name: str, *, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        async def aclose(self) -> None:
            events.append(self.name)
            if self.fail:
                raise CloseInterruption(secret)

    caplog.set_level(logging.ERROR, logger="gateway.router")
    providers = {
        "first": Provider("first", fail=True),
        "second": Provider("second"),
    }

    with pytest.raises(router_mod.RouterProviderCloseError) as error_info:
        asyncio.run(appmod.Router._close_provider_snapshot(providers))

    assert events == ["first", "second"]
    assert error_info.value.failed_count == 1
    assert str(error_info.value) == "router provider close incomplete"
    assert secret not in caplog.text
    assert secret not in str(error_info.value)


def test_router_provider_close_propagates_cancellation_after_closing_peers() -> None:
    events: list[str] = []

    class Provider:
        def __init__(self, name: str, *, cancel: bool = False) -> None:
            self.name = name
            self.cancel = cancel

        async def aclose(self) -> None:
            events.append(self.name)
            if self.cancel:
                raise asyncio.CancelledError()

    providers = {
        "first": Provider("first", cancel=True),
        "second": Provider("second"),
    }

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(appmod.Router._close_provider_snapshot(providers))

    assert events == ["first", "second"]


def test_router_aclose_retains_failed_generation_for_retry_without_reclosing_peer() -> None:
    """A failed provider remains owned; a successful peer reaches final state."""

    class CloseInterruption(BaseException):
        pass

    class Provider:
        enabled = True

        def __init__(self, name: str, *, fail_once: bool = False) -> None:
            self.name = name
            self.fail_once = fail_once
            self.close_count = 0

        async def aclose(self) -> None:
            self.close_count += 1
            if self.fail_once and self.close_count == 1:
                raise CloseInterruption("SECRET transient provider close failure")

    async def exercise() -> None:
        router = object.__new__(router_mod.Router)
        router._providers = {}
        router._routes = {}
        router._retired_generations = set()
        router._reload_lock = asyncio.Lock()
        failed_raw = Provider("failed", fail_once=True)
        peer_raw = Provider("peer")
        failed = router._wrap_provider(failed_raw)
        peer = router._wrap_provider(peer_raw)
        router._providers = {"failed": failed, "peer": peer}

        with pytest.raises(router_mod.RouterProviderCloseError):
            await router.aclose()

        assert failed in router._retired_generations
        assert peer not in router._retired_generations
        assert not failed.closed
        assert peer.closed
        assert failed_raw.close_count == 1
        assert peer_raw.close_count == 1

        await router.aclose()
        assert router._retired_generations == set()
        assert failed.closed
        assert failed_raw.close_count == 2
        assert peer_raw.close_count == 1

    asyncio.run(exercise())


def test_router_aclose_propagates_cancellation_but_retains_generation_for_retry() -> None:
    """Provider cancellation is observable without surrendering ownership."""

    class Provider:
        enabled = True

        def __init__(self, name: str, *, cancel_once: bool = False) -> None:
            self.name = name
            self.cancel_once = cancel_once
            self.close_count = 0

        async def aclose(self) -> None:
            self.close_count += 1
            if self.cancel_once and self.close_count == 1:
                raise asyncio.CancelledError()

    async def exercise() -> None:
        router = object.__new__(router_mod.Router)
        router._providers = {}
        router._routes = {}
        router._retired_generations = set()
        router._reload_lock = asyncio.Lock()
        cancelled_raw = Provider("cancelled", cancel_once=True)
        peer_raw = Provider("peer")
        cancelled = router._wrap_provider(cancelled_raw)
        peer = router._wrap_provider(peer_raw)
        router._providers = {"cancelled": cancelled, "peer": peer}

        with pytest.raises(asyncio.CancelledError):
            await router.aclose()

        assert cancelled in router._retired_generations
        assert peer not in router._retired_generations
        assert not cancelled.closed
        assert peer.closed
        assert cancelled_raw.close_count == 1
        assert peer_raw.close_count == 1

        await router.aclose()
        assert router._retired_generations == set()
        assert cancelled.closed
        assert cancelled_raw.close_count == 2
        assert peer_raw.close_count == 1

    asyncio.run(exercise())


def test_retirement_close_failure_stays_owned_until_router_retry_succeeds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Background retirement failure cannot silently leave the ownership set."""

    class CloseInterruption(BaseException):
        pass

    class Provider:
        name = "retiring"
        enabled = True

        def __init__(self) -> None:
            self.close_count = 0

        async def aclose(self) -> None:
            self.close_count += 1
            if self.close_count == 1:
                raise CloseInterruption("SECRET retirement close failure")

    async def exercise() -> None:
        router = object.__new__(router_mod.Router)
        router._providers = {}
        router._routes = {}
        router._retired_generations = set()
        router._reload_lock = asyncio.Lock()
        raw = Provider()
        generation = router._wrap_provider(raw)

        router._retire_provider(generation)
        assert generation._retirement_task is not None
        await generation._retirement_task

        assert generation in router._retired_generations
        assert not generation.closed
        assert raw.close_count == 1

        await router.aclose()
        assert generation.closed
        assert generation not in router._retired_generations
        assert raw.close_count == 2

    caplog.set_level(logging.ERROR, logger="gateway.router")
    asyncio.run(exercise())
    assert "provider retirement close incomplete" in caplog.text
    assert "SECRET retirement close failure" not in caplog.text


def test_reload_build_cleanup_failure_is_adopted_for_later_router_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed replacement never escapes the live router's ownership graph."""

    class Provider:
        name = "partial-replacement"
        enabled = True

        def __init__(self) -> None:
            self.close_count = 0

        async def aclose(self) -> None:
            self.close_count += 1
            if self.close_count == 1:
                raise OSError("SECRET replacement cleanup failure")

    async def exercise() -> None:
        router = object.__new__(router_mod.Router)
        router._catalog = {}
        router.store = None
        router._providers = {}
        router._routes = {}
        router._retired_generations = set()
        router._reload_lock = asyncio.Lock()
        created: list[tuple[Provider, object]] = []

        def fail_after_partial_build(replacement: router_mod.Router) -> None:
            raw = Provider()
            generation = replacement._wrap_provider(raw)
            replacement._providers["partial"] = generation
            created.append((raw, generation))
            raise ValueError("RELOAD BUILD ROOT")

        monkeypatch.setattr(router_mod.Router, "_build", fail_after_partial_build)

        with pytest.raises(ValueError, match="RELOAD BUILD ROOT"):
            await router.reload()

        raw, generation = created[0]
        assert generation in router._retired_generations
        assert not generation.closed
        assert raw.close_count == 1

        await router.aclose()
        assert generation not in router._retired_generations
        assert generation.closed
        assert raw.close_count == 2

    asyncio.run(exercise())


def test_single_connection_build_cleanup_failure_preserves_root_and_retry_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial one-connection candidates obey the same cleanup ownership rule."""

    class Provider:
        name = "partial-connection"
        enabled = True

        def __init__(self) -> None:
            self.close_count = 0

        def expected_model_family(self, _upstream: str) -> str:
            return "test-family"

        async def aclose(self) -> None:
            self.close_count += 1
            if self.close_count == 1:
                raise OSError("SECRET connection cleanup failure")

    class Store:
        @staticmethod
        def get(_name: str) -> dict[str, object]:
            return {
                "type": "openai_compat",
                "base_url": "https://api.openai.com/v1",
                "enabled_models": [{"id": "candidate-model"}],
            }

        @staticmethod
        def is_verified(_name: str, _conn: object) -> bool:
            return True

    async def exercise() -> None:
        router = object.__new__(router_mod.Router)
        router._catalog = {}
        router.store = Store()
        router._providers = {}
        router._routes = {}
        router._retired_generations = set()
        router._reload_lock = asyncio.Lock()
        raw = Provider()
        monkeypatch.setattr(
            router,
            "assert_connection_model_ids_available",
            lambda _name, _conn: None,
        )
        monkeypatch.setattr(
            router,
            "_make_provider_from_conn",
            lambda _name, _conn: raw,
        )
        monkeypatch.setattr(
            router_mod,
            "preset_meta",
            lambda _model: (_ for _ in ()).throw(ValueError("CONNECTION BUILD ROOT")),
        )

        with pytest.raises(ValueError, match="CONNECTION BUILD ROOT"):
            await router.reload_connection("partial-connection")

        assert len(router._retired_generations) == 1
        generation = next(iter(router._retired_generations))
        assert generation._provider is raw
        assert not generation.closed
        assert raw.close_count == 1

        await router.aclose()
        assert generation.closed
        assert router._retired_generations == set()
        assert raw.close_count == 2

    asyncio.run(exercise())


def test_repeated_failed_reload_stops_constructing_at_cleanup_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full cleanup-debt set fences the next build before any candidate exists."""

    class Provider:
        name = "persistent-partial"
        enabled = True

        async def aclose(self) -> None:
            raise OSError("SECRET persistent replacement cleanup failure")

    async def exercise() -> None:
        router = object.__new__(router_mod.Router)
        router._catalog = {}
        router.store = None
        router._providers = {}
        router._routes = {}
        router._retired_generations = set()
        router._reload_lock = asyncio.Lock()
        router._MAX_RETIRED_GENERATIONS = 1
        build_count = 0

        def fail_after_one_candidate(replacement: router_mod.Router) -> None:
            nonlocal build_count
            build_count += 1
            replacement._providers["partial"] = replacement._wrap_provider(
                Provider()
            )
            raise ValueError("RELOAD BUILD ROOT")

        monkeypatch.setattr(router_mod.Router, "_build", fail_after_one_candidate)

        with pytest.raises(ValueError, match="RELOAD BUILD ROOT"):
            await router.reload()
        assert build_count == 1
        assert len(router._retired_generations) == 1

        with pytest.raises(router_mod.ProviderRetirementCapacityError):
            await router.reload()
        assert build_count == 1
        assert len(router._retired_generations) == 1

    asyncio.run(exercise())


def test_provider_generation_immediate_retry_does_not_depend_on_done_callback() -> None:
    """The awaiting close path itself clears a failed task before returning."""

    class Provider:
        name = "same-tick-retry"
        enabled = True

        def __init__(self) -> None:
            self.close_count = 0

        async def aclose(self) -> None:
            self.close_count += 1
            if self.close_count == 1:
                raise OSError("SECRET first close failure")

    async def exercise() -> None:
        raw = Provider()
        generation = router_mod._ProviderGeneration(
            raw,
            on_closed=lambda _generation: None,
        )
        original_callback = generation._close_finished
        callback_count = 0

        def delay_only_first_callback(task: asyncio.Task[None]) -> None:
            nonlocal callback_count
            callback_count += 1
            if callback_count > 1:
                original_callback(task)

        generation._close_finished = delay_only_first_callback

        with pytest.raises(OSError, match="SECRET first close failure"):
            await generation.aclose()
        await generation.aclose()

        assert raw.close_count == 2
        assert generation.closed

    asyncio.run(exercise())


def test_service_task_that_ignores_cancellation_cannot_block_gateway_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancellation-resistant service is reported after a hard drain bound."""

    events: list[str] = []
    target = FastAPI()

    class ProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider")

    async def exercise() -> tuple[bool, BaseException | None]:
        started = asyncio.Event()
        release = asyncio.Event()

        async def cancellation_resistant_service() -> None:
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue

        service = asyncio.create_task(cancellation_resistant_service())
        await started.wait()
        target.state.gateway_service_tasks = {service}
        target.state.background_tasks = set()
        target.state.provider_call_ledger = ProviderLedger()
        target.state.gateway_lifespan_drain_finished = False
        drain = asyncio.create_task(appmod._drain_gateway_lifespan(target))
        done, _pending = await asyncio.wait({drain}, timeout=0.2)
        completed_in_time = drain in done
        error: BaseException | None = None
        if completed_in_time:
            try:
                await drain
            except BaseException as exc:  # noqa: BLE001 - assert sanitized aggregate
                error = exc
        release.set()
        if not completed_in_time:
            await drain
        await asyncio.wait_for(service, timeout=1.0)
        return completed_in_time, error

    monkeypatch.setattr(appmod, "_GATEWAY_TASK_DRAIN_TIMEOUT_SEC", 0.02, raising=False)
    monkeypatch.setattr(appmod.local_model, "stop", lambda: None)
    monkeypatch.setattr(appmod.undo_receipts, "configure", lambda _value: None)

    completed, error = asyncio.run(exercise())

    assert completed is True
    assert isinstance(error, appmod.GatewayShutdownError)
    assert error.failed_resources == ("service_tasks",)
    assert events == ["provider"]


def test_external_drain_cancellation_still_closes_resources_then_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller cancellation cannot interrupt the bounded cleanup transaction."""

    events: list[str] = []
    target = FastAPI()

    class ProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider")

    def fail_usage_close() -> None:
        events.append("usage")
        raise OSError("SECRET usage close failure")

    async def exercise() -> None:
        started = asyncio.Event()
        cancel_seen = asyncio.Event()
        release = asyncio.Event()

        async def resistant_service() -> None:
            started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancel_seen.set()
                    continue

        service = asyncio.create_task(resistant_service())
        await started.wait()
        target.state.gateway_service_tasks = {service}
        target.state.background_tasks = set()
        target.state.provider_call_ledger = ProviderLedger()
        target.state.usage = SimpleNamespace(close=fail_usage_close)
        target.state.local_model_stop_event = threading.Event()
        target.state.gateway_lifespan_drain_finished = False
        drain = asyncio.create_task(appmod._drain_gateway_lifespan(target))
        await asyncio.wait_for(cancel_seen.wait(), timeout=1.0)
        drain.cancel()
        with pytest.raises(asyncio.CancelledError):
            await drain
        release.set()
        await asyncio.wait_for(service, timeout=1.0)

    monkeypatch.setattr(appmod, "_GATEWAY_TASK_DRAIN_TIMEOUT_SEC", 0.02)
    monkeypatch.setattr(appmod.local_model, "stop", lambda: events.append("local"))
    monkeypatch.setattr(appmod.undo_receipts, "configure", lambda _value: None)

    asyncio.run(exercise())

    assert events == ["local", "usage", "provider"]
    assert target.state.gateway_lifespan_drain_finished is True
    assert target.state.gateway_shutdown_failures == ("service_tasks", "usage")


def test_lifespan_reports_sanitized_failure_after_closing_later_resources(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    secret = "SECRET usage database path and credential"

    original_usage_close = appmod.UsageLogger.close
    original_channel_close = appmod.DurableChannelMediaRequestStore.close
    original_undo_close = appmod.UndoReceiptStore.close

    class CloseableProviderLedger(NoopProviderCallLedger):
        def close(self) -> None:
            events.append("provider_call_ledger")

    def fail_usage_close(self) -> None:  # noqa: ANN001
        events.append("usage")
        original_usage_close(self)
        raise OSError(secret)

    def close_channel(self) -> None:  # noqa: ANN001
        events.append("channel_media_requests")
        original_channel_close(self)

    def close_undo(self) -> None:  # noqa: ANN001
        events.append("undo_receipts")
        original_undo_close(self)

    monkeypatch.setattr(appmod.UsageLogger, "close", fail_usage_close)
    monkeypatch.setattr(
        appmod.DurableChannelMediaRequestStore,
        "close",
        close_channel,
    )
    monkeypatch.setattr(appmod.UndoReceiptStore, "close", close_undo)
    monkeypatch.setattr(
        appmod,
        "configured_provider_call_ledger",
        lambda: CloseableProviderLedger(),
    )
    caplog.set_level(logging.ERROR, logger="nachuan.requests")

    with pytest.raises(appmod.GatewayShutdownError) as error_info:
        with TestClient(appmod.app):
            assert appmod.app.state.channel_media_requests is not None
            assert appmod.app.state.undo_receipts is not None

    assert events == [
        "usage",
        "channel_media_requests",
        "undo_receipts",
        "provider_call_ledger",
    ]
    assert str(error_info.value) == "gateway shutdown incomplete: usage"
    assert appmod.app.state.gateway_shutdown_failures == ("usage",)
    assert secret not in str(error_info.value)
    assert secret not in caplog.text
    assert "gateway shutdown incomplete: usage" in caplog.text
