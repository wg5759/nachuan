from __future__ import annotations

import asyncio

import httpx
import pytest

from gateway import failover as failover_mod
from gateway.failover import (
    chat_once_with_deadline,
    chat_with_fallback,
    stream_with_fallback,
)
from gateway.providers.base import ProviderError, ProviderSubmissionOutcomeUnknown
from gateway.schemas import ChatCompletionRequest


@pytest.fixture(autouse=True)
def _isolate_quota_state():
    """Policy deadline tests must not leak circuit-breaker state."""
    failover_mod.quota_state.clear()
    try:
        yield
    finally:
        failover_mod.quota_state.clear()


class _PolicyClock:
    """Deterministic clock for failover policy deadlines only."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Provider:
    def __init__(self, delay: float, text: str) -> None:
        self.delay = delay
        self.text = text
        self.calls = 0

    async def chat(self, _req, _upstream):  # noqa: ANN001
        self.calls += 1
        await asyncio.sleep(self.delay)
        return {
            "choices": [{"message": {"role": "assistant", "content": self.text}}],
            "usage": {},
        }


class _Route:
    def __init__(self, provider: _Provider) -> None:
        self.provider = provider
        self.upstream_model = "test"


class _Router:
    def __init__(self, routes: dict[str, _Provider]) -> None:
        self.routes = {name: _Route(provider) for name, provider in routes.items()}

    def resolve(self, model: str):  # noqa: ANN201
        return self.routes.get(model)


def _request(model: str) -> ChatCompletionRequest:
    return ChatCompletionRequest(model=model, messages=[{"role": "user", "content": "hello"}])


async def test_attempt_budget_timeout_stops_before_next_provider(monkeypatch) -> None:
    clock = _PolicyClock()
    monkeypatch.setattr(failover_mod, "time", clock)
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["slow", "fast"])
    slow = _Provider(0.2, "late")
    fast = _Provider(0, "ok")
    router = _Router({"slow": slow, "fast": fast})

    async with asyncio.timeout(5.0):
        with pytest.raises(ProviderSubmissionOutcomeUnknown):
            await chat_with_fallback(
                router,
                _request("slow"),
                attempt_timeout=0.02,
                total_timeout=0.15,
            )

    assert slow.calls == 1
    assert fast.calls == 0


async def test_first_attempt_timeout_stops_within_the_channel_slo(monkeypatch) -> None:
    clock = _PolicyClock()
    never = asyncio.Event()

    class _AdvancingProvider:
        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            clock.advance(0.03)
            await never.wait()

    monkeypatch.setattr(failover_mod, "time", clock)
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["a", "b"])
    a = _AdvancingProvider()
    b = _AdvancingProvider()
    router = _Router({"a": a, "b": b})

    async with asyncio.timeout(5.0):
        with pytest.raises(ProviderSubmissionOutcomeUnknown):
            await chat_with_fallback(
                router,
                _request("a"),
                attempt_timeout=0.03,
                total_timeout=0.05,
            )

    assert clock.now == pytest.approx(0.03)
    assert (a.calls, b.calls) == (1, 0)


def _chunk(text: str) -> dict:
    return {
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
        "usage": {},
    }


class _StreamingProvider:
    def __init__(
        self,
        *,
        first_delay: float = 0,
        first_text: str = "ok",
        stall_after_first: bool = False,
        empty: bool = False,
    ) -> None:
        self.first_delay = first_delay
        self.first_text = first_text
        self.stall_after_first = stall_after_first
        self.empty = empty
        self.started = asyncio.Event()
        self.closed = asyncio.Event()

    async def stream(self, _req, _upstream):  # noqa: ANN001
        self.started.set()
        try:
            await asyncio.sleep(self.first_delay)
            if self.empty:
                return
            yield _chunk(self.first_text)
            if self.stall_after_first:
                await asyncio.Event().wait()
        finally:
            self.closed.set()


async def test_slow_first_chunk_stops_and_closes_stream_without_replay(monkeypatch) -> None:
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["slow", "fast"])
    slow = _StreamingProvider(first_delay=1, first_text="late")
    fast = _StreamingProvider(first_text="backup")
    router = _Router({"slow": slow, "fast": fast})

    async with asyncio.timeout(5.0):
        chunks = [
            chunk
            async for chunk in stream_with_fallback(
                router,
                _request("slow"),
                attempt_timeout=0.08,
                first_chunk_timeout=0.02,
                idle_chunk_timeout=0.05,
                total_timeout=0.2,
            )
        ]

    assert len(chunks) == 1
    assert chunks[0]["error"]["type"] == "provider_error"
    assert slow.closed.is_set()
    assert not fast.started.is_set()


async def test_primary_stream_freezes_full_route_receipt_and_drops_provider_spoof(
    monkeypatch,
) -> None:
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary"])

    class Provider:
        def __init__(self) -> None:
            self.name = "provider-before-reload"
            self.route = None

        async def stream(self, _req, _upstream):  # noqa: ANN001
            # Simulate an unsafe in-place hot reload while the provider is
            # producing its first token.  Attribution must already be frozen.
            self.name = "provider-after-reload"
            self.route.upstream_model = "upstream-after-reload"
            self.route.tier = "cheap"
            yield _chunk("first")
            spoofed = _chunk("second")
            spoofed["_served_by"] = {
                "requested": "primary",
                "actual": "attacker-model",
                "provider": "attacker-provider",
            }
            yield spoofed

    provider = Provider()
    router = _Router({"primary": provider})
    route = router.routes["primary"]
    route.upstream_model = "upstream-before-reload"
    route.tier = "premium"
    provider.route = route

    chunks = await _collect_stream(router, _request("primary"))

    assert chunks[0]["_served_by"] == {
        "route_receipt_version": 1,
        "requested": "primary",
        "actual": "primary",
        "provider": "provider-before-reload",
        "upstream_model": "upstream-before-reload",
        "tier": "premium",
    }
    assert "_served_by" not in chunks[1]


async def test_empty_primary_stream_stops_without_replay(monkeypatch) -> None:
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["empty", "backup"])
    empty = _StreamingProvider(empty=True)
    backup = _StreamingProvider(first_text="after-empty")
    router = _Router({"empty": empty, "backup": backup})

    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            router,
            _request("empty"),
            attempt_timeout=0.1,
            first_chunk_timeout=0.05,
            idle_chunk_timeout=0.05,
            total_timeout=0.2,
        )
    ]
    assert len(chunks) == 1
    assert chunks[0]["error"]["type"] == "provider_error"
    assert empty.closed.is_set()
    assert not backup.started.is_set()

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["only-empty"])
    all_empty = _StreamingProvider(empty=True)
    terminal = [
        chunk
        async for chunk in stream_with_fallback(
            _Router({"only-empty": all_empty}),
            _request("only-empty"),
            attempt_timeout=0.1,
            first_chunk_timeout=0.05,
            idle_chunk_timeout=0.05,
            total_timeout=0.2,
        )
    ]
    assert len(terminal) == 1
    assert terminal[0]["error"]["type"] == "provider_error"


async def test_stall_after_first_chunk_emits_error_without_replaying_from_backup(monkeypatch) -> None:
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary", "backup"])
    primary = _StreamingProvider(first_text="once", stall_after_first=True)
    backup = _StreamingProvider(first_text="must-not-run")
    router = _Router({"primary": primary, "backup": backup})

    async with asyncio.timeout(5.0):
        chunks = [
            chunk
            async for chunk in stream_with_fallback(
                router,
                _request("primary"),
                attempt_timeout=0.1,
                first_chunk_timeout=0.05,
                idle_chunk_timeout=0.02,
                total_timeout=0.2,
            )
        ]

    text_chunks = [c for c in chunks if c.get("choices")]
    assert [c["choices"][0]["delta"]["content"] for c in text_chunks] == ["once"]
    assert chunks[-1]["error"]["type"] == "stream_idle_timeout"
    assert not backup.started.is_set()
    assert primary.closed.is_set()


async def test_stream_attempt_budget_only_caps_precommit_not_active_output(monkeypatch) -> None:
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary"])
    closed = asyncio.Event()
    clock = 0.0

    class _Clock:
        @staticmethod
        def monotonic() -> float:
            return clock

    # Keep asyncio.wait_for on the real event-loop clock, but make the
    # failover policy clock deterministic.  Advancing it after commit proves
    # that the pre-commit attempt deadline is no longer consulted without
    # relying on sub-100ms sleeps that become flaky under full-suite load.
    monkeypatch.setattr(failover_mod, "time", _Clock)

    class _ContinuousProvider:
        async def stream(self, _req, _upstream):  # noqa: ANN001
            nonlocal clock
            try:
                yield _chunk("tick")
                for _ in range(5):
                    clock += 0.2  # past attempt_timeout after the first chunk
                    yield _chunk("tick")
            finally:
                closed.set()

    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router({"primary": _ContinuousProvider()}),
            _request("primary"),
            attempt_timeout=0.12,
            first_chunk_timeout=1,
            idle_chunk_timeout=1,
            total_timeout=10,
        )
    ]

    assert len([chunk for chunk in chunks if chunk.get("choices")]) == 6
    assert not any(chunk.get("error") for chunk in chunks)
    assert closed.is_set()


async def test_stream_consumer_cancellation_closes_provider_and_propagates(monkeypatch) -> None:
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary"])
    primary = _StreamingProvider(first_text="first", stall_after_first=True)
    router = _Router({"primary": primary})
    got_first = asyncio.Event()

    async def consume() -> None:
        async for chunk in stream_with_fallback(
            router,
            _request("primary"),
            attempt_timeout=1,
            first_chunk_timeout=1,
            idle_chunk_timeout=1,
            total_timeout=2,
        ):
            if chunk.get("choices"):
                got_first.set()

    task = asyncio.create_task(consume())
    try:
        async with asyncio.timeout(5.0):
            await got_first.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await primary.closed.wait()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_nonstream_none_timeouts_still_use_mandatory_defaults(monkeypatch) -> None:
    clock = _PolicyClock()
    never = asyncio.Event()
    calls: list[str] = []

    class _AdvancingProvider:
        def __init__(self, name: str) -> None:
            self.name = name

        async def chat(self, _req, _upstream):  # noqa: ANN001
            calls.append(self.name)
            clock.advance(0.025)
            await never.wait()

    monkeypatch.setattr(failover_mod, "time", clock)
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["a", "b"])
    monkeypatch.setattr(failover_mod, "DEFAULT_ATTEMPT_TIMEOUT_SEC", 0.02, raising=False)
    monkeypatch.setattr(failover_mod, "DEFAULT_TOTAL_TIMEOUT_SEC", 0.05, raising=False)
    router = _Router({"a": _AdvancingProvider("a"), "b": _AdvancingProvider("b")})

    async with asyncio.timeout(5.0):
        with pytest.raises(ProviderSubmissionOutcomeUnknown):
            await chat_with_fallback(router, _request("a"))

    assert calls == ["a"]
    assert clock.now == pytest.approx(0.025)


async def test_chat_once_default_total_uses_nonstream_contract(monkeypatch) -> None:
    started = asyncio.Event()
    closed = asyncio.Event()

    class _NeverReturningProvider:
        async def chat(self, _req, _upstream):  # noqa: ANN001
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                closed.set()

    monkeypatch.setattr(failover_mod, "DEFAULT_ATTEMPT_TIMEOUT_SEC", 0.2, raising=False)
    monkeypatch.setattr(failover_mod, "DEFAULT_TOTAL_TIMEOUT_SEC", 0.01, raising=False)
    monkeypatch.setattr(
        failover_mod, "DEFAULT_STREAM_TOTAL_TIMEOUT_SEC", 0.2, raising=False
    )

    async with asyncio.timeout(5.0):
        with pytest.raises(asyncio.TimeoutError):
            await chat_once_with_deadline(
                _NeverReturningProvider(),
                _request("single"),
                "single-upstream",
            )

    assert started.is_set()
    assert closed.is_set()


async def test_stream_none_timeouts_still_use_mandatory_defaults(monkeypatch) -> None:
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["slow", "fast"])
    monkeypatch.setattr(
        failover_mod, "DEFAULT_STREAM_ATTEMPT_TIMEOUT_SEC", 0.04, raising=False
    )
    monkeypatch.setattr(
        failover_mod, "DEFAULT_STREAM_TOTAL_TIMEOUT_SEC", 0.08, raising=False
    )
    monkeypatch.setattr(failover_mod, "DEFAULT_FIRST_CHUNK_TIMEOUT_SEC", 0.01, raising=False)
    monkeypatch.setattr(failover_mod, "DEFAULT_IDLE_CHUNK_TIMEOUT_SEC", 0.02, raising=False)
    slow = _StreamingProvider(first_delay=1, first_text="late")
    fast = _StreamingProvider(first_text="default-bounded")

    async with asyncio.timeout(5.0):
        chunks = await _collect_stream(
            _Router({"slow": slow, "fast": fast}), _request("slow")
        )

    assert len(chunks) == 1
    assert chunks[0]["error"]["type"] == "provider_error"
    assert slow.closed.is_set()
    assert not fast.started.is_set()


async def test_stream_default_total_uses_long_stream_contract(monkeypatch) -> None:
    clock = _PolicyClock()
    waiting_for_second = asyncio.Event()
    allow_second = asyncio.Event()

    class TwoChunkProvider:
        async def stream(self, _req, _upstream):  # noqa: ANN001
            yield _chunk("first")
            waiting_for_second.set()
            await allow_second.wait()
            yield _chunk("second")

    monkeypatch.setattr(failover_mod, "time", clock)
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary"])
    monkeypatch.setattr(failover_mod, "DEFAULT_TOTAL_TIMEOUT_SEC", 0.01, raising=False)
    monkeypatch.setattr(
        failover_mod, "DEFAULT_STREAM_TOTAL_TIMEOUT_SEC", 0.2, raising=False
    )
    monkeypatch.setattr(
        failover_mod, "DEFAULT_STREAM_ATTEMPT_TIMEOUT_SEC", 0.2, raising=False
    )
    monkeypatch.setattr(failover_mod, "DEFAULT_FIRST_CHUNK_TIMEOUT_SEC", 0.1, raising=False)
    monkeypatch.setattr(failover_mod, "DEFAULT_IDLE_CHUNK_TIMEOUT_SEC", 0.1, raising=False)

    task = asyncio.create_task(
        _collect_stream(
            _Router({"primary": TwoChunkProvider()}),
            _request("primary"),
        )
    )
    try:
        async with asyncio.timeout(5.0):
            await waiting_for_second.wait()
            clock.advance(0.05)
            allow_second.set()
            chunks = await task
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    assert [
        chunk["choices"][0]["delta"]["content"]
        for chunk in chunks
        if chunk.get("choices")
    ] == ["first", "second"]


async def test_stream_precommit_timeout_stops_before_alternate_route(monkeypatch) -> None:
    clock = _PolicyClock()
    never = asyncio.Event()

    class _SpendingProvider:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.closed = asyncio.Event()

        async def stream(self, _req, _upstream):  # noqa: ANN001
            self.started.set()
            try:
                clock.advance(0.05)
                await never.wait()
                yield _chunk("late")
            finally:
                self.closed.set()

    monkeypatch.setattr(failover_mod, "time", clock)
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["a", "b"])
    a = _SpendingProvider()
    b = _StreamingProvider(first_delay=1)

    async with asyncio.timeout(5.0):
        chunks = [
            chunk
            async for chunk in stream_with_fallback(
                _Router({"a": a, "b": b}),
                _request("a"),
                attempt_timeout=0.1,
                first_chunk_timeout=0.04,
                idle_chunk_timeout=0.04,
                total_timeout=0.05,
            )
        ]

    assert chunks[-1]["error"]["type"] == "provider_error"
    assert clock.now == pytest.approx(0.05)
    assert a.closed.is_set()
    assert not b.started.is_set()


async def _collect_stream(router: _Router, req: ChatCompletionRequest) -> list[dict]:
    return [chunk async for chunk in stream_with_fallback(router, req)]


async def test_safe_connect_fallback_does_not_mutate_provider_result(monkeypatch) -> None:
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["slow", "backup"])
    original = {
        "choices": [{"message": {"role": "assistant", "content": "backup"}}],
        "usage": {},
    }

    class Slow:
        async def chat(self, _req, _upstream):  # noqa: ANN001
            raise httpx.ConnectError(
                "connection refused",
                request=httpx.Request("POST", "https://provider.test/v1/chat"),
            )

    class Backup:
        async def chat(self, _req, _upstream):  # noqa: ANN001
            return original

    async with asyncio.timeout(5.0):
        result, served, _route = await chat_with_fallback(
            _Router({"slow": Slow(), "backup": Backup()}),
            _request("slow"),
            attempt_timeout=0.1,
            total_timeout=0.2,
        )

    assert served == "backup"
    assert result["_served_by"] == {"requested": "slow", "actual": "backup"}
    assert "_served_by" not in original


async def test_safe_stream_connect_fallback_does_not_mutate_first_chunk(monkeypatch) -> None:
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["empty", "backup"])
    original = _chunk("immutable")

    class Empty:
        async def stream(self, _req, _upstream):  # noqa: ANN001
            if False:
                yield {}
            raise httpx.ConnectError(
                "connection refused",
                request=httpx.Request("POST", "https://provider.test/v1/chat"),
            )

    class Backup:
        async def stream(self, _req, _upstream):  # noqa: ANN001
            yield original

    chunks = await _collect_stream(
        _Router({"empty": Empty(), "backup": Backup()}), _request("empty")
    )

    assert chunks[0]["_served_by"] == {
        "route_receipt_version": 1,
        "requested": "empty",
        "actual": "backup",
        "provider": "",
        "upstream_model": "test",
        "tier": "",
    }
    assert "_served_by" not in original


async def test_postcommit_total_timeout_is_local_policy_not_provider_failure(
    monkeypatch,
) -> None:
    clock = _PolicyClock()
    marks: list[str] = []
    monkeypatch.setattr(failover_mod, "time", clock)
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary"])
    monkeypatch.setattr(failover_mod.quota_state, "mark_ok", lambda *_: None)
    monkeypatch.setattr(
        failover_mod.quota_state, "mark_error", lambda model: marks.append(model)
    )
    provider = _StreamingProvider(first_text="first", stall_after_first=True)

    stream = stream_with_fallback(
        _Router({"primary": provider}),
        _request("primary"),
        attempt_timeout=0.1,
        first_chunk_timeout=0.05,
        idle_chunk_timeout=0.2,
        total_timeout=0.03,
    )
    try:
        async with asyncio.timeout(5.0):
            first = await anext(stream)
            clock.advance(0.04)
            terminal = await anext(stream)
            with pytest.raises(StopAsyncIteration):
                await anext(stream)
    finally:
        await stream.aclose()

    assert first["choices"][0]["delta"]["content"] == "first"
    assert terminal["error"]["type"] == "stream_total_timeout"
    assert marks == []
    assert provider.closed.is_set()


@pytest.mark.parametrize("failure", ["idle", "provider"])
async def test_postcommit_upstream_failures_still_feed_the_breaker(
    monkeypatch, failure
) -> None:
    marks: list[str] = []
    monkeypatch.setattr(failover_mod, "time", _PolicyClock())
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_: ["primary"])
    monkeypatch.setattr(failover_mod.quota_state, "mark_ok", lambda *_: None)
    monkeypatch.setattr(
        failover_mod.quota_state, "mark_error", lambda model: marks.append(model)
    )
    monkeypatch.setattr(failover_mod.quota_state, "mark_if_quota", lambda *_: False)

    if failure == "idle":
        provider = _StreamingProvider(first_text="first", stall_after_first=True)
        expected = "stream_idle_timeout"
    else:
        class ProviderFailure:
            async def stream(self, _req, _upstream):  # noqa: ANN001
                yield _chunk("first")
                raise ProviderError("upstream failed", status_code=502)

        provider = ProviderFailure()
        expected = "provider_error"

    async with asyncio.timeout(5.0):
        chunks = [
            chunk
            async for chunk in stream_with_fallback(
                _Router({"primary": provider}),
                _request("primary"),
                attempt_timeout=0.1,
                first_chunk_timeout=0.05,
                idle_chunk_timeout=0.01,
                total_timeout=0.2,
            )
        ]

    assert chunks[-1]["error"]["type"] == expected
    assert marks == ["primary"]
