"""失败转移：备用链 + 主模型失败自动转备用。"""

from __future__ import annotations

import asyncio
import pytest

from gateway.failover import (
    FALLBACKS,
    chat_with_fallback,
    fallback_chain,
    stream_with_fallback,
)
from gateway.providers.base import ProviderError, ProviderSubmissionOutcomeUnknown
from gateway.schemas import ChatCompletionRequest


@pytest.fixture(autouse=True)
def _isolate_quota_state():
    """Failover tests must not cool models used by later test modules."""
    from gateway import quota_state

    quota_state.clear()
    try:
        yield
    finally:
        quota_state.clear()


def test_fallback_chain():
    chain = fallback_chain("glm")
    assert chain[0] == "glm"
    assert "agnes-flash" in chain  # 火山→Agnes 备用
    assert fallback_chain("unknown-model") == ["unknown-model"]


def test_automatic_fallback_roster_contains_no_claude_route():
    configured_routes = [*FALLBACKS, *(item for chain in FALLBACKS.values() for item in chain)]
    assert all("claude" not in route.casefold() for route in configured_routes)
    assert fallback_chain("gpt-5.5") == ["gpt-5.5", "gpt-5.4"]
    assert fallback_chain("gpt-5.4") == ["gpt-5.4", "gpt-5.4-mini"]


class _Prov:
    def __init__(self, name: str, fail: bool = False):
        self.name = name
        self.fail = fail
        self.calls = 0

    async def chat(self, req, upstream):
        self.calls += 1
        if self.fail:
            raise ProviderError("quota exhausted", status_code=429)
        return {"choices": [{"message": {"content": f"from {self.name}"}}], "usage": {}}


class _Route:
    def __init__(self, prov: _Prov):
        self.provider = prov
        self.upstream_model = "u"
        self.tier = "t"
        self.virtual_model = "x"


class _Router:
    def __init__(self, routes: dict):
        self._r = routes

    def resolve(self, m: str):
        return self._r.get(m)


def _req(model: str) -> ChatCompletionRequest:
    return ChatCompletionRequest(model=model, messages=[{"role": "user", "content": "hi"}])


async def test_error_circuit_breaker_cools_down_after_consecutive_failures():
    """通用熔断：非额度失败（CLI超时/挂死）连续 2 次 → 冷却，选将/兜底跳过；成功清计数。
    机主实测灾难回归：claude CLI 180s 超时被编排反复撞 15 分钟——熔断后第 2 次就让路。"""
    from gateway import quota_state

    quota_state.clear()
    mid = "cli-hang-model"
    quota_state.mark_error(mid)  # 第 1 次失败：仅计数
    assert quota_state.available(mid)
    quota_state.mark_error(mid)  # 第 2 次连续失败：熔断
    assert not quota_state.available(mid)
    assert quota_state.cooldown_left(mid) > 60
    quota_state.clear(mid)
    # 成功清零：失败1次→成功→再失败1次 = 不熔断（防偶发抖动累积）
    quota_state.mark_error(mid)
    quota_state.mark_ok(mid)
    quota_state.mark_error(mid)
    assert quota_state.available(mid)
    quota_state.clear()


async def test_chat_unknown_provider_failure_marks_error_without_replay():
    """普通上游失败按结果未知停止，同时仍累计熔断计数。"""
    from gateway import quota_state

    quota_state.clear()

    class _HangProv(_Prov):
        async def chat(self, req, upstream):
            raise ProviderError("claude CLI 超时（180.0s）")  # 非 429，模拟 CLI 挂死

    backup = _Prov("agnes")
    router = _Router({"glm": _Route(_HangProv("hang")), "agnes-flash": _Route(backup)})
    try:
        with pytest.raises(ProviderSubmissionOutcomeUnknown):
            await chat_with_fallback(router, _req("glm"))
        assert quota_state.available("glm")
        with pytest.raises(ProviderSubmissionOutcomeUnknown):
            await chat_with_fallback(router, _req("glm"))
        assert not quota_state.available("glm")
        assert backup.calls == 0
    finally:
        quota_state.clear()


async def test_provider_429_after_invocation_stops_before_backup():
    # HTTP 429 是供应商响应，不证明请求未执行或未计费，不能猜测性重放。
    from gateway import quota_state

    quota_state.clear()
    backup = _Prov("agnes")
    router = _Router(
        {"glm": _Route(_Prov("volcano", fail=True)), "agnes-flash": _Route(backup)}
    )
    try:
        with pytest.raises(ProviderSubmissionOutcomeUnknown):
            await chat_with_fallback(router, _req("glm"))
        assert backup.calls == 0
    finally:
        quota_state.clear()


async def test_failover_all_fail_raises():
    router = _Router({"glm": _Route(_Prov("volcano", fail=True))})
    with pytest.raises(ProviderError):
        await chat_with_fallback(router, _req("glm"))


async def test_chat_uses_bounded_provider_declared_timeout_without_changing_defaults(
    monkeypatch,
):
    from gateway import failover

    class Attempt:
        call_id = "test-call"

    async def resolve_ledger(_ledger):
        return object()

    async def start_attempt(*_args, **_kwargs):
        return Attempt()

    async def finish_attempt(*_args, **_kwargs):
        return True

    monkeypatch.setattr(failover, "resolve_provider_call_ledger_durable", resolve_ledger)
    monkeypatch.setattr(failover, "start_provider_attempt_durable", start_attempt)
    monkeypatch.setattr(failover, "finish_provider_attempt_durable", finish_attempt)

    class Provider(_Prov):
        chat_timeout_s = 0.1

        async def chat(self, req, upstream):
            self.calls += 1
            await asyncio.sleep(0.04)
            return {
                "choices": [{"message": {"content": "from subscription"}}],
                "usage": {},
            }

    monkeypatch.setattr(failover, "DEFAULT_ATTEMPT_TIMEOUT_SEC", 0.01)
    monkeypatch.setattr(failover, "DEFAULT_TOTAL_TIMEOUT_SEC", 0.02)
    provider = Provider("subscription")
    result, served, _route = await chat_with_fallback(
        _Router({"subscription-model": _Route(provider)}),
        _req("subscription-model"),
    )

    assert result["choices"][0]["message"]["content"] == "from subscription"
    assert served == "subscription-model"
    assert provider.calls == 1


@pytest.mark.parametrize(
    ("declared", "explicit_attempt", "explicit_total"),
    [
        (None, None, None),
        (180.0, None, None),
        (180.0, 0.5, 0.7),
        (True, None, None),
        (301.0, None, None),
    ],
)
def test_chat_timeout_budget_contract_is_bounded_and_explicit_values_win(
    declared,
    explicit_attempt,
    explicit_total,
):
    from gateway import failover

    class Provider:
        chat_timeout_s = declared

    route = _Route(Provider())
    attempt = failover._provider_chat_attempt_budget(
        route.provider,
        explicit_attempt,
    )
    total = failover._provider_chat_total_budget(
        route.provider,
        explicit_total,
    )

    expected_declared = declared if type(declared) in {int, float} and declared <= 300 else None
    assert attempt == (
        explicit_attempt
        if explicit_attempt is not None
        else expected_declared or failover.DEFAULT_ATTEMPT_TIMEOUT_SEC
    )
    assert total == (
        explicit_total
        if explicit_total is not None
        else max(
            failover.DEFAULT_TOTAL_TIMEOUT_SEC,
            expected_declared + failover._DECLARED_CHAT_TOTAL_GRACE_SEC
            if expected_declared
            else failover.DEFAULT_TOTAL_TIMEOUT_SEC,
        )
    )


async def test_stream_uses_bounded_provider_declared_first_chunk_timeout(
    monkeypatch,
):
    from gateway import failover

    class Attempt:
        call_id = "stream-test-call"

    async def resolve_ledger(_ledger):
        return object()

    async def start_attempt(*_args, **_kwargs):
        return Attempt()

    async def finish_attempt(*_args, **_kwargs):
        return True

    monkeypatch.setattr(failover, "resolve_provider_call_ledger_durable", resolve_ledger)
    monkeypatch.setattr(failover, "start_provider_attempt_durable", start_attempt)
    monkeypatch.setattr(failover, "finish_provider_attempt_durable", finish_attempt)

    class Provider:
        name = "subscription"
        stream_attempt_timeout_s = 0.1
        stream_first_chunk_timeout_s = 0.1
        stream_total_timeout_s = 0.2

        async def stream(self, req, upstream):
            await asyncio.sleep(0.04)
            yield {
                "model": req.model,
                "choices": [{"delta": {"content": "hello"}}],
            }

    monkeypatch.setattr(failover, "DEFAULT_STREAM_ATTEMPT_TIMEOUT_SEC", 0.01)
    monkeypatch.setattr(failover, "DEFAULT_STREAM_TOTAL_TIMEOUT_SEC", 0.02)
    monkeypatch.setattr(failover, "DEFAULT_FIRST_CHUNK_TIMEOUT_SEC", 0.01)
    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router({"subscription-model": _Route(Provider())}),
            _req("subscription-model"),
        )
    ]

    assert len(chunks) == 1
    assert chunks[0]["choices"][0]["delta"]["content"] == "hello"


class _SSLProv(_Prov):
    """模拟裸 ssl.SSLError 穿透 provider（大图 payload 过代理 TLS 记录损坏——机主实测舰队编排直接炸）。"""

    async def chat(self, req, upstream):
        import ssl

        raise ssl.SSLError(1, "[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC] decryption failed or bad record mac")


async def test_raw_ssl_error_after_invocation_stops_before_backup():
    # SSL 错可能发生在请求字节写出之后；没有阶段证明时按提交结果未知处理。
    backup = _Prov("agnes")
    router = _Router(
        {"glm": _Route(_SSLProv("volcano")), "agnes-flash": _Route(backup)}
    )
    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(router, _req("glm"))
    assert backup.calls == 0


async def test_raw_ssl_error_is_sanitized_as_submission_unknown():
    # 不向调用者泄漏裸 SSL 细节，也不把阶段未知的错误伪装成可安全重试。
    router = _Router({"glm": _Route(_SSLProv("volcano"))})
    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(router, _req("glm"))


def test_long_input_prefers_chatgpt():
    """超长输入 → 备用链优先 ChatGPT（额度/上下文最大）；短输入不触发。"""
    from gateway.failover import GPT_BACKUP, LONG_INPUT_CHARS

    long_req = ChatCompletionRequest(
        model="agnes-flash", messages=[{"role": "user", "content": "x" * (LONG_INPUT_CHARS + 1)}]
    )
    assert fallback_chain("agnes-flash", long_req)[0] == GPT_BACKUP
    assert fallback_chain("agnes-flash", _req("agnes-flash"))[0] == "agnes-flash"  # 短输入不转
