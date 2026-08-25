"""Provider 单元测试：echo 直测 + OpenAI 兼容上游（用 respx 模拟 httpx）。"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from gateway import quota_state
from gateway.failover import chat_with_fallback
from gateway.providers.base import ProviderError
from gateway.providers.echo import EchoProvider
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import ChatCompletionRequest

UPSTREAM = "https://up.example/v1"


def _req(model: str = "m", stream: bool = False) -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model=model,
        messages=[{"role": "user", "content": "hi"}],
        stream=stream,
    )


def test_provider_error_accepts_only_closed_ledger_error_type() -> None:
    accepted = ProviderError(
        "public",
        ledger_error_type="KimiSubscriptionProviderError.agent_rpc_error",
    )
    rejected = ProviderError(
        "public",
        ledger_error_type="PRIVATE PROMPT sk-live-must-not-persist",
    )

    assert accepted.ledger_error_type == (
        "KimiSubscriptionProviderError.agent_rpc_error"
    )
    assert rejected.ledger_error_type is None


async def test_echo_provider_chat():
    out = await EchoProvider().chat(_req(model="echo"), "echo")
    assert out["choices"][0]["message"]["content"].startswith("[echo:echo]")
    assert out["usage"]["total_tokens"] > 0


@respx.mock
async def test_openai_compat_chat_swaps_model():
    route = respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "x",
                "object": "chat.completion",
                "model": "up",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "hello"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )
    )
    p = OpenAICompatProvider(name="t", base_url=UPSTREAM, api_key="k")
    out = await p.chat(_req(), "up")
    assert out["choices"][0]["message"]["content"] == "hello"
    sent = json.loads(route.calls.last.request.content)
    assert sent["model"] == "up"  # 虚拟名被替换成上游模型
    assert sent["stream"] is False
    await p.aclose()


@respx.mock
async def test_openai_compat_stream_parses_chunks():
    sse = (
        'data: {"choices":[{"delta":{"content":"he"}}]}\n\n'
        'data: {"choices":[{"delta":{"content":"llo"}}]}\n\n'
        'data: {"choices":[{"delta":{}}],"usage":{"total_tokens":3}}\n\n'
        "data: [DONE]\n\n"
    )
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
    )
    p = OpenAICompatProvider(name="t", base_url=UPSTREAM, api_key="k")
    chunks = [c async for c in p.stream(_req(stream=True), "up")]
    text = "".join(
        c["choices"][0]["delta"].get("content", "") for c in chunks if c.get("choices")
    )
    assert text == "hello"
    assert any(c.get("usage") for c in chunks)
    await p.aclose()


@respx.mock
async def test_openai_compat_error_maps_status():
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(429, text="rate limited")
    )
    p = OpenAICompatProvider(name="t", base_url=UPSTREAM, api_key="k")
    with pytest.raises(ProviderError) as ei:
        await p.chat(_req(), "up")
    assert ei.value.status_code == 429
    await p.aclose()


@respx.mock
async def test_openai_compat_invalid_json_is_sanitized_provider_502():
    """HTTP 200 非 JSON 必须成为脱敏的 provider 502，不能泄露响应体。"""

    secret_body = "<html>upstream secret token: should-not-leak</html>"
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            text=secret_body,
            headers={"content-type": "text/html"},
        )
    )
    p = OpenAICompatProvider(name="t", base_url=UPSTREAM, api_key="k")
    try:
        with pytest.raises(ProviderError) as exc_info:
            await p.chat(_req(), "up")
    finally:
        await p.aclose()

    assert exc_info.value.status_code == 502
    assert "无效 JSON" in str(exc_info.value)
    assert "should-not-leak" not in str(exc_info.value)


@respx.mock
@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"debug_secret": "should-not-leak"},
        {"choices": []},
        {"choices": [{}]},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": "   "}}]},
    ],
)
async def test_openai_compat_invalid_chat_schema_is_sanitized_provider_502(payload):
    """可解析 JSON 仍须满足聊天响应合同，否则统一按脱敏 provider 502 处理。"""

    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(200, json=payload)
    )
    p = OpenAICompatProvider(name="t", base_url=UPSTREAM, api_key="k")
    try:
        with pytest.raises(ProviderError) as exc_info:
            await p.chat(_req(), "up")
    finally:
        await p.aclose()

    assert exc_info.value.status_code == 502
    assert str(exc_info.value) == "上游返回了无效聊天响应"
    assert "should-not-leak" not in str(exc_info.value)


@respx.mock
async def test_openai_compat_accepts_tool_calls_without_text_content():
    """工具调用是合法的 assistant 输出，即使 content 为 null 也必须保留。"""

    payload = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": "{}"},
                        }
                    ],
                }
            }
        ]
    }
    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(200, json=payload)
    )
    p = OpenAICompatProvider(name="t", base_url=UPSTREAM, api_key="k")
    try:
        result = await p.chat(_req(), "up")
    finally:
        await p.aclose()

    assert result == payload


@respx.mock
@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        ("<html>temporary upstream error</html>", "text/html"),
        ("{}", "application/json"),
    ],
)
async def test_openai_compat_invalid_success_stops_before_backup(body, content_type):
    """A 200 invalid payload may follow an accepted POST, so never replay it."""

    respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            text=body,
            headers={"content-type": content_type},
        )
    )
    primary = OpenAICompatProvider(name="primary", base_url=UPSTREAM, api_key="k")

    class Backup:
        calls = 0

        async def chat(self, _request, _upstream_model):
            self.calls += 1
            return {
                "choices": [{"message": {"content": "backup answer"}}],
                "usage": {},
            }

    backup = Backup()

    class Router:
        @staticmethod
        def resolve(model):
            provider = {
                "glm": primary,
                "agnes-flash": backup,
            }.get(model)
            if provider is None:
                return None
            return type(
                "Route",
                (),
                {
                    "provider": provider,
                    "upstream_model": model,
                    "virtual_model": model,
                    "tier": "test",
                },
            )()

    quota_state.clear()
    try:
        with pytest.raises(ProviderError):
            await chat_with_fallback(Router(), _req(model="glm"))
    finally:
        quota_state.clear()
        await primary.aclose()

    assert backup.calls == 0


@respx.mock
async def test_openai_compat_first_invalid_success_stops_as_sanitized_provider_502():
    """第一个 HTTP 200 非法响应即停止，避免备用链重复执行并保持脱敏。"""

    upstream = respx.post(f"{UPSTREAM}/chat/completions").mock(
        return_value=httpx.Response(
            200,
            text="<html>private upstream diagnostics: should-not-leak</html>",
            headers={"content-type": "text/html"},
        )
    )
    provider = OpenAICompatProvider(name="invalid", base_url=UPSTREAM, api_key="k")

    class Router:
        @staticmethod
        def resolve(model):
            if model not in {"glm", "agnes-flash"}:
                return None
            return type(
                "Route",
                (),
                {
                    "provider": provider,
                    "upstream_model": model,
                    "virtual_model": model,
                    "tier": "test",
                },
            )()

    quota_state.clear()
    try:
        with pytest.raises(ProviderError) as exc_info:
            await chat_with_fallback(Router(), _req(model="glm"))
    finally:
        quota_state.clear()
        await provider.aclose()

    assert upstream.call_count == 1
    assert exc_info.value.status_code == 502
    assert str(exc_info.value) == "上游返回了无效 JSON"
    assert "should-not-leak" not in str(exc_info.value)


# ── 视频瞬时错重试（Agnes 海外抖动多；照 agnes.py 已验证写法）──────────────────
import gateway.providers.openai_compat as oc  # noqa: E402


@pytest.fixture()
def _no_sleep(monkeypatch):
    """把 asyncio.sleep 换成记录用的 no-op，重试不真等，并能断言退避时序。"""
    slept: list[float] = []

    async def fake_sleep(s):  # noqa: ANN001
        slept.append(float(s))

    monkeypatch.setattr(oc.asyncio, "sleep", fake_sleep)
    return slept


@respx.mock
async def test_get_video_retries_network_then_502_then_ok(_no_sleep):
    """网络瞬时错 + 502/503/504 → 重试(退避 1→2→4→8s)，最终成功。"""
    respx.get(f"{UPSTREAM}/videos/tid").mock(
        side_effect=[
            httpx.ConnectError("boom"),
            httpx.Response(503, text="busy"),
            httpx.Response(200, json={"status": "completed", "url": "http://x/v.mp4"}),
        ]
    )
    p = OpenAICompatProvider(name="agnes", base_url=UPSTREAM, api_key="k")
    out = await p.get_video("tid")
    assert out["status"] == "completed"
    assert _no_sleep == [1.0, 2.0]  # ConnectError→1s，503→2s（共用退避预算）
    await p.aclose()


@respx.mock
async def test_generate_video_does_not_retry_ambiguous_post_timeout(_no_sleep):
    """非幂等视频 POST 超时后结果未知；没有可靠幂等键时绝不自动重发。"""
    route = respx.post(f"{UPSTREAM}/videos").mock(
        side_effect=[
            httpx.ReadTimeout("slow"),
            httpx.Response(200, json={"task_id": "v-1"}),
        ]
    )
    from gateway.schemas import VideoGenerationRequest

    p = OpenAICompatProvider(name="agnes", base_url=UPSTREAM, api_key="k")
    with pytest.raises(ProviderError, match="结果未知.*禁止自动重试"):
        await p.generate_video(
            VideoGenerationRequest(model="agnes-video", prompt="cat"),
            "agnes-video-v2.0",
        )
    assert route.call_count == 1
    assert _no_sleep == []
    await p.aclose()


@respx.mock
async def test_get_video_4xx_not_retried(_no_sleep):
    """401/400 等 4xx（鉴权/参数错）→ 立刻抛，绝不重试（白重试）。"""
    route = respx.get(f"{UPSTREAM}/videos/tid").mock(return_value=httpx.Response(401, text="unauthorized"))
    p = OpenAICompatProvider(name="agnes", base_url=UPSTREAM, api_key="k")
    with pytest.raises(ProviderError) as ei:
        await p.get_video("tid")
    assert ei.value.status_code == 401
    assert route.call_count == 1  # 只调一次，没重试
    assert _no_sleep == []        # 没退避
    await p.aclose()


@respx.mock
async def test_get_video_429_slow_waits_then_raises(_no_sleep):
    """429 = Agnes 限流 → ≥13s 慢等、和网络错分开；一直 429 则慢等满次数后透传报错。"""
    route = respx.get(f"{UPSTREAM}/videos/tid").mock(return_value=httpx.Response(429, text="rate limit"))
    p = OpenAICompatProvider(name="agnes", base_url=UPSTREAM, api_key="k")
    with pytest.raises(ProviderError) as ei:
        await p.get_video("tid")
    assert ei.value.status_code == 429
    # 慢等 _VIDEO_RATELIMIT_TRIES 次、每次 ≥13s（绝不快重试）；总调用 = 首次 + 重试次数
    assert _no_sleep == [13.0] * oc._VIDEO_RATELIMIT_TRIES
    assert all(s >= 13.0 for s in _no_sleep)
    assert route.call_count == oc._VIDEO_RATELIMIT_TRIES + 1
    await p.aclose()


@respx.mock
async def test_get_video_429_then_ok(_no_sleep):
    """429 一次后放行 → 慢等 13s 再试即成功（RPM 突发能过）。"""
    respx.get(f"{UPSTREAM}/videos/tid").mock(
        side_effect=[
            httpx.Response(429, text="rate limit"),
            httpx.Response(200, json={"status": "completed", "url": "http://x/v.mp4"}),
        ]
    )
    p = OpenAICompatProvider(name="agnes", base_url=UPSTREAM, api_key="k")
    out = await p.get_video("tid")
    assert out["status"] == "completed"
    assert _no_sleep == [13.0]
    await p.aclose()


@respx.mock
async def test_get_video_exhausts_network_retries_then_raises(_no_sleep):
    """网络错一直不好 → 退避 4 次(1→2→4→8s)后抛人话错误，不无限转。"""
    respx.get(f"{UPSTREAM}/videos/tid").mock(side_effect=httpx.ConnectError("down"))
    p = OpenAICompatProvider(name="agnes", base_url=UPSTREAM, api_key="k")
    with pytest.raises(ProviderError) as ei:
        await p.get_video("tid")
    assert "查询视频失败" in str(ei.value)
    assert _no_sleep == [1.0, 2.0, 4.0, 8.0]  # 4 次退避后放弃
    await p.aclose()
