"""通用 OpenAI 兼容 provider：把请求转发到任意 OpenAI 兼容上游（含火山方舟）。"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import math
import re
import ssl
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import httpx

from gateway.admission import (
    BackgroundJobLimitExceeded,
    current_background_job_lease,
    get_background_job_pool,
)
from gateway.media_call_metering import begin_media_http_attempt
from gateway.model_identity import exact_verified_model_identity, model_family_from_identifier
from gateway.provider_call_ledger import (
    financial_usage_from_payload,
    finish_provider_attempt_durable,
    observed_model_from_payload,
)
from gateway.providers.base import (
    ChatProvider,
    ProviderError,
    ProviderSubmissionOutcomeUnknown,
    friendly_error,
    friendly_status,
)
from gateway.schemas import ChatCompletionRequest, ImageGenerationRequest, VideoGenerationRequest

# 视频 GET 轮询的瞬时错重试参数——仅幂等 GET 可以重试。创建视频的 POST 在供应商没有
# 经过验证的幂等键前绝不自动重试：ReadTimeout 可能代表“供应商已接单但响应丢失”，重发会
# 产生孤儿任务和重复计费。每次真实 HTTP 尝试都由下面的循环单独写 provider_calls。
_VIDEO_RETRY_BACKOFFS = (1.0, 2.0, 4.0, 8.0)
_VIDEO_TRANSIENT_STATUS = (502, 503, 504)
# 网络瞬时错：连接类(NetworkError=ConnectError/ReadError/WriteError/CloseError) + 超时类
# (TimeoutException=ConnectTimeout/ReadTimeout/WriteTimeout/PoolTimeout) + 连接被上游中途掐断
# (RemoteProtocolError，如"server disconnected")。轮询是幂等 GET，这些全值得退避重试。
# 机主实测：以前只列 ConnectError/ConnectTimeout/ReadTimeout，Agnes 抖动常报 ReadError/
# RemoteProtocolError 漏在网外→没重试、一次就报废。
_VIDEO_TRANSIENT_NET = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, ssl.SSLError)
_DEFINITELY_PRE_SUBMISSION_NET = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
)
_VIDEO_RATELIMIT_WAIT = 13.0  # 视频 5 RPM → 窗口 12s + 余量
_VIDEO_RATELIMIT_TRIES = 3    # 429 慢等最多几次（RPM 突发能过；每日额度打满则透传报错，不空转）
_MEDIA_BILLING_DIMENSIONS_SCHEMA = "media_billing_dimensions_v1"
_MEDIA_QUALITY_VALUES = frozenset(
    {"auto", "standard", "hd", "low", "medium", "high"}
)
_PAID_MEDIA_V2_SUCCESS_BYTES = 1024 * 1024
_PAID_MEDIA_V2_ERROR_BYTES = 64 * 1024
_PAID_MEDIA_V2_MAX_ASSETS = 4
_CHAT_PROBE_BODY_BYTES = 64 * 1024
_CHAT_COMPLETION_BODY_BYTES = 16 * 1024 * 1024
_CHAT_ERROR_BODY_BYTES = 64 * 1024
_CHAT_STREAM_TOTAL_BYTES = 64 * 1024 * 1024
_CHAT_STREAM_LINE_BYTES = 1024 * 1024


class _ProviderBodyTooLarge(ValueError):
    pass


async def _read_bounded_provider_body(response: Any, maximum: int) -> bytes:
    """Read a streaming response without touching json/text/content helpers."""

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if not isinstance(chunk, bytes):
            chunk = bytes(chunk)
        if len(body) + len(chunk) > maximum:
            raise _ProviderBodyTooLarge("provider metadata body exceeds its limit")
        body.extend(chunk)
    return bytes(body)


async def _iter_bounded_sse_lines(
    response: Any, *, maximum_total: int, maximum_line: int
) -> AsyncIterator[bytes]:
    """Yield raw SSE lines while bounding both the stream and one frame line."""

    total = 0
    pending = bytearray()
    async for chunk in response.aiter_bytes():
        raw = bytes(chunk)
        total += len(raw)
        if total > maximum_total:
            raise _ProviderBodyTooLarge("provider stream exceeds its total limit")
        pending.extend(raw)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                if len(pending) > maximum_line:
                    raise _ProviderBodyTooLarge("provider stream line exceeds its limit")
                break
            line = bytes(pending[:newline])
            del pending[: newline + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            if len(line) > maximum_line:
                raise _ProviderBodyTooLarge("provider stream line exceeds its limit")
            yield line
    if pending:
        if len(pending) > maximum_line:
            raise _ProviderBodyTooLarge("provider stream line exceeds its limit")
        if pending.endswith(b"\r"):
            pending = pending[:-1]
        yield bytes(pending)


def _strict_json_object(body: bytes) -> dict[str, Any]:
    try:
        decoded = body.decode("utf-8", "strict")
        value = json.loads(decoded)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("provider metadata is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("provider metadata must be a JSON object")
    return value


def _base_url_is_loopback(value: str) -> bool:
    """Return whether an explicit base URL is confined to a loopback host."""

    try:
        hostname = (urlsplit(value).hostname or "").casefold().rstrip(".")
    except (UnicodeError, ValueError):
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
        if address.is_loopback:
            return True
        mapped = getattr(address, "ipv4_mapped", None)
        return bool(mapped is not None and mapped.is_loopback)
    except ValueError:
        return False


def _declared_content_length(response: Any) -> int | None:
    """Parse one unambiguous non-negative Content-Length, if supplied."""

    values = response.headers.get_list("content-length")
    if not values:
        return None
    tokens = [token.strip() for value in values for token in value.split(",")]
    if not tokens or any(not token.isascii() or not token.isdecimal() for token in tokens):
        raise ValueError("invalid Content-Length")
    lengths = {int(token) for token in tokens}
    if len(lengths) != 1:
        raise ValueError("ambiguous Content-Length")
    return lengths.pop()


def _valid_chat_completion(payload: Any) -> bool:
    """Validate the minimum OpenAI-compatible non-streaming chat contract."""

    if not isinstance(payload, dict) or isinstance(payload.get("error"), dict):
        return False
    choices = payload.get("choices")
    first = choices[0] if isinstance(choices, list) and choices else None
    message = first.get("message") if isinstance(first, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
    return bool(
        isinstance(message, dict)
        and (
            (isinstance(content, str) and content.strip())
            or (isinstance(tool_calls, list) and tool_calls)
        )
    )


def _bounded_provider_usage(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, Any] = {}
    integer_fields = frozenset(
        {
            "prompt_tokens",
            "input_tokens",
            "completion_tokens",
            "output_tokens",
            "total_tokens",
            "cached_tokens",
            "cache_read_tokens",
            "cache_creation_tokens",
        }
    )
    for key in integer_fields:
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and 0 <= item < 1 << 63:
            out[key] = item
    cost = value.get("cost_usd")
    if (
        isinstance(cost, (int, float))
        and not isinstance(cost, bool)
        and math.isfinite(float(cost))
        and 0 <= float(cost) <= 1_000_000_000
    ):
        out["cost_usd"] = cost
    for key in ("cost_basis", "cost_attribution_basis"):
        item = value.get(key)
        if isinstance(item, str) and 0 < len(item) <= 64 and item.isascii():
            out[key] = item
    details = value.get("prompt_tokens_details")
    if isinstance(details, dict):
        cached = details.get("cached_tokens")
        if (
            isinstance(cached, int)
            and not isinstance(cached, bool)
            and 0 <= cached < 1 << 63
        ):
            out["prompt_tokens_details"] = {"cached_tokens": cached}
    return out or None


def _paid_media_v2_url_metadata(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("provider image response must be an object")
    data = value.get("data")
    if not isinstance(data, list) or not 1 <= len(data) <= _PAID_MEDIA_V2_MAX_ASSETS:
        raise ValueError("provider image response has an invalid asset count")
    normalized: list[dict[str, str]] = []
    for item in data:
        if (
            not isinstance(item, dict)
            or "url" not in item
            or item.get("b64_json") is not None
        ):
            raise ValueError("provider image response is missing a URL")
        url = item.get("url")
        if not isinstance(url, str) or not 1 <= len(url) <= 8192:
            raise ValueError("provider image URL is invalid")
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.fragment)
        ):
            raise ValueError("provider image URL is outside the HTTPS asset contract")
        normalized.append({"url": url})
    result: dict[str, Any] = {"data": normalized}
    created = value.get("created")
    if (
        isinstance(created, int)
        and not isinstance(created, bool)
        and 0 <= created <= (1 << 53) - 1
    ):
        result["created"] = created
    model = value.get("model")
    if isinstance(model, str) and 0 < len(model) <= 512:
        result["model"] = model
    usage = _bounded_provider_usage(value.get("usage"))
    if usage is not None:
        result["usage"] = usage
    return result


def _post_submission_outcome_unknown(exc: BaseException) -> bool:
    """Return whether a failed non-idempotent POST may already be accepted.

    Only failures that prove no request could have reached the provider are
    treated as ordinary submission failures.  Bare SSL/OSError failures and
    all later-stage HTTPX failures are conservative outcome-unknown cases.
    """

    if isinstance(exc, _DEFINITELY_PRE_SUBMISSION_NET):
        return False
    return isinstance(exc, (httpx.HTTPError, OSError))


def _valid_chat_stream_chunk(payload: Any) -> bool:
    """Validate a bounded OpenAI chat-completions stream payload."""

    if not isinstance(payload, dict) or isinstance(payload.get("error"), dict):
        return False
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return False
    if not choices:
        return isinstance(payload.get("usage"), dict)
    return any(
        isinstance(choice, dict)
        and (
            isinstance(choice.get("delta"), dict)
            or choice.get("finish_reason") is not None
        )
        for choice in choices
    )

# Agnes 视频成片 URL 会散落在这些字段里（照已验证的 agnes.py `_extract_video_url`）。纳川以前只查
# url/video_url/data.url 3 个 → 常挖不到 → 明明做好了却当"处理中"傻等到超时。这里对齐官方与历史形状。
_AGNES_VIDEO_URL_FIELDS = (
    "remixed_from_video_id", "url", "video_url", "output_url", "download_url",
    "data.url", "data.video_url", "data.output_url", "result.url", "result.video_url",
    "video.url", "metadata.url",
)


def _bounded_billing_number(
    value: Any,
    *,
    minimum: float,
    maximum: float,
) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        return None
    return int(number) if number.is_integer() else number


def _bounded_billing_resolution(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized == "auto":
        return normalized
    match = re.fullmatch(r"(\d{2,5})x(\d{2,5})", normalized)
    if match is None:
        return None
    width, height = (int(part) for part in match.groups())
    if not (64 <= width <= 8192 and 64 <= height <= 8192):
        return None
    if width * height > 33_554_432:
        return None
    return normalized


def _media_billing_usage(operation: str, payload: Any) -> dict[str, Any]:
    """Build bounded local pricing dimensions without prompts or response IDs."""

    dimensions: dict[str, int | float | str] = {"operation": operation}
    if isinstance(payload, dict):
        n = _bounded_billing_number(payload.get("n"), minimum=1, maximum=100)
        if n is not None:
            dimensions["n"] = n
        size = _bounded_billing_resolution(payload.get("size"))
        if size is not None:
            dimensions["size"] = size
        quality = str(payload.get("quality") or "").strip().lower()
        if quality in _MEDIA_QUALITY_VALUES:
            dimensions["quality"] = quality

        if operation == "media.generate_video":
            for key in ("duration_seconds", "seconds"):
                duration = _bounded_billing_number(
                    payload.get(key), minimum=0.001, maximum=86_400
                )
                if duration is not None:
                    dimensions[key] = duration

            resolution = _bounded_billing_resolution(payload.get("resolution"))
            if resolution is None:
                width = _bounded_billing_number(
                    payload.get("width"), minimum=64, maximum=8192
                )
                height = _bounded_billing_number(
                    payload.get("height"), minimum=64, maximum=8192
                )
                if isinstance(width, int) and isinstance(height, int):
                    resolution = _bounded_billing_resolution(f"{width}x{height}")
            if resolution is not None:
                dimensions["resolution"] = resolution

            fps = _bounded_billing_number(
                payload.get("fps", payload.get("frame_rate")),
                minimum=1,
                maximum=240,
            )
            if fps is not None:
                dimensions["fps"] = fps
            frame_count = _bounded_billing_number(
                payload.get("frame_count", payload.get("num_frames")),
                minimum=1,
                maximum=1_000_000,
            )
            if isinstance(frame_count, int):
                dimensions["frame_count"] = frame_count

    return {
        "billing_dimensions_json": dimensions,
        "billing_dimensions_schema": _MEDIA_BILLING_DIMENSIONS_SCHEMA,
    }


def _extract_agnes_video_url(p: Any) -> str:
    """从 Agnes 视频状态响应里挖成片 URL（多字段、支持 a.b 嵌套）。挖不到返回 ""。"""
    if not isinstance(p, dict):
        return ""
    for f in _AGNES_VIDEO_URL_FIELDS:
        cur: Any = p
        for part in f.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if isinstance(cur, str) and cur.startswith("http"):
            return cur
    return ""


def _video_job_ids(payload: Any) -> tuple[str, ...]:
    if not isinstance(payload, dict):
        return ()
    nested = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    out: list[str] = []
    for key in ("video_id", "task_id", "id", "request_id", "upstream_task_id"):
        item = str(payload.get(key) or nested.get(key) or "").strip()
        if item and len(item) <= 256 and not any(ord(ch) < 32 for ch in item) and item not in out:
            out.append(item)
    return tuple(out)


def _is_official_agnes_video_create_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return bool(
            parsed.scheme.casefold() == "https"
            and (parsed.hostname or "").casefold() == "apihub.agnes-ai.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/v1/videos"
            and not parsed.query
            and not parsed.fragment
        )
    except (UnicodeError, ValueError):
        return False


def _valid_agnes_video_poll_id(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    value = payload.get("video_id")
    return bool(
        isinstance(value, str)
        and 1 <= len(value.strip()) <= 256
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _video_job_terminal(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    nested = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    status = str(payload.get("status") or nested.get("status") or "").strip().lower()
    if status in {
        "complete",
        "completed",
        "done",
        "success",
        "succeeded",
        "failure",
        "failed",
        "error",
        "cancelled",
        "canceled",
    }:
        return True
    if status:
        return False
    return bool(_extract_agnes_video_url(payload))


_log = logging.getLogger("uvicorn.error")


class OpenAICompatProvider(ChatProvider):
    paid_media_asset_protocol_versions = frozenset({"2"})
    media_http_attempt_accounting_operations = frozenset(
        {"media.generate_image", "media.generate_video", "media.get_video"}
    )

    def __init__(self, name: str, base_url: str, api_key: str, timeout: float = 300.0):
        self.name = name
        self.base_url = (base_url or "").rstrip("/")
        # 本地模型（Ollama/LM Studio 等）无需 key：有 base_url 即可启用
        self.enabled = bool(self.base_url)
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            timeout=timeout,
            # Local model servers must never be silently retargeted through an
            # HTTP(S)_PROXY inherited from the desktop/service environment.
            # Remote providers retain the user's existing proxy compatibility.
            trust_env=not _base_url_is_loopback(self.base_url),
            follow_redirects=False,
        )
        self._background_video_leases: set[str] = set()

    @property
    def paid_media_video_asset_protocol_versions(self) -> frozenset[str]:
        # The durable create/frozen-route/poll/asset-ingestion contract is
        # currently verified only for Agnes' exact official API root.  Generic
        # OpenAI-compatible endpoints stay fail-closed until independently
        # proven.
        if self.base_url.casefold() == "https://apihub.agnes-ai.com/v1":
            return frozenset({"2"})
        return frozenset()

    @property
    def _endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _trusted_endpoint_family(self) -> str | None:
        """Bind identity authority to exact vendor-owned TLS endpoints only."""

        try:
            parsed = urlsplit(str(getattr(self, "base_url", "") or ""))
            if (
                parsed.scheme.casefold() != "https"
                or parsed.port not in (None, 443)
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                return None
            key = ((parsed.hostname or "").casefold(), parsed.path.rstrip("/"))
        except (UnicodeError, ValueError):
            return None
        official = {
            ("api.openai.com", "/v1"): "openai",
            (
                "generativelanguage.googleapis.com",
                "/v1beta/openai",
            ): "google-gemini",
            ("api.deepseek.com", "/v1"): "deepseek",
            ("open.bigmodel.cn", "/api/paas/v4"): "zhipu",
            ("api.moonshot.cn", "/v1"): "moonshot",
            ("api.moonshot.ai", "/v1"): "moonshot",
            (
                "dashscope.aliyuncs.com",
                "/compatible-mode/v1",
            ): "alibaba-qwen",
            (
                "dashscope-intl.aliyuncs.com",
                "/compatible-mode/v1",
            ): "alibaba-qwen",
            (
                "dashscope-us.aliyuncs.com",
                "/compatible-mode/v1",
            ): "alibaba-qwen",
            ("api.z.ai", "/api/paas/v4"): "zhipu",
            (
                "api.hunyuan.cloud.tencent.com",
                "/v1",
            ): "tencent-hunyuan",
            ("qianfan.baidubce.com", "/v2"): "baidu-ernie",
            ("api.minimaxi.com", "/v1"): "minimax",
            ("api.minimax.io", "/v1"): "minimax",
            ("api.x.ai", "/v1"): "xai-grok",
            ("api.mistral.ai", "/v1"): "mistral",
            ("apihub.agnes-ai.com", "/v1"): "agnes",
            ("api.perplexity.ai", ""): "perplexity-sonar",
        }.get(key)
        if official is not None:
            return official
        host, path = key
        if (
            path == "/compatible-mode/v1"
            and host.endswith(".cn-beijing.maas.aliyuncs.com")
            and host.count(".") == 4
        ):
            return "alibaba-qwen"
        return None

    def expected_model_family(self, upstream_model: str) -> str | None:
        endpoint_family = self._trusted_endpoint_family()
        identifier_family = model_family_from_identifier(upstream_model)
        return endpoint_family if endpoint_family == identifier_family else None

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        endpoint_family = self._trusted_endpoint_family()
        verified = exact_verified_model_identity(upstream_model, observed_model)
        if verified is None or verified[1] != endpoint_family:
            return None
        return verified

    async def chat(self, req: ChatCompletionRequest, upstream_model: str) -> dict[str, Any]:
        payload = req.to_upstream_payload(upstream_model, stream=False)
        try:
            async with self._client.stream(
                "POST", self._endpoint, headers=self._headers, json=payload
            ) as response:
                status_code = int(response.status_code)
                if 300 <= status_code < 400:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游聊天响应发生了未授权重定向", status_code=502
                    )
                if status_code >= 400:
                    try:
                        error_body = await _read_bounded_provider_body(
                            response, _CHAT_ERROR_BODY_BYTES
                        )
                        error_text = error_body.decode("utf-8", "replace")
                    except _ProviderBodyTooLarge:
                        error_text = "响应错误体过大"
                    message = friendly_status(status_code, error_text)
                    if status_code >= 500:
                        raise ProviderSubmissionOutcomeUnknown(
                            message, status_code=status_code
                        )
                    raise ProviderError(message, status_code=status_code)
                try:
                    declared_length = _declared_content_length(response)
                except ValueError as exc:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游返回了无效 Content-Length", status_code=502
                    ) from exc
                if (
                    declared_length is not None
                    and declared_length > _CHAT_COMPLETION_BODY_BYTES
                ):
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游聊天响应超过安全大小限制", status_code=502
                    )
                try:
                    body = await _read_bounded_provider_body(
                        response, _CHAT_COMPLETION_BODY_BYTES
                    )
                except _ProviderBodyTooLarge as exc:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游聊天响应超过安全大小限制", status_code=502
                    ) from exc
        except ProviderError:
            raise
        except (httpx.HTTPError, OSError) as e:
            # OSError 覆盖 ssl.SSLError（大 payload 过代理时 TLS 记录损坏可裸穿 httpx——
            # 机主实测 DECRYPTION_FAILED_OR_BAD_RECORD_MAC 直接炸穿备用链）：包成 ProviderError 才能走 failover。
            raise ProviderError(f"上游请求失败：{friendly_error(e)}") from e
        try:
            result = json.loads(body.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as e:
            raise ProviderSubmissionOutcomeUnknown(
                "上游返回了无效 JSON", status_code=502
            ) from e
        if not _valid_chat_completion(result):
            raise ProviderSubmissionOutcomeUnknown(
                "上游返回了无效聊天响应", status_code=502
            )
        return result

    async def probe_chat(
        self, req: ChatCompletionRequest, upstream_model: str
    ) -> dict[str, Any]:
        """Probe a connection through a strict, bounded streaming response path."""

        payload = req.to_upstream_payload(upstream_model, stream=False)
        try:
            async with self._client.stream(
                "POST",
                self._endpoint,
                headers=self._headers,
                json=payload,
            ) as response:
                status_code = int(response.status_code)
                if 300 <= status_code < 400:
                    raise ProviderError("上游探测拒绝重定向", status_code=502)
                if status_code >= 500:
                    raise ProviderSubmissionOutcomeUnknown(
                        friendly_status(status_code),
                        status_code=status_code,
                    )
                if status_code >= 400:
                    raise ProviderError(
                        friendly_status(status_code),
                        status_code=status_code,
                    )
                if status_code < 200:
                    raise ProviderError("上游探测返回了无效 HTTP 状态", status_code=502)

                try:
                    declared_length = _declared_content_length(response)
                except ValueError as exc:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游返回了无效聊天响应", status_code=502
                    ) from exc
                if (
                    declared_length is not None
                    and declared_length > _CHAT_PROBE_BODY_BYTES
                ):
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游探测响应过大", status_code=502
                    )
                try:
                    # aiter_bytes() yields HTTPX-decoded bytes, so the same
                    # bound also covers gzip/brotli decompression expansion.
                    body = await _read_bounded_provider_body(
                        response, _CHAT_PROBE_BODY_BYTES
                    )
                except _ProviderBodyTooLarge as exc:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游探测响应过大", status_code=502
                    ) from exc
        except ProviderError:
            raise
        except (httpx.HTTPError, OSError) as exc:
            raise ProviderError(f"上游探测请求失败：{friendly_error(exc)}") from exc

        try:
            result = _strict_json_object(body)
        except ValueError as exc:
            raise ProviderSubmissionOutcomeUnknown(
                "上游返回了无效聊天响应", status_code=502
            ) from exc
        if not _valid_chat_completion(result):
            raise ProviderSubmissionOutcomeUnknown(
                "上游返回了无效聊天响应", status_code=502
            )
        return result

    async def stream(
        self, req: ChatCompletionRequest, upstream_model: str
    ) -> AsyncIterator[dict[str, Any]]:
        payload = req.to_upstream_payload(upstream_model, stream=True)
        saw_valid_chunk = False
        try:
            async with self._client.stream(
                "POST", self._endpoint, headers=self._headers, json=payload
            ) as resp:
                if 300 <= resp.status_code < 400:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游流式响应发生了未授权重定向", status_code=502
                    )
                if resp.status_code >= 500:
                    raise ProviderSubmissionOutcomeUnknown(
                        friendly_status(resp.status_code),
                        status_code=resp.status_code,
                    )
                if resp.status_code >= 400:
                    try:
                        body = await _read_bounded_provider_body(
                            resp, _CHAT_ERROR_BODY_BYTES
                        )
                    except _ProviderBodyTooLarge:
                        body = b"response error body too large"
                    raise ProviderError(
                        f"上游返回 {resp.status_code}: {body.decode('utf-8', 'ignore')[:500]}",
                        status_code=resp.status_code,
                    )
                try:
                    declared_length = _declared_content_length(resp)
                except ValueError as exc:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游返回了无效 Content-Length", status_code=502
                    ) from exc
                if (
                    declared_length is not None
                    and declared_length > _CHAT_STREAM_TOTAL_BYTES
                ):
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游流式响应超过安全大小限制", status_code=502
                    )
                async for raw_line in _iter_bounded_sse_lines(
                    resp,
                    maximum_total=_CHAT_STREAM_TOTAL_BYTES,
                    maximum_line=_CHAT_STREAM_LINE_BYTES,
                ):
                    try:
                        line = raw_line.decode("utf-8", "strict").strip()
                    except UnicodeError as exc:
                        raise ProviderSubmissionOutcomeUnknown(
                            "上游返回了无效流式 UTF-8", status_code=502
                        ) from exc
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:"):].strip()
                    if data == "[DONE]":
                        if not saw_valid_chunk:
                            raise ProviderSubmissionOutcomeUnknown(
                                "上游流式响应在有效首包前结束", status_code=502
                            )
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError as e:
                        raise ProviderSubmissionOutcomeUnknown(
                            "上游返回了无效流式 JSON", status_code=502
                        ) from e
                    if not _valid_chat_stream_chunk(chunk):
                        raise ProviderSubmissionOutcomeUnknown(
                            "上游返回了无效流式聊天响应", status_code=502
                        )
                    saw_valid_chunk = True
                    yield chunk
                if not saw_valid_chunk:
                    raise ProviderSubmissionOutcomeUnknown(
                        "上游返回了空流或无效流", status_code=502
                    )
        except _ProviderBodyTooLarge as exc:
            raise ProviderSubmissionOutcomeUnknown(
                "上游流式响应超过安全大小限制", status_code=502
            ) from exc
        except (httpx.HTTPError, OSError) as e:  # OSError 覆盖 ssl.SSLError(TLS 损坏裸穿)
            raise ProviderError(f"上游流式请求失败：{friendly_error(e)}") from e

    async def generate_image_asset_urls(
        self, req: ImageGenerationRequest, upstream_model: str
    ) -> dict[str, Any]:
        """Submit once and parse only bounded URL metadata for protocol v2."""

        if req.response_format == "b64_json":
            raise ProviderError(
                "paid-media protocol v2 requires URL image results",
                status_code=422,
            )
        payload = req.to_upstream_payload(upstream_model)
        if self._trusted_endpoint_family() == "agnes":
            # Agnes Image 2.1 rejects OpenAI's top-level response_format and
            # requires an explicit size.  Keep this vendor mapping pinned to
            # the exact official TLS endpoint; generic OpenAI-compatible
            # providers retain the standard top-level field.
            payload.pop("response_format", None)
            payload.setdefault("size", "1K")
            raw_extra_body = payload.get("extra_body")
            if raw_extra_body is None:
                extra_body: dict[str, Any] = {}
            elif isinstance(raw_extra_body, dict):
                extra_body = dict(raw_extra_body)
            else:
                raise ProviderError(
                    "Agnes image extra_body must be an object",
                    status_code=422,
                )
            extra_body["response_format"] = "url"
            payload["extra_body"] = extra_body
        else:
            payload["response_format"] = "url"
        billing_usage = _media_billing_usage("media.generate_image", payload)
        accounting = await begin_media_http_attempt(1)
        status_code = 0
        body = b""
        body_too_large = False
        try:
            async with self._client.stream(
                "POST",
                f"{self.base_url}/images/generations",
                headers=self._headers,
                json=payload,
            ) as response:
                status_code = int(response.status_code)
                maximum = (
                    _PAID_MEDIA_V2_ERROR_BYTES
                    if status_code >= 400
                    else _PAID_MEDIA_V2_SUCCESS_BYTES
                )
                try:
                    body = await _read_bounded_provider_body(response, maximum)
                except _ProviderBodyTooLarge:
                    body_too_large = True
        except asyncio.CancelledError:
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="cancelled",
                    usage=billing_usage,
                    error_type="image_submission_outcome_unknown",
                    error_message=(
                        "image submission cancelled after provider invocation; "
                        "submission outcome unknown; automatic retry forbidden"
                    ),
                )
            raise
        except (httpx.HTTPError, OSError) as exc:
            outcome_unknown = _post_submission_outcome_unknown(exc)
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status=(
                        "timeout"
                        if isinstance(exc, (TimeoutError, httpx.TimeoutException))
                        else "provider_error"
                    ),
                    usage=billing_usage,
                    error_type=(
                        "image_submission_outcome_unknown"
                        if outcome_unknown
                        else type(exc).__name__
                    ),
                    error_message=(
                        "image submission outcome unknown; automatic retry forbidden"
                        if outcome_unknown
                        else str(exc)
                    ),
                )
            if outcome_unknown:
                raise ProviderSubmissionOutcomeUnknown(
                    "image submission outcome unknown; automatic retry forbidden",
                    status_code=502,
                ) from exc
            raise ProviderError("image provider connection failed", status_code=502) from exc

        if status_code >= 400:
            error_text = ""
            if not body_too_large:
                try:
                    error_text = body.decode("utf-8", "strict")
                except UnicodeError:
                    error_text = ""
            message = friendly_status(status_code, error_text)
            outcome_unknown = status_code >= 500
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="provider_error",
                    usage=billing_usage,
                    error_type=(
                        "image_submission_outcome_unknown"
                        if outcome_unknown
                        else "HTTPStatusError"
                    ),
                    error_message=(
                        "image submission outcome unknown after upstream "
                        f"HTTP {status_code}; automatic retry forbidden"
                        if outcome_unknown
                        else message
                    ),
                )
            if outcome_unknown:
                raise ProviderSubmissionOutcomeUnknown(
                    "image submission outcome unknown; automatic retry forbidden",
                    status_code=status_code,
                )
            raise ProviderError(message, status_code=status_code)

        if body_too_large:
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="provider_error",
                    usage=billing_usage,
                    error_type="image_submission_outcome_unknown",
                    error_message=(
                        "image submission returned oversized metadata; "
                        "submission outcome unknown; automatic retry forbidden"
                    ),
                )
            raise ProviderSubmissionOutcomeUnknown(
                "image submission returned oversized metadata; automatic retry forbidden",
                status_code=502,
            )
        try:
            result = _paid_media_v2_url_metadata(_strict_json_object(body))
        except ValueError as exc:
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="provider_error",
                    usage=billing_usage,
                    error_type="image_submission_outcome_unknown",
                    error_message=(
                        "image submission returned invalid URL metadata; "
                        "submission outcome unknown; automatic retry forbidden"
                    ),
                )
            raise ProviderSubmissionOutcomeUnknown(
                "image submission returned invalid URL metadata; automatic retry forbidden",
                status_code=502,
            ) from exc
        if accounting is not None:
            await finish_provider_attempt_durable(
                accounting,
                status="success",
                observed_model=observed_model_from_payload(result),
                usage={**financial_usage_from_payload(result), **billing_usage},
            )
        return result

    async def generate_image(
        self, req: ImageGenerationRequest, upstream_model: str
    ) -> dict[str, Any]:
        payload = req.to_upstream_payload(upstream_model)
        billing_usage = _media_billing_usage("media.generate_image", payload)
        accounting = await begin_media_http_attempt(1)
        try:
            resp = await self._client.post(
                f"{self.base_url}/images/generations", headers=self._headers, json=payload
            )
        except asyncio.CancelledError as e:
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="cancelled",
                    usage=billing_usage,
                    error_type="image_submission_outcome_unknown",
                    error_message=(
                        "image submission cancelled after provider invocation; "
                        "submission outcome unknown; automatic retry forbidden"
                    ),
                )
            raise
        except (httpx.HTTPError, OSError) as e:  # OSError 覆盖 ssl.SSLError(TLS 损坏裸穿)
            outcome_unknown = _post_submission_outcome_unknown(e)
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="timeout"
                    if isinstance(e, (TimeoutError, httpx.TimeoutException))
                    else "provider_error",
                    usage=billing_usage,
                    error_type=(
                        "image_submission_outcome_unknown"
                        if outcome_unknown
                        else type(e).__name__
                    ),
                    error_message=(
                        "image submission outcome unknown; automatic retry forbidden"
                        if outcome_unknown
                        else str(e)
                    ),
                )
            if outcome_unknown:
                raise ProviderError(
                    f"生图请求结果未知；供应商可能已受理，禁止自动重试：{friendly_error(e)}"
                ) from e
            raise ProviderError(f"生图请求失败：{friendly_error(e)}") from e
        if resp.status_code >= 400:
            message = friendly_status(resp.status_code, resp.text)
            outcome_unknown = resp.status_code >= 500
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="provider_error",
                    usage=billing_usage,
                    error_type=(
                        "image_submission_outcome_unknown"
                        if outcome_unknown
                        else "HTTPStatusError"
                    ),
                    error_message=(
                        "image submission outcome unknown after upstream "
                        f"HTTP {resp.status_code}; automatic retry forbidden"
                        if outcome_unknown
                        else message
                    ),
                )
            if outcome_unknown:
                raise ProviderError(
                    "生图请求结果未知；供应商可能已受理，禁止自动重试："
                    f"{message}",
                    status_code=resp.status_code,
                )
            raise ProviderError(message, status_code=resp.status_code)
        try:
            result = resp.json()
        except Exception as e:  # noqa: BLE001
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="provider_error",
                    usage=billing_usage,
                    error_type="image_submission_outcome_unknown",
                    error_message=(
                        "image submission returned invalid JSON; "
                        "submission outcome unknown; automatic retry forbidden"
                    ),
                )
            raise ProviderError(
                "生图请求结果未知；供应商可能已受理，禁止自动重试："
                "上游返回了无效 JSON"
            ) from e
        image_data = result.get("data") if isinstance(result, dict) else None
        usable_image = isinstance(image_data, list) and any(
            isinstance(item, dict)
            and any(
                isinstance(item.get(field), str) and bool(item[field].strip())
                for field in ("url", "b64_json")
            )
            for item in image_data
        )
        if not usable_image:
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="provider_error",
                    usage=billing_usage,
                    error_type="image_submission_outcome_unknown",
                    error_message=(
                        "image submission response missing usable url/b64_json data; "
                        "submission outcome unknown; automatic retry forbidden"
                    ),
                )
            raise ProviderError(
                "生图请求结果未知；供应商可能已受理，禁止自动重试："
                "2xx 响应缺少可用的 data（url/b64_json）"
            )
        if accounting is not None:
            await finish_provider_attempt_durable(
                accounting,
                status="success",
                observed_model=observed_model_from_payload(result),
                usage={**financial_usage_from_payload(result), **billing_usage},
            )
        return result

    async def _video_request_with_retry(
        self, method: str, url: str, *, what: str, json_body: Any = None
    ) -> dict[str, Any]:
        """Send video HTTP requests, retrying only idempotent reads.

        Every raw request receives its own immutable accounting row.  POST is
        deliberately single-shot until a provider idempotency key is verified.
        """
        retry_safe = method.upper() in {"GET", "HEAD"}
        billing_usage = (
            {}
            if retry_safe
            else _media_billing_usage("media.generate_video", json_body)
        )
        net_i = 0  # 网络瞬时错 + 502/503/504 共用的退避预算（4 次）
        rl_i = 0   # 429 慢等独立计数
        raw_attempt = 0
        while True:
            raw_attempt += 1
            accounting = await begin_media_http_attempt(raw_attempt)
            try:
                resp = await self._client.request(method, url, headers=self._headers, json=json_body)
            except asyncio.CancelledError as e:
                outcome_unknown = not retry_safe
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="cancelled",
                        usage=billing_usage,
                        error_type=(
                            "video_submission_outcome_unknown"
                            if outcome_unknown
                            else type(e).__name__
                        ),
                        error_message=(
                            "video submission cancelled after provider invocation; "
                            "submission outcome unknown; automatic retry forbidden"
                            if outcome_unknown
                            else f"{what} cancelled"
                        ),
                    )
                raise
            except _VIDEO_TRANSIENT_NET as e:
                outcome_unknown = (
                    not retry_safe and _post_submission_outcome_unknown(e)
                )
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="timeout" if isinstance(e, (TimeoutError, httpx.TimeoutException)) else "provider_error",
                        usage=billing_usage,
                        error_type=(
                            "video_submission_outcome_unknown"
                            if outcome_unknown
                            else type(e).__name__
                        ),
                        error_message=(
                            "video submission outcome unknown; automatic retry forbidden"
                            if outcome_unknown
                            else str(e)
                        ),
                    )
                if retry_safe and net_i < len(_VIDEO_RETRY_BACKOFFS):
                    wait = _VIDEO_RETRY_BACKOFFS[net_i]
                    net_i += 1
                    _log.warning(
                        "[%s:%s 重试 %d/%d] 网络瞬时错 %s，%.0fs 后重试",
                        self.name, what, net_i, len(_VIDEO_RETRY_BACKOFFS), type(e).__name__, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                if outcome_unknown:
                    raise ProviderError(
                        f"{what}结果未知；供应商可能已受理，禁止自动重试：{friendly_error(e)}"
                    ) from e
                raise ProviderError(f"{what}失败：{friendly_error(e)}") from e
            except (httpx.HTTPError, OSError) as e:  # 其它 httpx/网络错（非上述瞬时）→ 不重试但包成 ProviderError
                outcome_unknown = (
                    not retry_safe and _post_submission_outcome_unknown(e)
                )
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="timeout" if isinstance(e, (TimeoutError, httpx.TimeoutException)) else "provider_error",
                        usage=billing_usage,
                        error_type=(
                            "video_submission_outcome_unknown"
                            if outcome_unknown
                            else type(e).__name__
                        ),
                        error_message=(
                            "video submission outcome unknown; automatic retry forbidden"
                            if outcome_unknown
                            else str(e)
                        ),
                    )
                if outcome_unknown:
                    raise ProviderError(
                        f"{what}结果未知；供应商可能已受理，禁止自动重试：{friendly_error(e)}"
                    ) from e
                raise ProviderError(f"{what}失败：{friendly_error(e)}") from e

            code = resp.status_code
            if code == 429:  # Agnes 限流：慢等、绝不快重试；和网络错分开计数
                message = friendly_status(code, resp.text)
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="provider_error",
                        usage=billing_usage,
                        error_type="HTTPStatusError",
                        error_message=message,
                    )
                if retry_safe and rl_i < _VIDEO_RATELIMIT_TRIES:
                    rl_i += 1
                    _log.warning(
                        "[%s:%s 重试] 429 Agnes 限流(5RPM/每日额度)，%.0fs 慢等后重试 (%d/%d)",
                        self.name, what, _VIDEO_RATELIMIT_WAIT, rl_i, _VIDEO_RATELIMIT_TRIES,
                    )
                    await asyncio.sleep(_VIDEO_RATELIMIT_WAIT)
                    continue
                raise ProviderError(message, status_code=code)
            if code >= 500:
                message = friendly_status(code, resp.text)
                outcome_unknown = not retry_safe
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="provider_error",
                        usage=billing_usage,
                        error_type=(
                            "video_submission_outcome_unknown"
                            if outcome_unknown
                            else "HTTPStatusError"
                        ),
                        error_message=(
                            "video submission outcome unknown after upstream "
                            f"HTTP {code}; automatic retry forbidden"
                            if outcome_unknown
                            else message
                        ),
                    )
                if (
                    retry_safe
                    and code in _VIDEO_TRANSIENT_STATUS
                    and net_i < len(_VIDEO_RETRY_BACKOFFS)
                ):
                    wait = _VIDEO_RETRY_BACKOFFS[net_i]
                    net_i += 1
                    _log.warning(
                        "[%s:%s 重试 %d/%d] 上游 %d，%.0fs 后重试",
                        self.name, what, net_i, len(_VIDEO_RETRY_BACKOFFS), code, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                if outcome_unknown:
                    raise ProviderError(
                        f"{what}结果未知；供应商可能已受理，禁止自动重试："
                        f"{message}",
                        status_code=code,
                    )
                raise ProviderError(message, status_code=code)
            if code >= 400:  # 其它 4xx（401/400 等）：重试无用，直接抛
                message = friendly_status(code, resp.text)
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="provider_error",
                        usage=billing_usage,
                        error_type="HTTPStatusError",
                        error_message=message,
                    )
                raise ProviderError(message, status_code=code)
            try:
                result = resp.json()
            except Exception as e:  # noqa: BLE001
                outcome_unknown = not retry_safe
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="provider_error",
                        usage=billing_usage,
                        error_type=(
                            "video_submission_outcome_unknown"
                            if outcome_unknown
                            else type(e).__name__
                        ),
                        error_message=(
                            "video submission returned invalid JSON; "
                            "submission outcome unknown; automatic retry forbidden"
                            if outcome_unknown
                            else str(e)
                        ),
                    )
                if outcome_unknown:
                    raise ProviderError(
                        f"{what}结果未知；供应商可能已受理，禁止自动重试："
                        "上游返回了无效 JSON"
                    ) from e
                raise ProviderError(f"{what}失败：上游返回了无效 JSON") from e
            missing_identifier = not _video_job_ids(result)
            missing_official_agnes_poll_id = (
                _is_official_agnes_video_create_url(url)
                and not _valid_agnes_video_poll_id(result)
            )
            if not retry_safe and (
                missing_identifier or missing_official_agnes_poll_id
            ):
                missing_name = (
                    "video_id"
                    if missing_official_agnes_poll_id
                    else "task identifier"
                )
                if accounting is not None:
                    await finish_provider_attempt_durable(
                        accounting,
                        status="provider_error",
                        usage=billing_usage,
                        error_type="video_submission_outcome_unknown",
                        error_message=(
                            f"video submission response missing required {missing_name}; "
                            "submission outcome unknown; automatic retry forbidden"
                        ),
                    )
                raise ProviderError(
                    f"{what}结果未知；供应商可能已受理，禁止自动重试："
                    f"2xx 响应缺少必要的 {missing_name}"
                )
            if accounting is not None:
                await finish_provider_attempt_durable(
                    accounting,
                    status="success",
                    observed_model=observed_model_from_payload(result),
                    usage={**financial_usage_from_payload(result), **billing_usage},
                )
            return result

    async def generate_video(
        self, req: VideoGenerationRequest, upstream_model: str
    ) -> dict[str, Any]:
        """创建视频生成任务（POST /videos），返回上游原始响应（含 task_id）。带瞬时错重试。"""
        pool = get_background_job_pool()
        # Terminal polling and the stale TTL release capacity in the shared pool.
        # Prune our shutdown bookkeeping too, otherwise a long-lived provider
        # would retain one tiny token for every historical video forever.
        self._background_video_leases = {
            token for token in self._background_video_leases if pool.is_active(token)
        }
        inherited_lease = current_background_job_lease("video")
        lease = inherited_lease or pool.try_acquire(kind="video")
        if lease is None:
            raise BackgroundJobLimitExceeded("background video capacity reached")
        owned_lease = inherited_lease is None
        if owned_lease:
            self._background_video_leases.add(lease)
        payload = req.to_upstream_payload(upstream_model)
        try:
            result = await self._video_request_with_retry(
                "POST", f"{self.base_url}/videos", what="生视频请求", json_body=payload
            )
        except asyncio.CancelledError:
            # Submission may already have reached the provider. Keep the bounded
            # lease until provider close/TTL rather than reopening capacity blindly.
            raise
        except Exception:
            if owned_lease:
                pool.release(lease)
                self._background_video_leases.discard(lease)
            raise
        # Agnes create 同时返回两个完全不同的标识：
        #   task_id=提交队列 id；video_id=GET /agnesapi?video_id= 真正接受的查询 id。
        # 把前者拿去轮询会稳定得到 404 {"message":"task not found"}。网关对外契约里的
        # task_id 必须始终是“可轮询 id”，同时保留 upstream_task_id 方便诊断原始提交任务。
        if "agnes" in self.base_url.lower() and isinstance(result, dict):
            poll_id = str(result.get("video_id") or "").strip()
            submit_id = str(result.get("task_id") or result.get("id") or "").strip()
            if poll_id:
                result = dict(result)
                if submit_id and submit_id != poll_id:
                    result["upstream_task_id"] = submit_id
                result["task_id"] = poll_id
        if owned_lease:
            if _video_job_terminal(result):
                pool.release(lease)
                self._background_video_leases.discard(lease)
            else:
                aliases = _video_job_ids(result)
                if aliases and not pool.bind(lease, aliases):
                    pool.release(lease)
                    self._background_video_leases.discard(lease)
        return result

    async def get_video(self, task_id: str) -> dict[str, Any]:
        """查询视频任务状态。带瞬时错重试（Agnes 海外抖动多，尤其轮询）。

        机主实测根因：Agnes 的视频状态**不在** `/videos/{id}`，而在 `ROOT/agnesapi?video_id=`，且成片 URL
        散落在多字段（见 agnes.py 已验证）。纳川以前按 OpenAI 风格查 `/videos/{id}` + 只认 3 个 URL 字段，
        于是**视频明明做好了却识别不出→当"处理中"傻等到超时**。这里对 Agnes 走它真正的端点 + 11 字段挖 URL，
        并把结果归一化成 `{status, url}`——前端拿 `st.url` 就能判完成（媒体块和 awaitVideo 两条路都受益）。
        """
        if "agnes" in self.base_url.lower():
            from urllib.parse import quote

            root = self.base_url.rsplit("/v1", 1)[0]  # https://apihub.agnes-ai.com
            raw = await self._video_request_with_retry(
                "GET", f"{root}/agnesapi?video_id={quote(str(task_id))}", what="查询视频"
            )
            out: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {"raw": raw}
            out["status"] = str(out.get("status") or "").lower()
            url = _extract_agnes_video_url(raw)
            if url:
                out["url"] = url  # 归一化：前端 st.url 命中 → 判完成
            result = out
        else:
            result = await self._video_request_with_retry(
                "GET", f"{self.base_url}/videos/{task_id}", what="查询视频"
            )
        pool = get_background_job_pool()
        if _video_job_terminal(result):
            pool.release_external("video", str(task_id))
        else:
            pool.renew_external("video", str(task_id))
        self._background_video_leases = {
            token for token in self._background_video_leases if pool.is_active(token)
        }
        return result

    async def aclose(self) -> None:
        pool = get_background_job_pool()
        for lease in tuple(self._background_video_leases):
            pool.release(lease)
        self._background_video_leases.clear()
        await self._client.aclose()
