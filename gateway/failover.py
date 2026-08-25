"""失败转移：仅在能够证明请求尚未提交给模型商时走备用链。

用户编排：**ChatGPT(Codex Pro，额度最大最可靠) 是所有模型的统一后备**。
快/看图用 Agnes(免费)，长文/兜底用 ChatGPT；超长输入还会自动优先走 ChatGPT。
备用链可按需增改；未列出的模型只用自身、不转移。请求一旦调用上游，
除 ConnectError/ConnectTimeout/PoolTimeout 外的异常均按提交结果未知停止，避免重复执行和计费。
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import time
from typing import Any, AsyncIterator, Optional

import httpx

from gateway import quota_state
from gateway.provider_call_ledger import (
    CommercialBudgetAuthorization,
    ProviderCallContext,
    ProviderCallLedgerProtocol,
    ProviderRouteIdentity,
    current_provider_call_context,
    financial_usage_from_payload,
    finish_provider_attempt_durable,
    observed_model_from_payload,
    resolve_provider_call_ledger_durable,
    start_provider_attempt_durable,
)
from gateway.providers.base import (
    ProviderError,
    ProviderSubmissionOutcomeUnknown,
    friendly_status,
)
from gateway.route_attestation import capture_provider_call_provenance
from gateway.schemas import ChatCompletionRequest, ChatMessage

# ChatGPT 标准后备（Codex Pro 额度最大、上下文大、最可靠）。
GPT_BACKUP = "gpt-5.4"
# 输入超此长度(字符)→ 优先走大额度大上下文的 ChatGPT（Agnes 才 512K）。
LONG_INPUT_CHARS = 400_000
# 本身上下文/额度就大的模型，不因长度转走。
_BIG_ENOUGH = {"gpt-5.5", "gpt-5.4", "gpt-5.4-mini", "codex-spark", "glm"}

_LEDGER_ERROR_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")


def _closed_ledger_error_type(exc: BaseException) -> str:
    candidate = getattr(exc, "ledger_error_type", None)
    if isinstance(candidate, str) and _LEDGER_ERROR_TYPE.fullmatch(candidate):
        return candidate
    return type(exc).__name__[:128]


def _env_timeout(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) and value > 0 else default


# Unified interactive latency contract. ``None`` at a call site means these
# mandatory defaults, never an unbounded provider timeout (some providers use
# 180/300 seconds internally).
DEFAULT_ATTEMPT_TIMEOUT_SEC = _env_timeout("NACHUAN_FAILOVER_ATTEMPT_TIMEOUT", 25.0)
DEFAULT_TOTAL_TIMEOUT_SEC = _env_timeout("NACHUAN_FAILOVER_TOTAL_TIMEOUT", 55.0)
_MAX_DECLARED_CHAT_TIMEOUT_SEC = 300.0
_DECLARED_CHAT_TOTAL_GRACE_SEC = 15.0
DEFAULT_STREAM_ATTEMPT_TIMEOUT_SEC = _env_timeout(
    "NACHUAN_FAILOVER_STREAM_ATTEMPT_TIMEOUT", DEFAULT_TOTAL_TIMEOUT_SEC
)
DEFAULT_STREAM_TOTAL_TIMEOUT_SEC = _env_timeout(
    "NACHUAN_FAILOVER_STREAM_TOTAL_TIMEOUT", 10 * 60.0
)
DEFAULT_FIRST_CHUNK_TIMEOUT_SEC = _env_timeout(
    "NACHUAN_FAILOVER_FIRST_CHUNK_TIMEOUT", 12.0
)
DEFAULT_IDLE_CHUNK_TIMEOUT_SEC = _env_timeout(
    "NACHUAN_FAILOVER_IDLE_CHUNK_TIMEOUT", 20.0
)
_STREAM_CLOSE_TIMEOUT_SEC = 1.0
_STREAM_ROUTE_RECEIPT_VERSION = 1
_CHAT_SUBMISSION_OUTCOME_UNKNOWN = "chat_submission_outcome_unknown"
_STREAM_SUBMISSION_OUTCOME_UNKNOWN = "stream_submission_outcome_unknown"

# These failures happen before an HTTP request can reach the provider.  Other
# HTTPX transport failures may occur after some/all request bytes were sent, so
# financial accounting must not claim that the provider definitely did nothing.
_DEFINITELY_PRE_SUBMISSION_HTTP_ERRORS = (
    httpx.ConnectTimeout,
    httpx.ConnectError,
    httpx.PoolTimeout,
)
_MAX_EXCEPTION_CHAIN_DEPTH = 8


def _submission_unknown() -> ProviderSubmissionOutcomeUnknown:
    return ProviderSubmissionOutcomeUnknown(
        "上游可能已接收请求但结果未知，已停止自动切换模型",
        status_code=502,
    )


def _exception_chain_pre_submission_type(exc: BaseException) -> str | None:
    """Return the one transport class that proves no request reached upstream."""

    current: BaseException | None = exc
    seen: set[int] = set()
    proven: str | None = None
    for _ in range(_MAX_EXCEPTION_CHAIN_DEPTH):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if isinstance(current, (asyncio.TimeoutError, ProviderSubmissionOutcomeUnknown)):
            return None
        if isinstance(current, _DEFINITELY_PRE_SUBMISSION_HTTP_ERRORS):
            proven = type(current).__name__
        elif _transport_may_have_submitted(current):
            return None
        cause = current.__cause__
        if cause is not None:
            current = cause
        elif not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    return proven


class ChatFallbackResult(tuple):
    """True three-tuple with a process-private provider-call sidecar.

    Keeping the public value an actual tuple preserves old equality, JSON and
    unpacking behaviour.  The HMAC-verified ``provenance`` attribute is only an
    in-process hand-off and is deliberately absent from tuple repr/encoding.
    """

    provenance: dict[str, Any] | None

    def __new__(
        cls,
        response: dict[str, Any],
        served_model: str,
        route: Any,
        provenance: dict[str, Any] | None = None,
    ) -> "ChatFallbackResult":
        value = super().__new__(cls, (response, served_model, route))
        value.provenance = provenance
        return value

    @property
    def response(self) -> dict[str, Any]:
        return self[0]

    @property
    def served_model(self) -> str:
        return self[1]

    @property
    def route(self) -> Any:
        return self[2]

    def __reduce_ex__(self, protocol: int):  # noqa: ANN204 - preserve sidecar on copy
        del protocol
        return type(self), (*tuple(self), self.provenance)


def _transport_may_have_submitted(exc: BaseException) -> bool:
    if isinstance(exc, _DEFINITELY_PRE_SUBMISSION_HTTP_ERRORS):
        return False
    return isinstance(exc, (httpx.HTTPError, OSError))


def _exception_chain_may_have_submitted(exc: BaseException) -> bool:
    """Inspect bounded adapter wrapping without trusting only the outer type."""

    current: BaseException | None = exc
    seen: set[int] = set()
    for _ in range(_MAX_EXCEPTION_CHAIN_DEPTH):
        if current is None or id(current) in seen:
            return False
        seen.add(id(current))
        if (
            isinstance(current, (asyncio.TimeoutError, ProviderSubmissionOutcomeUnknown))
            or _transport_may_have_submitted(current)
        ):
            return True
        cause = current.__cause__
        if cause is not None:
            current = cause
        elif not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    return False


def _stream_route_receipt(requested: str, actual: str, route: Any) -> dict[str, Any]:
    """Freeze the committed route before hot reload can change attribution."""

    provider = getattr(route, "provider", None)
    return {
        "route_receipt_version": _STREAM_ROUTE_RECEIPT_VERSION,
        "requested": str(requested or ""),
        "actual": str(actual or ""),
        "provider": str(getattr(provider, "name", "") or ""),
        "upstream_model": str(getattr(route, "upstream_model", "") or ""),
        "tier": str(getattr(route, "tier", "") or ""),
    }

FALLBACKS: dict[str, list[str]] = {
    # 火山(配额少) → ChatGPT(可靠大额度) → Agnes(免费兜底)
    "glm": [GPT_BACKUP, "agnes-flash"],
    "kimi": [GPT_BACKUP, "agnes-flash"],
    "minimax": [GPT_BACKUP, "agnes-flash"],
    # Agnes(限速/上下文短) → ChatGPT
    "agnes-flash": [GPT_BACKUP, "glm"],
    # ChatGPT 自身：只在当前可用的同家族档位间互备。
    "gpt-5.5": ["gpt-5.4"],
    "gpt-5.4": ["gpt-5.4-mini"],
}


def _input_chars(req: ChatCompletionRequest) -> int:
    n = 0
    for m in req.messages:
        c = m.content
        if isinstance(c, str):
            n += len(c)
        elif isinstance(c, list):
            n += sum(len(str(b.get("text", ""))) for b in c if isinstance(b, dict))
    return n


# 超长输入压缩阈值：总输入超此字符数才尝试压（与 LONG_INPUT_CHARS 解耦，可更早触发省 token）。
COMPRESS_LONG_CHARS = int(os.getenv("COMPRESS_LONG_CHARS", "8000"))
# 单条消息短于此不压（短的省不下、也更易失真）。
_COMPRESS_MSG_MIN = 1200


def _maybe_compress_long(req: ChatCompletionRequest) -> ChatCompletionRequest:
    """输入很长时，有损压缩**冗余的长消息**省 token——但绝不动用户当前问题。

    策略：保留最后一条 user 消息（用户当前的真实提问/指令）原样不动；
    其余的长文本消息（system 提示、更早的历史/文档）才压。
    安全降级：未开启/不可用/异常 → 原 req 不变。
    """
    try:
        from orchestrator.compress import compress_text, enabled

        if not enabled() or _input_chars(req) < COMPRESS_LONG_CHARS:
            return req
        msgs = req.messages
        # 找最后一条 user 消息的下标——它是“用户当前问题”，绝不压。
        last_user = -1
        for i in range(len(msgs) - 1, -1, -1):
            if msgs[i].role == "user":
                last_user = i
                break
        changed = False
        new_msgs = []
        for i, m in enumerate(msgs):
            c = m.content
            if i != last_user and isinstance(c, str) and len(c) >= _COMPRESS_MSG_MIN:
                nc = compress_text(c, rate=0.5)
                if nc != c:
                    md = m.model_dump(exclude_none=True)
                    md["content"] = nc
                    new_msgs.append(ChatMessage(**md))
                    changed = True
                    continue
            new_msgs.append(m)
        if not changed:
            return req
        data = req.model_dump(exclude_none=True)
        data["messages"] = [m.model_dump(exclude_none=True) for m in new_msgs]
        return ChatCompletionRequest(**data)
    except Exception:  # noqa: BLE001
        return req


def fallback_chain(model: str, req: Optional[ChatCompletionRequest] = None) -> list[str]:
    # 超长输入 → 优先 ChatGPT（额度/上下文最大），原模型仍留作其次。
    if req is not None and model not in _BIG_ENOUGH and _input_chars(req) > LONG_INPUT_CHARS:
        chain = [GPT_BACKUP, model]
    else:
        chain = [model]
    for b in FALLBACKS.get(model, []):
        if b not in chain:
            chain.append(b)
    # 额度感知：把处于冷却(429/超额)的模型**挪到最后**——优先试还有额度的，但不彻底剔除
    #（全都冷却时仍兜底试一把）。稳定排序保留同类相对顺序。
    chain.sort(key=lambda m: 0 if quota_state.available(m) else 1)
    return chain


def _sub(req: ChatCompletionRequest, model_id: str) -> ChatCompletionRequest:
    data = req.model_dump(exclude_none=True)
    data["model"] = model_id
    return ChatCompletionRequest(**data)


def _timeout_or_default(value: float | None, default: float) -> float:
    """Return a finite positive timeout; ``None`` can never disable a budget."""

    try:
        candidate = default if value is None else float(value)
    except (TypeError, ValueError):
        candidate = default
    return candidate if math.isfinite(candidate) and candidate > 0 else default


def _declared_provider_timeout(
    provider: object,
    attribute: str,
) -> float | None:
    value = getattr(provider, attribute, None)
    if (
        not isinstance(attribute, str)
        or isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= _MAX_DECLARED_CHAT_TIMEOUT_SEC
    ):
        return None
    return float(value)


def _declared_provider_chat_timeout(provider: object) -> float | None:
    return _declared_provider_timeout(provider, "chat_timeout_s")


def _provider_chat_attempt_budget(
    provider: object,
    explicit_timeout: float | None,
) -> float:
    if explicit_timeout is not None:
        return _timeout_or_default(explicit_timeout, DEFAULT_ATTEMPT_TIMEOUT_SEC)
    return _declared_provider_chat_timeout(provider) or DEFAULT_ATTEMPT_TIMEOUT_SEC


def _provider_chat_total_budget(
    provider: object,
    explicit_timeout: float | None,
) -> float:
    if explicit_timeout is not None:
        return _timeout_or_default(explicit_timeout, DEFAULT_TOTAL_TIMEOUT_SEC)
    declared = _declared_provider_chat_timeout(provider)
    return max(
        DEFAULT_TOTAL_TIMEOUT_SEC,
        declared + _DECLARED_CHAT_TOTAL_GRACE_SEC
        if declared is not None
        else DEFAULT_TOTAL_TIMEOUT_SEC,
    )


def _provider_stream_budget(
    provider: object,
    attribute: str,
    explicit_timeout: float | None,
    default: float,
) -> float:
    if explicit_timeout is not None:
        return _timeout_or_default(explicit_timeout, default)
    return _declared_provider_timeout(provider, attribute) or default


def _provider_stream_total_budget(
    provider: object,
    explicit_timeout: float | None,
) -> float:
    if explicit_timeout is not None:
        return _timeout_or_default(explicit_timeout, DEFAULT_STREAM_TOTAL_TIMEOUT_SEC)
    direct = _declared_provider_timeout(provider, "stream_total_timeout_s")
    attempt = _declared_provider_timeout(
        provider,
        "stream_attempt_timeout_s",
    )
    declared = (
        direct
        if direct is not None
        else attempt + _DECLARED_CHAT_TOTAL_GRACE_SEC
        if attempt is not None
        else None
    )
    return max(
        DEFAULT_STREAM_TOTAL_TIMEOUT_SEC,
        declared if declared is not None else DEFAULT_STREAM_TOTAL_TIMEOUT_SEC,
    )


async def chat_once_with_deadline(
    provider: Any,
    req: ChatCompletionRequest,
    upstream_model: str,
    *,
    attempt_timeout: float | None = None,
    total_timeout: float | None = None,
    probe: bool = False,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
    commercial_budget: CommercialBudgetAuthorization | None = None,
) -> dict[str, Any]:
    """Run one provider chat with mandatory attempt and total deadlines.

    This is for model-specific operations where failover would change meaning
    (for example vision or a named panelist).  Since there is one attempt, the
    effective deadline is the smaller budget.  ``asyncio.wait_for`` cancels and
    awaits the provider coroutine both on timeout and when the caller cancels.
    """

    attempt_budget = _timeout_or_default(attempt_timeout, DEFAULT_ATTEMPT_TIMEOUT_SEC)
    # A named non-stream call shares the ordinary interactive total budget.
    # Explicit callers can still provide a smaller operation-specific deadline.
    total_budget = _timeout_or_default(total_timeout, DEFAULT_TOTAL_TIMEOUT_SEC)
    timeout = min(attempt_budget, total_budget)
    frozen_upstream = str(upstream_model)
    ledger = await resolve_provider_call_ledger_durable(provider_call_ledger)
    provider_attempt = await start_provider_attempt_durable(
        ledger,
        identity=ProviderRouteIdentity(
            requested_model=req.model,
            actual_model=req.model,
            provider=str(getattr(provider, "name", "") or ""),
            upstream_model=frozen_upstream,
        ),
        context=call_context or current_provider_call_context(),
        attempt=1,
        stream=False,
        commercial_budget=commercial_budget,
    )
    try:
        call = (
            provider.probe_chat(req, frozen_upstream)
            if probe
            else provider.chat(req, frozen_upstream)
        )
        result = await asyncio.wait_for(call, timeout=timeout)
    except asyncio.CancelledError as exc:
        await finish_provider_attempt_durable(
            provider_attempt,
            status="cancelled",
            error_type=_CHAT_SUBMISSION_OUTCOME_UNKNOWN,
            error_message=(
                "provider call cancelled after invocation; "
                "submission outcome is unknown"
            ),
        )
        raise
    except asyncio.TimeoutError:
        await finish_provider_attempt_durable(
            provider_attempt,
            status="timeout",
            error_type=_CHAT_SUBMISSION_OUTCOME_UNKNOWN,
            error_message=(
                f"provider attempt timed out after {timeout:.3f}s; "
                "submission outcome is unknown"
            ),
        )
        raise
    except (httpx.HTTPError, OSError) as exc:
        await finish_provider_attempt_durable(
            provider_attempt,
            status="provider_error",
            error_type=(
                _CHAT_SUBMISSION_OUTCOME_UNKNOWN
                if _transport_may_have_submitted(exc)
                else _closed_ledger_error_type(exc)
            ),
            error_message=str(exc),
        )
        raise
    except Exception as exc:
        await finish_provider_attempt_durable(
            provider_attempt,
            status="provider_error",
            error_type=(
                _CHAT_SUBMISSION_OUTCOME_UNKNOWN
                if _exception_chain_may_have_submitted(exc)
                else _closed_ledger_error_type(exc)
            ),
            error_message=str(exc),
        )
        raise
    await finish_provider_attempt_durable(
        provider_attempt,
        status="success",
        observed_model=observed_model_from_payload(result),
        usage=financial_usage_from_payload(result),
    )
    return result


def _stream_error(message: str, error_type: str, *, status_code: int = 502) -> dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": error_type,
            "status_code": status_code,
        }
    }


def _public_provider_stream_error(
    exc: object,
    error_type: str = "provider_error",
) -> dict[str, Any]:
    """Build a public SSE terminal without returning provider-owned text."""

    raw_status = getattr(exc, "status_code", 502)
    try:
        status_code = int(raw_status)
    except (TypeError, ValueError, OverflowError):
        status_code = 502
    if not 400 <= status_code <= 599:
        status_code = 502
    if isinstance(exc, ProviderSubmissionOutcomeUnknown):
        message = "上游可能已接收请求但结果未知，请勿自动重试"
    else:
        message = friendly_status(status_code)
    return _stream_error(message, error_type, status_code=status_code)


def _chunk_error(chunk: Any) -> str:
    if not isinstance(chunk, dict) or not isinstance(chunk.get("error"), dict):
        return ""
    return str(chunk["error"].get("message") or "上游返回流式错误")


async def _close_stream(stream: Any) -> None:
    """Best-effort bounded close for an abandoned provider async iterator."""

    close = getattr(stream, "aclose", None)
    if not callable(close):
        return
    try:
        await asyncio.wait_for(close(), timeout=_STREAM_CLOSE_TIMEOUT_SEC)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 -- close failure must not mask the primary error
        return


class _StreamAttemptAccounting:
    """Collect provider-reported stream evidence and finalize exactly once."""

    def __init__(self, attempt: Any) -> None:
        self._attempt = attempt
        self._observed_model: str | None = None
        self._usage: dict[str, int | None] = {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
            "cached_tokens": None,
            "cost_microusd": None,
        }
        self.finished = False

    def observe(self, payload: Any) -> None:
        if self._observed_model is None:
            self._observed_model = observed_model_from_payload(payload)
        for key, value in financial_usage_from_payload(payload).items():
            if value is not None:
                self._usage[key] = value

    async def finish(
        self,
        status: str,
        *,
        error_type: str | None = None,
        error_message: str | None = None,
    ) -> bool:
        if self.finished:
            return False
        changed = await finish_provider_attempt_durable(
            self._attempt,
            status=status,
            observed_model=self._observed_model,
            usage=self._usage,
            error_type=error_type,
            error_message=error_message,
        )
        self.finished = True
        return changed


async def chat_with_fallback(
    router: Any,
    req: ChatCompletionRequest,
    *,
    attempt_timeout: float | None = None,
    total_timeout: float | None = None,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
    commercial_budget: CommercialBudgetAuthorization | None = None,
):
    """按备用链尝试非流式调用。

    可选延迟预算只用于对用户可见的短交互。单个上游超时后诚实返回
    “提交结果未知”且停止备用链；只有可证明发生在提交前的连接失败才切换，
    从机制上避免同一用户操作被模型商重复执行或收费。
    """
    chain = fallback_chain(req.model, req)
    total_budget = _timeout_or_default(total_timeout, DEFAULT_TOTAL_TIMEOUT_SEC)
    req = _maybe_compress_long(req)  # 超长输入：有损压冗余消息省 token（不动用户问题）
    last: ProviderError | None = None
    operation_started = time.monotonic()
    deadline = operation_started + total_budget
    ledger = await resolve_provider_call_ledger_durable(provider_call_ledger)
    context = call_context or current_provider_call_context()
    attempt_number = 0
    for i, mid in enumerate(chain):
        route = router.resolve(mid)
        if route is None:
            continue
        provider = route.provider
        if total_timeout is None:
            deadline = max(
                deadline,
                operation_started + _provider_chat_total_budget(provider, None),
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last = ProviderError("消息渠道总延迟预算已耗尽", status_code=504)
            break
        timeout = min(
            _provider_chat_attempt_budget(provider, attempt_timeout),
            remaining,
        )
        upstream_model = str(route.upstream_model)
        provider_request = _sub(req, mid)
        attempt_number += 1
        provider_attempt = await start_provider_attempt_durable(
            ledger,
            identity=ProviderRouteIdentity(
                requested_model=req.model,
                actual_model=mid,
                provider=str(getattr(provider, "name", "") or ""),
                upstream_model=upstream_model,
            ),
            context=context,
            attempt=attempt_number,
            stream=False,
            commercial_budget=commercial_budget,
        )
        try:
            call = provider.chat(provider_request, upstream_model)
            res = await asyncio.wait_for(call, timeout=timeout)
        except asyncio.CancelledError as exc:
            await finish_provider_attempt_durable(
                provider_attempt,
                status="cancelled",
                error_type=_CHAT_SUBMISSION_OUTCOME_UNKNOWN,
                error_message=(
                    "provider call cancelled after invocation; "
                    "submission outcome is unknown"
                ),
            )
            raise
        except asyncio.TimeoutError:
            await finish_provider_attempt_durable(
                provider_attempt,
                status="timeout",
                error_type=_CHAT_SUBMISSION_OUTCOME_UNKNOWN,
                error_message=(
                    f"provider attempt timed out after {timeout:.3f}s; "
                    "submission outcome is unknown"
                ),
            )
            quota_state.mark_error(mid)
            raise _submission_unknown()
        except ProviderSubmissionOutcomeUnknown as e:
            await finish_provider_attempt_durable(
                provider_attempt,
                status="provider_error",
                error_type=_CHAT_SUBMISSION_OUTCOME_UNKNOWN,
                error_message=str(e),
            )
            quota_state.mark_error(mid)
            raise
        except ProviderError as e:
            pre_submission_type = _exception_chain_pre_submission_type(e)
            await finish_provider_attempt_durable(
                provider_attempt,
                status="provider_error",
                error_type=(
                    pre_submission_type or _CHAT_SUBMISSION_OUTCOME_UNKNOWN
                ),
                error_message=str(e),
            )
            if pre_submission_type is None:
                if not quota_state.mark_if_quota(mid, e):
                    quota_state.mark_error(mid)
                raise _submission_unknown() from e
            last = e
            if not quota_state.mark_if_quota(mid, e):  # 额度/限流错 → 记冷却
                quota_state.mark_error(mid)  # 非额度失败(CLI超时/进程挂/5xx) → 连败熔断，别反复撞墙
        except (httpx.HTTPError, OSError) as e:
            pre_submission_type = _exception_chain_pre_submission_type(e)
            await finish_provider_attempt_durable(
                provider_attempt,
                status="provider_error",
                error_type=(
                    pre_submission_type or _CHAT_SUBMISSION_OUTCOME_UNKNOWN
                ),
                error_message=str(e),
            )
            if pre_submission_type is None:
                quota_state.mark_error(mid)
                raise _submission_unknown() from e
            # Only a bounded exception chain proving ConnectError,
            # ConnectTimeout or PoolTimeout can reach this branch.
            last = ProviderError(f"上游连接在提交前失败：{e}")
            quota_state.mark_error(mid)
        except Exception as exc:
            pre_submission_type = _exception_chain_pre_submission_type(exc)
            await finish_provider_attempt_durable(
                provider_attempt,
                status="provider_error",
                error_type=(
                    pre_submission_type or _CHAT_SUBMISSION_OUTCOME_UNKNOWN
                ),
                error_message=str(exc),
            )
            if pre_submission_type is None:
                quota_state.mark_error(mid)
                raise _submission_unknown() from exc
            last = ProviderError(f"upstream pre-submission transport error: {exc}")
            quota_state.mark_error(mid)
        else:
            ledger_terminal_committed = await finish_provider_attempt_durable(
                provider_attempt,
                status="success",
                observed_model=observed_model_from_payload(res),
                usage=financial_usage_from_payload(res),
            )
            provenance = capture_provider_call_provenance(
                request_payload=provider_request.model_dump(exclude_none=True),
                response=res,
                requested_model=req.model,
                actual_model=mid,
                provider=str(getattr(provider, "name", "") or ""),
                upstream_model=upstream_model,
                route=route,
                call_id=str(provider_attempt.call_id or ""),
                attempt=attempt_number,
                call_context=context,
                ledger_terminal_committed=bool(ledger_terminal_committed),
            )
            if i > 0:
                # Provider results may be cached/reused by the adapter.  Route
                # metadata belongs to this request and must not taint that
                # provider-owned dictionary.
                res = dict(res)
                res["_served_by"] = {"requested": req.model, "actual": mid}
            quota_state.mark_ok(mid)  # 成功清连败计数（防偶发抖动累积成熔断）
            return ChatFallbackResult(res, mid, route, provenance)
    raise last or ProviderError(f"无可用模型: {req.model}", status_code=404)


async def stream_with_fallback(
    router: Any,
    req: ChatCompletionRequest,
    *,
    attempt_timeout: float | None = None,
    total_timeout: float | None = None,
    first_chunk_timeout: float | None = None,
    idle_chunk_timeout: float | None = None,
    provider_call_ledger: ProviderCallLedgerProtocol | None = None,
    call_context: ProviderCallContext | None = None,
    commercial_budget: CommercialBudgetAuthorization | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """Stream with bounded pre-commit failover and post-commit termination.

    Before the first chunk, a slow/failed/empty provider is closed and the next
    route may be tried. Once any chunk is exposed, the route is committed: an
    idle timeout or provider failure yields one explicit terminal error and
    never replays the answer from a backup model.
    """

    chain = fallback_chain(req.model, req)
    total_budget = _timeout_or_default(total_timeout, DEFAULT_STREAM_TOTAL_TIMEOUT_SEC)
    req = _maybe_compress_long(req)  # 超长输入：有损压冗余消息省 token（不动用户问题）
    last: ProviderError | None = None
    last_type = "provider_error"
    operation_started = time.monotonic()
    deadline = operation_started + total_budget
    ledger = await resolve_provider_call_ledger_durable(provider_call_ledger)
    context = call_context or current_provider_call_context()
    attempt_number = 0
    for i, mid in enumerate(chain):
        route = router.resolve(mid)
        if route is None:
            continue
        provider = route.provider
        if total_timeout is None:
            deadline = max(
                deadline,
                operation_started + _provider_stream_total_budget(provider, None),
            )
        # Freeze scalar attribution immediately after resolution.  A long
        # first-token wait must not let an in-place hot reload rewrite the
        # provider/upstream/tier later recorded for this invocation.
        attempt_receipt = _stream_route_receipt(req.model, mid, route)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last = ProviderError("流式响应总延迟预算已耗尽", status_code=504)
            last_type = "stream_total_timeout"
            break
        route_attempt_budget = _provider_stream_budget(
            provider,
            "stream_attempt_timeout_s",
            attempt_timeout,
            DEFAULT_STREAM_ATTEMPT_TIMEOUT_SEC,
        )
        route_first_budget = _provider_stream_budget(
            provider,
            "stream_first_chunk_timeout_s",
            first_chunk_timeout,
            DEFAULT_FIRST_CHUNK_TIMEOUT_SEC,
        )
        route_idle_budget = _provider_stream_budget(
            provider,
            "stream_idle_timeout_s",
            idle_chunk_timeout,
            DEFAULT_IDLE_CHUNK_TIMEOUT_SEC,
        )
        attempt_deadline = min(deadline, time.monotonic() + route_attempt_budget)
        upstream_model = str(route.upstream_model)
        provider_request = _sub(req, mid)
        attempt_number += 1
        provider_attempt = await start_provider_attempt_durable(
            ledger,
            identity=ProviderRouteIdentity(
                requested_model=req.model,
                actual_model=mid,
                provider=str(getattr(provider, "name", "") or ""),
                upstream_model=upstream_model,
            ),
            context=context,
            attempt=attempt_number,
            stream=True,
            commercial_budget=commercial_budget,
        )
        accounting = _StreamAttemptAccounting(provider_attempt)
        gen = None
        committed = False
        try:
            gen = provider.stream(provider_request, upstream_model)
            try:
                now = time.monotonic()
                first_total_remaining = deadline - now
                first_attempt_remaining = attempt_deadline - now
                if deadline <= attempt_deadline and first_total_remaining <= route_first_budget:
                    first_timeout_type = "stream_total_timeout"
                elif attempt_deadline < deadline and first_attempt_remaining <= route_first_budget:
                    first_timeout_type = "stream_attempt_timeout"
                else:
                    first_timeout_type = "first_chunk_timeout"
                first = await asyncio.wait_for(
                    gen.__anext__(),
                    timeout=min(
                        route_first_budget,
                        max(0.001, first_attempt_remaining),
                        max(0.001, first_total_remaining),
                    ),
                )
            except StopAsyncIteration:
                await accounting.finish(
                    "empty_stream",
                    error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                    error_message=(
                        f"model {mid} returned an empty stream after invocation; "
                        "submission outcome is unknown"
                    ),
                )
                quota_state.mark_error(mid)
                raise _submission_unknown()
            except asyncio.TimeoutError:
                await accounting.finish(
                    "timeout",
                    error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                    error_message=(
                        f"model {mid} timed out before first chunk "
                        f"({first_timeout_type}); submission outcome is unknown"
                    ),
                )
                quota_state.mark_error(mid)
                raise _submission_unknown()
            except ProviderSubmissionOutcomeUnknown:
                raise
            except ProviderError as exc:
                pre_submission_type = _exception_chain_pre_submission_type(exc)
                await accounting.finish(
                    "provider_error",
                    error_type=(
                        pre_submission_type or _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                    ),
                    error_message=str(exc),
                )
                if pre_submission_type is None:
                    if not quota_state.mark_if_quota(mid, exc):
                        quota_state.mark_error(mid)
                    raise _submission_unknown() from exc
                last = exc
                last_type = "provider_error"
                if not quota_state.mark_if_quota(mid, exc):
                    quota_state.mark_error(mid)
                continue
            except (httpx.HTTPError, OSError) as exc:
                pre_submission_type = _exception_chain_pre_submission_type(exc)
                await accounting.finish(
                    "provider_error",
                    error_type=(
                        pre_submission_type or _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                    ),
                    error_message=str(exc),
                )
                if pre_submission_type is None:
                    quota_state.mark_error(mid)
                    raise _submission_unknown() from exc
                last = ProviderError(f"上游连接在提交前失败：{exc}")
                last_type = "provider_error"
                quota_state.mark_error(mid)
                continue

            if not isinstance(first, dict):
                await accounting.finish(
                    "provider_error",
                    error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                    error_message=(
                        f"model {mid} returned a non-dict first chunk after invocation; "
                        "submission outcome is unknown"
                    ),
                )
                quota_state.mark_error(mid)
                raise _submission_unknown()
            first_error = _chunk_error(first)
            if first_error:
                accounting.observe(first)
                await accounting.finish(
                    "provider_error",
                    error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                    error_message=(
                        "provider returned an error chunk after invocation; "
                        "submission outcome is unknown"
                    ),
                )
                quota_state.mark_error(mid)
                raise _submission_unknown()

            accounting.observe(first)
            committed = True
            served_receipt = attempt_receipt
            # Always attach the invocation-time route snapshot, including for
            # the primary route.  Accounting must not re-resolve a mutable
            # router after a long-running stream.
            first = dict(first)
            first["_served_by"] = served_receipt
            quota_state.mark_ok(mid)
            yield first

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    await accounting.finish(
                        "timeout",
                        error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                        error_message=(
                            "stream total timeout after first chunk; "
                            "submission outcome is unknown"
                        ),
                    )
                    # This is our local end-to-end policy budget, not evidence
                    # that the provider is unhealthy.  Do not poison its
                    # circuit-breaker score after a successfully committed stream.
                    yield _stream_error(
                        "流式响应总延迟预算已耗尽",
                        "stream_total_timeout",
                        status_code=504,
                    )
                    return
                if remaining <= route_idle_budget:
                    timeout_type = "stream_total_timeout"
                else:
                    timeout_type = "stream_idle_timeout"
                try:
                    chunk = await asyncio.wait_for(
                        gen.__anext__(),
                        timeout=min(route_idle_budget, remaining),
                    )
                except StopAsyncIteration:
                    await accounting.finish("success")
                    return
                except asyncio.TimeoutError:
                    await accounting.finish(
                        "timeout",
                        error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                        error_message=(
                            f"model {mid} stream timed out after first chunk "
                            f"({timeout_type}); submission outcome is unknown"
                        ),
                    )
                    if timeout_type != "stream_total_timeout":
                        # An idle timeout is upstream liveness evidence; a total
                        # timeout is only the caller's local policy deadline.
                        quota_state.mark_error(mid)
                    yield _stream_error(
                        (
                            "流式响应总延迟预算已耗尽"
                            if timeout_type == "stream_total_timeout"
                            else f"模型 {mid} 在输出后长时间无新数据，流已终止"
                        ),
                        timeout_type,
                        status_code=504,
                    )
                    return
                except ProviderError as exc:
                    await accounting.finish(
                        "stream_interrupted",
                        error_type=(
                            _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                            if _exception_chain_may_have_submitted(exc)
                            else _closed_ledger_error_type(exc)
                        ),
                        error_message=str(exc),
                    )
                    if not quota_state.mark_if_quota(mid, exc):
                        quota_state.mark_error(mid)
                    yield _public_provider_stream_error(exc)
                    return
                except (httpx.HTTPError, OSError) as exc:
                    await accounting.finish(
                        "stream_interrupted",
                        error_type=(
                            _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                            if _transport_may_have_submitted(exc)
                            else type(exc).__name__
                        ),
                        error_message=str(exc),
                    )
                    quota_state.mark_error(mid)
                    yield _public_provider_stream_error(exc)
                    return

                if not isinstance(chunk, dict):
                    await accounting.finish(
                        "stream_interrupted",
                        error_type="invalid_stream_chunk",
                        error_message="provider returned a non-dict stream chunk",
                    )
                    quota_state.mark_error(mid)
                    yield _stream_error("上游返回非法流式数据", "provider_error")
                    return
                chunk_error = _chunk_error(chunk)
                if chunk_error:
                    accounting.observe(chunk)
                    await accounting.finish(
                        "stream_interrupted",
                        error_type="provider_error_chunk",
                        error_message=chunk_error,
                    )
                    quota_state.mark_error(mid)
                    yield _public_provider_stream_error(
                        ProviderError(chunk_error, status_code=502)
                    )
                    return
                # Provider-owned chunks cannot replace the trusted receipt
                # already emitted on the first committed chunk.
                if "_served_by" in chunk:
                    chunk = dict(chunk)
                    chunk.pop("_served_by", None)
                accounting.observe(chunk)
                yield chunk
        except asyncio.CancelledError as exc:
            await accounting.finish(
                "cancelled",
                error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                error_message=(
                    "stream provider call cancelled after invocation; "
                    "submission outcome is unknown"
                ),
            )
            raise
        except ProviderSubmissionOutcomeUnknown as exc:
            await accounting.finish(
                "stream_interrupted" if committed else "provider_error",
                error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                error_message=str(exc),
            )
            quota_state.mark_error(mid)
            if commercial_budget is not None:
                raise
            if committed:
                yield _public_provider_stream_error(exc)
                return
            last = exc
            last_type = "provider_error"
            break
        except ProviderError as exc:
            pre_submission_type = _exception_chain_pre_submission_type(exc)
            await accounting.finish(
                "stream_interrupted" if committed else "provider_error",
                error_type=(
                    pre_submission_type or _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                ),
                error_message=str(exc),
            )
            if committed:
                if not quota_state.mark_if_quota(mid, exc):
                    quota_state.mark_error(mid)
                yield _public_provider_stream_error(exc)
                return
            if pre_submission_type is None:
                if not quota_state.mark_if_quota(mid, exc):
                    quota_state.mark_error(mid)
                if commercial_budget is not None:
                    raise _submission_unknown() from exc
                last = _submission_unknown()
                last_type = "provider_error"
                break
            last = exc
            last_type = "provider_error"
            if not quota_state.mark_if_quota(mid, exc):
                quota_state.mark_error(mid)
        except (httpx.HTTPError, OSError) as exc:
            pre_submission_type = _exception_chain_pre_submission_type(exc)
            await accounting.finish(
                "stream_interrupted" if committed else "provider_error",
                error_type=(
                    pre_submission_type or _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                ),
                error_message=str(exc),
            )
            wrapped = ProviderError(f"上游网络/TLS 错：{exc}")
            quota_state.mark_error(mid)
            if committed:
                yield _public_provider_stream_error(wrapped)
                return
            if pre_submission_type is None:
                if commercial_budget is not None:
                    raise _submission_unknown() from exc
                last = _submission_unknown()
                last_type = "provider_error"
                break
            last = wrapped
            last_type = "provider_error"
        except Exception as exc:  # noqa: BLE001 -- malformed provider stream must not tear down SSE
            pre_submission_type = _exception_chain_pre_submission_type(exc)
            await accounting.finish(
                "stream_interrupted" if committed else "provider_error",
                error_type=(
                    pre_submission_type or _STREAM_SUBMISSION_OUTCOME_UNKNOWN
                ),
                error_message=str(exc),
            )
            wrapped = ProviderError(f"模型 {mid} 流式响应异常：{exc}")
            quota_state.mark_error(mid)
            if committed:
                yield _public_provider_stream_error(wrapped)
                return
            if pre_submission_type is None:
                if commercial_budget is not None:
                    raise _submission_unknown() from exc
                last = _submission_unknown()
                last_type = "provider_error"
                break
            last = wrapped
            last_type = "provider_error"
        finally:
            # Commit the financial terminal before awaiting provider cleanup.
            # A hostile/broken ``aclose`` may itself raise cancellation; it must
            # never strand a real upstream attempt in ``started``.
            try:
                if not accounting.finished:
                    await accounting.finish(
                        "cancelled",
                        error_type=_STREAM_SUBMISSION_OUTCOME_UNKNOWN,
                        error_message=(
                            "stream consumer closed after provider invocation; "
                            "submission outcome is unknown"
                        ),
                    )
            finally:
                if gen is not None:
                    await _close_stream(gen)

    terminal = last or ProviderError(f"无可用模型: {req.model}", status_code=404)
    if last_type == "provider_error":
        yield _public_provider_stream_error(terminal, last_type)
    else:
        # These messages are generated locally from bounded model identifiers
        # and fixed timeout/empty-stream wording, never provider response text.
        yield _stream_error(
            str(terminal), last_type, status_code=terminal.status_code
        )
