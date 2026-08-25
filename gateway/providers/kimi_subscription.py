"""Text-only provider for a user's contained Kimi Code subscription worker."""

from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Mapping
from typing import Any, AsyncIterator, Final, Literal, Protocol

from gateway.kimi_subscription_worker import (
    KimiInvocation,
    KimiSubscriptionError,
    KimiSubscriptionWorker,
)
from gateway.providers.base import ChatProvider, ProviderError
from gateway.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    Usage,
    _gen_id,
    final_chunk,
    text_chunk,
)
from gateway.subscription_cli_discovery import SubscriptionCliDiscovery


_CONNECTOR_ID = "kimi-code"
_PUBLIC_MODEL_ID = "kimi-code-subscription"
_PUBLIC_UNAVAILABLE_MESSAGE = "Kimi Code subscription turn is unavailable"
KimiConnectionReasonCode = Literal[
    "reauth_required",
    "text_contract_rejected",
    "connector_unavailable",
]
KIMI_CONNECTION_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        "reauth_required",
        "text_contract_rejected",
        "connector_unavailable",
    }
)
_REAUTH_WORKER_CODES: Final[frozenset[str]] = frozenset(
    {"auth_required", "reauth_required"}
)
_TEXT_CONTRACT_WORKER_CODES: Final[frozenset[str]] = frozenset(
    {
        "cli_output_rejected",
        "cli_result_rejected",
        "helper_protocol_rejected",
        "helper_request_rejected",
        "operation_rejected",
        "prompt_encoding_rejected",
        "prompt_size_rejected",
        "protocol_rejected",
        "served_model_receipt_unverified",
        "stop_reason_rejected",
        "text_contract_rejected",
        "tool_activity_rejected",
        "worker_result_rejected",
    }
)
_DIAGNOSTIC_WORKER_CODES: Final[frozenset[str]] = frozenset(
    {*_REAUTH_WORKER_CODES, *_TEXT_CONTRACT_WORKER_CODES, "agent_rpc_error"}
)
_TEXT_ONLY_PREFIX = (
    "You are answering one text-only conversation through Nachuan. "
    "Do not run commands, inspect files, browse the web, call tools, or modify "
    "the host. Return only the assistant answer.\n\nConversation:\n"
)
_TOOL_FIELDS = frozenset(
    {
        "functions",
        "function_call",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
    }
)
_ALLOWED_ROLES = frozenset({"system", "developer", "user", "assistant"})

# Kimi Code 0.27 ACP 的 initialize / session/new / session/prompt 响应精确键集
# （gateway/kimi_acp_product_protocol.py 闭管道校验）不含服役型号字段；
# configOptions 里的 model 只是请求别名 kimi-code/kimi-for-coding 的回显确认，不是证据。
_ACTUAL_SERVED_RECEIPT: Final = {
    "status": "unproven",
    "model": None,
    "evidence": "kimi_acp_prompt_response_has_no_served_model_field",
}


def _closed_connection_reason(code: object) -> KimiConnectionReasonCode:
    if isinstance(code, str) and code in _REAUTH_WORKER_CODES:
        return "reauth_required"
    if isinstance(code, str) and code in _TEXT_CONTRACT_WORKER_CODES:
        return "text_contract_rejected"
    return "connector_unavailable"


class KimiSubscriptionProviderError(ProviderError):
    """Fixed-text provider failure carrying only a closed public reason."""

    def __init__(
        self,
        *,
        reason_code: object,
        status_code: int = 503,
    ) -> None:
        diagnostic_code = (
            reason_code
            if isinstance(reason_code, str)
            and reason_code in _DIAGNOSTIC_WORKER_CODES
            else "connector_unavailable"
        )
        self.diagnostic_code = diagnostic_code
        self.reason_code = _closed_connection_reason(reason_code)
        super().__init__(
            _PUBLIC_UNAVAILABLE_MESSAGE,
            status_code=status_code,
            ledger_error_type=f"KimiSubscriptionProviderError.{diagnostic_code}",
        )


class KimiInvokeWorker(Protocol):
    def invoke(
        self,
        prompt: str,
        *,
        cancellation_event: threading.Event,
    ) -> KimiInvocation: ...


def _has_non_text_content(req: ChatCompletionRequest) -> bool:
    for message in req.messages:
        if message.role.casefold() not in _ALLOWED_ROLES:
            return True
        content = message.content
        if content is None or isinstance(content, str):
            continue
        if not isinstance(content, list):
            return True
        for block in content:
            if (
                not isinstance(block, dict)
                or block.get("type") not in {None, "text"}
                or not isinstance(block.get("text", ""), str)
                or set(block) - {"type", "text"}
            ):
                return True
    return False


def _has_tool_contract(req: ChatCompletionRequest) -> bool:
    extras = req.model_extra or {}
    return any(name in extras and extras[name] is not None for name in _TOOL_FIELDS)


def _subscription_usage() -> Usage:
    return Usage(
        prompt_tokens=None,
        completion_tokens=None,
        total_tokens=None,
        cost_basis="subscription_unallocated",
        cost_attribution_basis="kimi_code_cli_turn",
    )


def _validated_invocation(value: object) -> KimiInvocation:
    if (
        not isinstance(value, KimiInvocation)
        or value.model_id != _PUBLIC_MODEL_ID
        or value.actual_served_model is not None
        or not isinstance(value.text, str)
        or not value.text
        or not isinstance(value.session_id, str)
        or not value.session_id
    ):
        raise KimiSubscriptionError("worker_result_rejected")
    return value


def _invoke_with_cancellation(
    worker: KimiInvokeWorker,
    prompt: str,
    cancellation_event: threading.Event,
) -> KimiInvocation:
    return worker.invoke(
        prompt,
        cancellation_event=cancellation_event,
    )


def _public_worker_error(exc: KimiSubscriptionError) -> ProviderError:
    status_code = 413 if exc.code == "prompt_size_rejected" else 503
    return KimiSubscriptionProviderError(
        reason_code=(
            exc.code
            if exc.process_exit_verified
            else "connector_unavailable"
        ),
        status_code=status_code,
    )


class KimiSubscriptionProvider(ChatProvider):
    """Expose one generic model without asserting an upstream served identity."""

    connection_probe_timeout_s = 180.0

    def __init__(
        self,
        name: str = _CONNECTOR_ID,
        *,
        timeout_s: float = 180.0,
        environment: Mapping[str, str] | None = None,
        worker: KimiInvokeWorker | None = None,
    ) -> None:
        self.name = name
        self.timeout_s = timeout_s
        source = dict(os.environ if environment is None else environment)
        descriptor = next(
            (
                item
                for item in SubscriptionCliDiscovery(
                    environment=source
                ).list_public()
                if item.get("id") == _CONNECTOR_ID
            ),
            None,
        )
        self.enabled = (
            descriptor is not None
            and descriptor.get("state") == "installed_unprobed"
        )
        self._worker: KimiInvokeWorker | None = (
            worker
            if self.enabled and worker is not None
            else KimiSubscriptionWorker(environment=source)
            if self.enabled
            else None
        )

    def expected_model_family(self, upstream_model: str) -> None:
        del upstream_model
        return None

    def verify_model_identity(
        self,
        upstream_model: str,
        observed_model: str,
    ) -> None:
        del upstream_model, observed_model
        return None

    def actual_served_receipt(self) -> dict[str, Any]:
        """Return the honest verification-time served-identity receipt.

        The ACP prompt response carries only ``stopReason``; no served-model
        field exists on the wire, so this stays ``unproven`` and never echoes
        the internal ``kimi-code/kimi-for-coding`` request alias as evidence.
        """

        return dict(_ACTUAL_SERVED_RECEIPT)

    def _prompt(self, req: ChatCompletionRequest) -> str:
        if _has_non_text_content(req):
            raise ProviderError(
                "Kimi Code subscription connection supports text messages only",
                status_code=400,
            )
        if _has_tool_contract(req):
            raise ProviderError(
                "Kimi Code subscription connection does not expose tool contracts",
                status_code=400,
            )
        return _TEXT_ONLY_PREFIX + req.prompt_text()

    async def _wait_for_cancelled_worker(
        self,
        future: asyncio.Future[KimiInvocation],
        cancellation_event: threading.Event,
    ) -> None:
        cancellation_event.set()
        while not future.done():
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                cancellation_event.set()
                continue
            except Exception:
                break
        try:
            _validated_invocation(future.result())
        except KimiSubscriptionError as exc:
            if exc.process_exit_verified:
                return
            raise ProviderError(
                "Kimi Code subscription process cleanup is unverified",
                status_code=503,
            ) from None
        except Exception:
            raise ProviderError(
                "Kimi Code subscription process cleanup is unverified",
                status_code=503,
            ) from None

    async def _invoke(self, req: ChatCompletionRequest) -> KimiInvocation:
        if not self.enabled or self._worker is None:
            raise ProviderError(
                "Kimi Code subscription CLI is not explicitly attested",
                status_code=503,
            )
        prompt = self._prompt(req)
        cancellation_event = threading.Event()
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(
            None,
            _invoke_with_cancellation,
            self._worker,
            prompt,
            cancellation_event,
        )
        try:
            invocation = await asyncio.shield(future)
        except asyncio.CancelledError as cancelled:
            await self._wait_for_cancelled_worker(future, cancellation_event)
            raise cancelled
        except KimiSubscriptionError as exc:
            raise _public_worker_error(exc) from None
        except Exception:
            raise ProviderError(
                "Kimi Code subscription turn is unavailable",
                status_code=503,
            ) from None
        try:
            return _validated_invocation(invocation)
        except KimiSubscriptionError as exc:
            raise _public_worker_error(exc) from None

    async def agent_exec(
        self,
        task: str,
        *,
        upstream_model: str,
        workdir: str,
        sandbox: str = "workspace-write",
    ) -> dict[str, Any]:
        del task, upstream_model, workdir, sandbox
        raise ProviderError(
            "Kimi Code host agent execution is not exposed by the text-only subscription worker",
            status_code=503,
        )

    async def chat(
        self,
        req: ChatCompletionRequest,
        upstream_model: str,
    ) -> dict[str, Any]:
        del upstream_model
        invocation = await self._invoke(req)
        return ChatCompletionResponse.from_text(
            model=_PUBLIC_MODEL_ID,
            text=invocation.text,
            usage=_subscription_usage(),
        ).model_dump()

    async def stream(
        self,
        req: ChatCompletionRequest,
        upstream_model: str,
    ) -> AsyncIterator[dict[str, Any]]:
        del upstream_model
        invocation = await self._invoke(req)
        chunk_id = _gen_id("chatcmpl")
        yield text_chunk(
            model=_PUBLIC_MODEL_ID,
            delta_text=invocation.text,
            chunk_id=chunk_id,
            role="assistant",
        )
        yield final_chunk(
            model=_PUBLIC_MODEL_ID,
            chunk_id=chunk_id,
            usage=_subscription_usage().model_dump(),
        )


__all__ = ["KimiInvokeWorker", "KimiSubscriptionProvider"]
