"""User-owned Codex subscription provider backed by the contained CLI worker.

This adapter is deliberately text-only.  It does not expose Codex agent tools,
does not read login files, does not claim a served GPT model identity, and does
not place prompts in argv.  The worker owns the official ``codex exec`` JSONL
turn inside an empty read-only workspace.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from typing import Any, AsyncIterator, Protocol

from gateway.codex_subscription_worker import (
    CodexInvocation,
    CodexSubscriptionError,
    CodexSubscriptionWorker,
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


class CodexInvokeWorker(Protocol):
    def invoke(self, prompt: str) -> CodexInvocation: ...


def _has_non_text_content(req: ChatCompletionRequest) -> bool:
    for message in req.messages:
        if message.role.casefold() not in _ALLOWED_ROLES:
            return True
        if not isinstance(message.content, list):
            continue
        for block in message.content:
            if (
                not isinstance(block, dict)
                or block.get("type") not in {None, "text"}
                or not isinstance(block.get("text", ""), str)
            ):
                return True
    return False


def _has_tool_contract(req: ChatCompletionRequest) -> bool:
    extras = req.model_extra or {}
    return any(name in extras and extras[name] is not None for name in _TOOL_FIELDS)


# codex exec --json 的 ThreadEvent 闭集（codex-rs/exec/src/exec_events.rs @
# rust-v0.144.x）不含任何服役型号字段；账号路由的真实模型身份无法从官方
# 线文证明，回执只能如实记 unproven——绝不回退成配置别名。
_ACTUAL_SERVED_RECEIPT = {
    "status": "unproven",
    "model": None,
    "evidence": "codex_exec_jsonl_turn_has_no_served_model_field",
}


def _subscription_usage(invocation: CodexInvocation) -> Usage:
    return Usage(
        prompt_tokens=invocation.prompt_tokens,
        completion_tokens=invocation.completion_tokens,
        total_tokens=invocation.prompt_tokens + invocation.completion_tokens,
        cached_tokens=invocation.cached_tokens,
        cost_basis="subscription_unallocated",
        cost_attribution_basis="codex_cli_turn",
    )


class CodexProvider(ChatProvider):
    """Text-only provider for the account default model chosen by official CLI."""

    # Official subscription turns include local CLI startup and account routing.
    # Admin connection validation must not apply the 10/15 second HTTP probe
    # budget, otherwise it cancels a still-running contained CLI turn.
    connection_probe_timeout_s = 180.0

    def __init__(
        self,
        name: str = "codex",
        *,
        timeout_s: float = 180.0,
        environment: Mapping[str, str] | None = None,
        worker: CodexInvokeWorker | None = None,
    ) -> None:
        self.name = name
        self.timeout_s = timeout_s
        source = dict(os.environ if environment is None else environment)
        descriptor = SubscriptionCliDiscovery(environment=source).list_public()[0]
        self.enabled = descriptor.get("state") == "installed_unprobed"
        self._worker: CodexInvokeWorker | None = (
            worker
            if self.enabled and worker is not None
            else CodexSubscriptionWorker(environment=source)
            if self.enabled
            else None
        )

    def expected_model_family(self, upstream_model: str) -> str | None:
        del upstream_model
        # ``codex exec --json`` does not attest the actually served GPT model.
        return None

    def verify_model_identity(
        self,
        upstream_model: str,
        observed_model: str,
    ) -> tuple[str, str] | None:
        del upstream_model, observed_model
        return None

    def actual_served_receipt(self) -> dict[str, Any]:
        """Return the honest verification-time served-identity receipt.

        ``codex exec --json`` attests no served model, so this stays
        ``unproven``; the configured alias is never reported as evidence.
        """

        return dict(_ACTUAL_SERVED_RECEIPT)

    def _prompt(self, req: ChatCompletionRequest) -> str:
        if _has_non_text_content(req):
            raise ProviderError(
                "Codex subscription connection supports text messages only",
                status_code=400,
            )
        if _has_tool_contract(req):
            raise ProviderError(
                "Codex subscription connection does not expose tool contracts",
                status_code=400,
            )
        return _TEXT_ONLY_PREFIX + req.prompt_text()

    async def _invoke(self, req: ChatCompletionRequest) -> CodexInvocation:
        if not self.enabled or self._worker is None:
            raise ProviderError(
                "Codex subscription CLI is not explicitly attested",
                status_code=503,
            )
        prompt = self._prompt(req)
        try:
            return await asyncio.to_thread(self._worker.invoke, prompt)
        except CodexSubscriptionError as exc:
            status_code = 413 if exc.code == "prompt_size_rejected" else 503
            raise ProviderError(
                "Codex subscription turn is unavailable",
                status_code=status_code,
            ) from None

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
            "Codex host agent execution is not exposed by the text-only subscription worker",
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
            model=req.model,
            text=invocation.text,
            usage=_subscription_usage(invocation),
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
            model=req.model,
            delta_text=invocation.text,
            chunk_id=chunk_id,
            role="assistant",
        )
        yield final_chunk(
            model=req.model,
            chunk_id=chunk_id,
            usage=_subscription_usage(invocation).model_dump(),
        )


__all__ = ["CodexInvokeWorker", "CodexProvider"]
