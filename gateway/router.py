"""路由层：从「连接存储」实时构建 providers，并把虚拟模型名映射到具体后端。

外部模型只来自连接中心完成 transient 验证并带匹配 receipt 的连接记录。
旧记录和环境变量配置不会被静默冒充为“已连接”，必须显式重新验证。
echo 永远可用，用于联通性测试。
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Optional
from urllib.parse import urlsplit

from gateway import local_model
from gateway.catalog import PROVIDER_PRESETS, preset_meta, preset_models
from gateway.config import load_models_config
from gateway.connections import (
    ConnectionStore,
    normalize_base_url,
)
from gateway.media_call_metering import _consume_paid_media_dispatch_permit
from gateway.model_identity import review_strength_from_identifier
from gateway.provider_plugins import (
    build_builtin_provider_kernel,
    provider_factory_service,
)
from gateway.providers.base import ChatProvider, ProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.providers.perplexity import PerplexityProvider
from gateway.providers.volcano import VolcanoProvider
from gateway.runtime_profile import current_runtime_profile
from orchestrator.plugin_kernel import PluginKernel, ServiceLease

_LOG = logging.getLogger(__name__)
_UNAVAILABLE_CONNECTION_REASONS: dict[str, str] = {}


def _connection_exec_backend(conn: dict[str, Any]) -> str:
    provider_type = str(conn.get("type") or "").strip().casefold()
    return "codex" if provider_type == "codex" else ""


class ModelRouteConflictError(ValueError):
    """A connection attempted to claim a virtual id owned by another route."""


class ProviderRetirementCapacityError(RuntimeError):
    """Too many old provider generations are still draining."""


class RouterProviderCloseError(RuntimeError):
    """Sanitized aggregate raised after every provider close was attempted."""

    def __init__(self, failed_count: int) -> None:
        self.failed_count = int(failed_count)
        super().__init__("router provider close incomplete")


class _PluginLeasedProvider(ChatProvider):
    """Keep the provider-factory plugin borrowed until its client really closes."""

    def __init__(self, provider: ChatProvider, lease: ServiceLease) -> None:
        self._provider = provider
        self._lease = lease
        self._close_lock = asyncio.Lock()
        self._closed = False
        self.name = provider.name
        self.enabled = provider.enabled
        self.paid_media_asset_protocol_versions = (
            provider.paid_media_asset_protocol_versions
        )
        self.paid_media_video_asset_protocol_versions = (
            provider.paid_media_video_asset_protocol_versions
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._provider, name)

    def expected_model_family(self, upstream_model: str) -> str | None:
        return self._provider.expected_model_family(upstream_model)

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        return self._provider.verify_model_identity(upstream_model, observed_model)

    async def chat(self, req, upstream_model: str) -> dict[str, Any]:
        return await self._provider.chat(req, upstream_model)

    async def probe_chat(self, req, upstream_model: str) -> dict[str, Any]:
        return await self._provider.probe_chat(req, upstream_model)

    async def stream(self, req, upstream_model: str) -> AsyncIterator[dict[str, Any]]:
        async for item in self._provider.stream(req, upstream_model):
            yield item

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            await self._provider.aclose()
            self._lease.release()
            self._closed = True


def _opaque_independence_domain(kind: str, value: str) -> str:
    digest = hashlib.sha256(
        b"nachuan/independence-domain/v1\0"
        + kind.encode("utf-8")
        + b"\0"
        + value.encode("utf-8")
    ).hexdigest()
    return f"sha256:{digest}"


def _provider_family(provider_type: str) -> str:
    """Return the protocol family, never a user-controlled connection alias."""

    if provider_type in {"openai_compat", "perplexity", "volcano"}:
        return "openai-compatible"
    return provider_type or "http-provider"


def _canonical_network_target(provider_type: str, base_url: str) -> str | None:
    """Fold URL spellings to provider family + canonical host.

    Paths are API routing details, not an independent trust boundary.  All
    loopback spellings identify the same machine.  Ports are deliberately
    ignored too: one operator can expose the same service on multiple ports,
    so treating ports as independent would permit vote multiplication.
    """

    try:
        parsed = urlsplit(base_url)
        host = (parsed.hostname or "").strip().casefold().rstrip(".")
        if not host:
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if host == "localhost" or bool(address and address.is_loopback):
            host = "local-machine"

        # Accessing parsed.port validates an explicit port even though it is
        # excluded from the trust identity.
        parsed.port
    except (UnicodeError, ValueError):
        return None
    return f"{_provider_family(provider_type)}\0{host}"


def connection_independence_domain(conn: dict[str, Any]) -> str | None:
    """Bind aliases to an opaque HTTP target or local CLI login domain.

    Connection names and model aliases are intentionally excluded: both are
    user-controlled and renaming them must not create a fake independent vote.
    The returned digest is safe for receipts because it contains no URL/key.
    """

    ptype = str(conn.get("type") or "").strip().casefold()
    # Local CLI providers ignore HTTP configuration entirely.  Their trust
    # identity is the local login family and must not be split by an injected
    # or stale base_url field.
    if ptype == "claude_code":
        return _opaque_independence_domain("cli-login", "claude-code:default")
    if ptype == "codex":
        return _opaque_independence_domain("cli-login", "codex:default")
    if ptype == "kimi_code":
        return _opaque_independence_domain("cli-login", "kimi-code:default")
    if ptype == "echo":
        return _opaque_independence_domain("local-provider", "echo")

    base_url = str(conn.get("base_url") or "").strip()
    if base_url:
        try:
            canonical = normalize_base_url(base_url, verify_public=False)
        except (TypeError, ValueError):
            return None
        if canonical:
            target = _canonical_network_target(ptype, canonical)
            if target:
                return _opaque_independence_domain("network-target", target)
    return None


@dataclass
class ModelRoute:
    virtual_model: str
    provider: ChatProvider
    upstream_model: str
    tier: str
    description: str = ""
    modality: str = "chat"
    rank: int = 0  # 同档位内偏好（越小越优先，0=未排）
    flagship: bool = False  # 王牌，仅「最强」显式动用，自动路由不烧
    # 原生执行后端是路由元数据，不得由前端猜模型名字。空字符串=只能走 chat/function-calling。
    exec_backend: str = ""
    # Opaque HTTP-target / CLI-login identity used by ReviewGate.  Never a URL.
    independence_domain: str | None = None
    # Closed-registry model developer family, derived from provider/upstream
    # semantics rather than the user-controlled connection name.
    model_family: str | None = None
    tool_capable: bool = True
    skills: tuple[str, ...] = ()


class _ProviderGeneration(ChatProvider):
    """Drain an old provider without interrupting calls already in flight.

    A short hand-off window covers the resolve-then-call race.  After that
    window, no new call may start on the retired generation; the underlying
    client closes as soon as its active calls reach zero.  Router shutdown is
    allowed to force closure because the process itself is terminating.
    """

    _accounted_media_dispatch_operations = frozenset(
        {"media.generate_image", "media.generate_video"}
    )

    def __init__(
        self,
        provider: ChatProvider,
        *,
        on_closed: Callable[["_ProviderGeneration"], None],
    ) -> None:
        self._provider = provider
        self._on_closed = on_closed
        self._state_lock = asyncio.Lock()
        self._zero_active = asyncio.Event()
        self._zero_active.set()
        self._active = 0
        self._retiring = False
        self._accept_until = float("inf")
        self._close_started = False
        self._close_task: asyncio.Task[None] | None = None
        self._close_done = asyncio.Event()
        self._close_notified = False
        self._retirement_task: asyncio.Task[None] | None = None
        self.name = provider.name
        self.enabled = provider.enabled
        self.independence_domain = getattr(provider, "independence_domain", None)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._provider, name)

    @property
    def paid_media_asset_protocol_versions(self) -> frozenset[str]:
        return self._provider.paid_media_asset_protocol_versions

    @property
    def paid_media_video_asset_protocol_versions(self) -> frozenset[str]:
        return self._provider.paid_media_video_asset_protocol_versions

    @property
    def closed(self) -> bool:
        return self._close_done.is_set()

    def expected_model_family(self, upstream_model: str) -> str | None:
        return self._provider.expected_model_family(upstream_model)

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        return self._provider.verify_model_identity(upstream_model, observed_model)

    async def _begin_operation(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._state_lock:
            if self._close_started or (
                self._retiring and loop.time() >= self._accept_until
            ):
                raise ProviderError(
                    "连接刚刚完成安全切换，请重试本次请求",
                    status_code=503,
                )
            self._active += 1
            self._zero_active.clear()

    async def _end_operation(self) -> None:
        async with self._state_lock:
            self._active = max(0, self._active - 1)
            if self._active == 0:
                self._zero_active.set()

    async def chat(self, req, upstream_model: str) -> dict[str, Any]:
        await self._begin_operation()
        try:
            return await self._provider.chat(req, upstream_model)
        finally:
            await self._end_operation()

    async def probe_chat(self, req, upstream_model: str) -> dict[str, Any]:
        await self._begin_operation()
        try:
            return await self._provider.probe_chat(req, upstream_model)
        finally:
            await self._end_operation()

    async def stream(self, req, upstream_model: str) -> AsyncIterator[dict[str, Any]]:
        await self._begin_operation()
        try:
            async for item in self._provider.stream(req, upstream_model):
                yield item
        finally:
            await self._end_operation()

    async def generate_image(self, req, upstream_model: str) -> dict[str, Any]:
        _consume_paid_media_dispatch_permit(self, "media.generate_image")
        await self._begin_operation()
        try:
            return await self._provider.generate_image(req, upstream_model)
        finally:
            await self._end_operation()

    async def generate_image_asset_urls(
        self, req, upstream_model: str
    ) -> dict[str, Any]:
        _consume_paid_media_dispatch_permit(self, "media.generate_image")
        await self._begin_operation()
        try:
            return await self._provider.generate_image_asset_urls(req, upstream_model)
        finally:
            await self._end_operation()

    async def generate_video(self, req, upstream_model: str) -> dict[str, Any]:
        _consume_paid_media_dispatch_permit(self, "media.generate_video")
        await self._begin_operation()
        try:
            return await self._provider.generate_video(req, upstream_model)
        finally:
            await self._end_operation()

    async def get_video(self, task_id: str) -> dict[str, Any]:
        await self._begin_operation()
        try:
            return await self._provider.get_video(task_id)
        finally:
            await self._end_operation()

    def retire(self, *, handoff_seconds: float) -> None:
        if self._retiring or self._close_started:
            return
        loop = asyncio.get_running_loop()
        self._retiring = True
        self._accept_until = loop.time() + max(0.0, float(handoff_seconds))
        self._retirement_task = loop.create_task(self._finish_retirement())

    async def _finish_retirement(self) -> None:
        delay = max(0.0, self._accept_until - asyncio.get_running_loop().time())
        if delay:
            await asyncio.sleep(delay)
        while True:
            async with self._state_lock:
                if self._close_started:
                    break
                if self._active == 0:
                    self._close_started = True
                    break
                waiter = self._zero_active
            await waiter.wait()
        try:
            await self._close_underlying_once()
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise
            _LOG.error("provider retirement close incomplete")
        except BaseException:
            # Background-task exception reporting would include the provider's
            # secret-adjacent message.  Ownership remains in the router set.
            _LOG.error("provider retirement close incomplete")

    async def _close_underlying_once(self) -> None:
        async with self._state_lock:
            self._close_started = True
            if self._close_task is None:
                self._close_task = asyncio.create_task(self._provider.aclose())
                self._close_task.add_done_callback(self._close_finished)
            close_task = self._close_task
        try:
            await asyncio.shield(close_task)
        except BaseException:
            # Do not depend on done-callback scheduling order: a caller may
            # retry immediately in the same event-loop turn.  Keep an
            # in-flight task shared, but detach a task whose close really
            # reached a failed terminal state.
            if close_task.done() and self._close_task is close_task:
                self._close_task = None
            raise
        else:
            # Finalize synchronously for callers; the registered callback is
            # still the fallback for an externally cancelled waiter.
            self._close_finished(close_task)

    def _close_finished(self, task: asyncio.Task[None]) -> None:
        if self._close_notified:
            return
        if task.cancelled() or task.exception() is not None:
            # A failed close is not a terminal state.  Keep the generation
            # owned and permit a later bounded router drain to make a fresh
            # attempt against the same underlying provider.
            if self._close_task is task:
                self._close_task = None
            return
        self._close_notified = True
        self._close_done.set()
        self._on_closed(self)

    async def aclose(self) -> None:
        task = self._retirement_task
        if (
            task is not None
            and task is not asyncio.current_task()
            and not task.done()
            and self._close_task is None
        ):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        if self._close_done.is_set():
            return
        # Forced router shutdown may close active operations because the
        # process itself is terminating.  The one-shot close task prevents a
        # concurrent retirement worker from double-closing the client.
        await self._close_underlying_once()


class Router:
    _MAX_RETIRED_GENERATIONS = 32
    _RETIREMENT_HANDOFF_SECONDS = 2.0

    def __init__(
        self,
        models_config: Optional[dict[str, Any]] = None,
        store: Optional[ConnectionStore] = None,
        codex_worker: Any | None = None,
        codex_environment: Mapping[str, str] | None = None,
        kimi_worker: Any | None = None,
        kimi_environment: Mapping[str, str] | None = None,
        plugin_kernel: PluginKernel | None = None,
        durable_event_sink: Callable[[str, object], object] | None = None,
    ):
        self._catalog = models_config if models_config is not None else load_models_config()
        self.store = store
        self._codex_worker = codex_worker
        self._codex_environment = dict(
            os.environ if codex_environment is None else codex_environment
        )
        self._kimi_worker = kimi_worker
        self._kimi_environment = dict(
            os.environ if kimi_environment is None else kimi_environment
        )
        self._plugin_kernel = (
            build_builtin_provider_kernel(durable_event_sink=durable_event_sink)
            if plugin_kernel is None
            else plugin_kernel
        )
        self._owns_plugin_kernel = plugin_kernel is None
        self._providers: dict[str, ChatProvider] = {}
        self._routes: dict[str, ModelRoute] = {}
        self._retired_generations: set[_ProviderGeneration] = set()
        self._reload_lock = asyncio.Lock()
        self._build_provider_budget: int | None = None
        self._build()

    @property
    def plugin_kernel(self) -> PluginKernel:
        kernel = getattr(self, "_plugin_kernel", None)
        if kernel is None:
            # A handful of fail-closed endpoint tests intentionally construct
            # a bare Router without __init__.  Lazily attach only the built-in,
            # no-secret kernel instead of letting diagnostics crash.
            kernel = build_builtin_provider_kernel()
            self._plugin_kernel = kernel
            self._owns_plugin_kernel = True
        return kernel

    def _generation_closed(self, generation: _ProviderGeneration) -> None:
        self._retired_generations.discard(generation)

    def _wrap_provider(self, provider: ChatProvider) -> _ProviderGeneration:
        return _ProviderGeneration(provider, on_closed=self._generation_closed)

    def _assert_retirement_capacity(self, additional: int) -> None:
        self._retired_generations = {
            generation
            for generation in self._retired_generations
            if not generation.closed
        }
        if (
            additional > 0
            and len(self._retired_generations) + additional
            > self._MAX_RETIRED_GENERATIONS
        ):
            raise ProviderRetirementCapacityError(
                "provider retirement queue is full; retry after active calls drain"
            )

    def _retire_provider(self, provider: ChatProvider) -> None:
        if isinstance(provider, _ProviderGeneration):
            provider._on_closed = self._generation_closed
            self._retired_generations.add(provider)
            provider.retire(handoff_seconds=self._RETIREMENT_HANDOFF_SECONDS)
            return
        # Every Router-created provider is wrapped.  Keep this branch closed
        # rather than silently leaking if a test/plugin installs a raw object.
        raise TypeError("router provider generation is not lifecycle-managed")

    def _adopt_provider_cleanup(
        self, providers: tuple[ChatProvider, ...]
    ) -> None:
        """Retain close candidates until their wrappers report real success."""

        for provider in providers:
            if not isinstance(provider, _ProviderGeneration):
                raise TypeError(
                    "router provider generation is not lifecycle-managed"
                )
            provider._on_closed = self._generation_closed
            self._retired_generations.add(provider)

    def _claim_build_provider_slot(self) -> None:
        """Reserve cleanup ownership before constructing a provider client."""

        budget = getattr(self, "_build_provider_budget", None)
        if budget is None:
            return
        if budget <= 0:
            raise ProviderRetirementCapacityError(
                "provider retirement queue is full; retry after active calls drain"
            )
        self._build_provider_budget = budget - 1

    # ── 构建 ──
    def _build(self) -> None:
        self._providers = {}
        self._routes = {}

        self._claim_build_provider_slot()
        raw_echo = self._make_provider_from_conn("echo", {"type": "echo"})
        if raw_echo is None:
            raise RuntimeError("builtin echo provider plugin is unavailable")
        raw_echo.independence_domain = connection_independence_domain({"type": "echo"})
        echo = self._wrap_provider(raw_echo)
        self._providers["echo"] = echo
        self._routes["echo"] = ModelRoute(
            "echo",
            echo,
            "echo",
            "free",
            "本地回显",
            independence_domain=raw_echo.independence_domain,
            model_family=echo.expected_model_family("echo"),
        )

        connections = self.store.all() if self.store else {}
        for pname, conn in connections.items():
            if self.store.is_verified(pname, conn):
                self._register_connection(pname, conn)
            else:
                _LOG.warning(
                    "provider connection %r is legacy/unverified and was not routed",
                    pname,
                )

        # 自带本地模型只有在「本次由我们启动并完成 nonce 就绪探测」后才可见。
        # available() 只证明磁盘文件受审，不能证明 8091 上的服务属于本进程；固定写死
        # upstream_model="local" 也无法绑定 llama-server 的 --alias 身份。
        local_alias = local_model.ready_model_alias()
        local_base_url = local_model.base_url() if local_alias else ""
        if "local" not in self._providers and local_alias and local_base_url:
            self._register_connection(
                "local",
                {
                    "type": "openai_compat",
                    "base_url": local_base_url,
                    "enabled_models": [
                        {
                            "id": "local",
                            "upstream_model": local_alias,
                            "tier": "free",
                            "description": "本地模型（离线·受审运行时）",
                        }
                    ],
                },
            )

    def assert_connection_model_ids_available(
        self, pname: str, conn: dict[str, Any]
    ) -> None:
        for model in conn.get("enabled_models") or []:
            model_id = str(model.get("id") or "").strip()
            if not model_id:
                continue
            existing = self._routes.get(model_id)
            if existing is not None and existing.provider.name != pname:
                raise ModelRouteConflictError(
                    f"virtual model id {model_id!r} is already owned"
                )

    @staticmethod
    def _namespaced_model_id(pname: str, requested: str) -> str:
        candidate = f"{pname}::{requested}"
        if len(candidate) <= 512:
            return candidate
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:16]
        prefix = f"{pname}::"
        budget = max(1, 512 - len(prefix) - len(digest) - 1)
        return f"{prefix}{requested[:budget]}~{digest}"

    def assign_available_model_ids(
        self, pname: str, conn: dict[str, Any]
    ) -> dict[str, Any]:
        """Keep a short id when free; namespace conflicts automatically.

        Customers should never need to understand virtual routing aliases just
        because two vendors expose the same upstream model name.  Existing
        aliases owned by this connection remain stable across reconnects.
        """

        assigned_models: list[dict[str, Any]] = []
        assigned_ids: set[str] = set()
        for original in conn.get("enabled_models") or []:
            model = dict(original)
            requested = str(model.get("id") or "").strip()
            existing = self._routes.get(requested)
            assigned = requested
            if existing is not None and existing.provider.name != pname:
                if requested.startswith(f"{pname}::"):
                    raise ModelRouteConflictError(
                        f"provider namespace {requested!r} is already owned"
                    )
                assigned = self._namespaced_model_id(pname, requested)
            owner = self._routes.get(assigned)
            if (
                owner is not None and owner.provider.name != pname
            ) or assigned in assigned_ids:
                raise ModelRouteConflictError(
                    f"virtual model id {assigned!r} is already owned"
                )
            model["id"] = assigned
            assigned_ids.add(assigned)
            assigned_models.append(model)
        return {**conn, "enabled_models": assigned_models}

    def build_transient_routes(
        self, pname: str, conn: dict[str, Any]
    ) -> list[ModelRoute]:
        """Build every chat validation route without touching the live table."""

        self.assert_connection_model_ids_available(pname, conn)
        provider = self._make_provider_from_conn(pname, conn)
        if provider is None or not provider.enabled:
            return []
        domain_source = dict(conn)
        if not str(domain_source.get("base_url") or "").strip():
            provider_target = str(getattr(provider, "base_url", "") or "").strip()
            if provider_target:
                domain_source["base_url"] = provider_target
        domain = connection_independence_domain(domain_source)
        provider.independence_domain = domain
        routes: list[ModelRoute] = []
        for model in conn.get("enabled_models") or []:
            if model.get("modality", "chat") != "chat":
                continue
            model_id = str(model.get("id") or "").strip()
            upstream = str(model.get("upstream_model") or model_id).strip()
            if not model_id or not upstream:
                continue
            meta = preset_meta(model_id)
            routes.append(ModelRoute(
                virtual_model=model_id,
                provider=provider,
                upstream_model=upstream,
                tier=str(model.get("tier") or "default"),
                description=str(model.get("description") or ""),
                modality="chat",
                rank=int(model.get("rank") or meta["rank"] or 0),
                flagship=bool(model.get("flagship") or meta["flagship"]),
                exec_backend=_connection_exec_backend(conn),
                independence_domain=domain,
                model_family=provider.expected_model_family(upstream),
                tool_capable=bool(
                    model.get("tool_capable", meta.get("tool_capable", True))
                ),
                skills=tuple(model.get("skills") or meta.get("skills") or []),
            ))
        return routes

    def _register_connection(self, pname: str, conn: dict[str, Any]) -> None:
        self.assert_connection_model_ids_available(pname, conn)
        self._claim_build_provider_slot()
        raw_provider = self._make_provider_from_conn(pname, conn)
        if raw_provider is None or not raw_provider.enabled:
            return
        domain_source = dict(conn)
        if not str(domain_source.get("base_url") or "").strip():
            provider_target = str(
                getattr(raw_provider, "base_url", "") or ""
            ).strip()
            if provider_target:
                domain_source["base_url"] = provider_target
        domain = connection_independence_domain(domain_source)
        raw_provider.independence_domain = domain
        provider = self._wrap_provider(raw_provider)
        self._providers[pname] = provider
        for m in conn.get("enabled_models") or []:
            mid = m.get("id")
            if not mid:
                continue
            _meta = preset_meta(mid)  # 老连接(连接中心存的)没带 rank/flagship → 回退用预设的偏好
            upstream_model = str(m.get("upstream_model", mid) or "").strip()
            model_family = raw_provider.expected_model_family(upstream_model)
            self._routes[mid] = ModelRoute(
                virtual_model=mid,
                provider=provider,
                upstream_model=upstream_model,
                tier=m.get("tier", "default"),
                description=m.get("description", ""),
                modality=m.get("modality", "chat"),
                rank=int(m.get("rank") or _meta["rank"] or 0),
                flagship=bool(m.get("flagship") or _meta["flagship"]),
                exec_backend=_connection_exec_backend(conn),
                independence_domain=domain,
                model_family=model_family,
                tool_capable=bool(
                    m.get("tool_capable", _meta.get("tool_capable", True))
                ),
                skills=tuple(m.get("skills") or _meta.get("skills") or []),
            )

    def _make_provider_from_conn(
        self, pname: str, conn: dict[str, Any]
    ) -> Optional[ChatProvider]:
        ptype = str(conn.get("type", pname) or "").strip().casefold()
        if not current_runtime_profile().allows_provider_type(ptype):
            return None
        factory_service = provider_factory_service(ptype)
        if self.plugin_kernel.services.has_provider(factory_service):
            lease = self.plugin_kernel.borrow_service(factory_service)
            try:
                factory = lease.value
                if not callable(factory):
                    raise TypeError("provider factory service is not callable")
                provider = factory(pname, dict(conn))
                if provider is None:
                    lease.release()
                    return None
                if not isinstance(provider, ChatProvider):
                    raise TypeError("provider factory returned an invalid provider")
                if not provider.enabled:
                    lease.release()
                    return None
                return _PluginLeasedProvider(provider, lease)
            except BaseException:
                lease.release()
                raise
        api_key = (conn.get("api_key") or "").strip()
        base_url = (conn.get("base_url") or "").strip()
        if ptype == "volcano":
            return (
                VolcanoProvider(name=pname, api_key=api_key, base_url=base_url or None)
                if api_key
                else None
            )
        if ptype == "openai_compat":
            # 有 base_url 即可（本地模型无 key）
            return (
                OpenAICompatProvider(name=pname, base_url=base_url, api_key=api_key)
                if base_url
                else None
            )
        if ptype == "perplexity":
            return (
                PerplexityProvider(name=pname, base_url=base_url, api_key=api_key)
                if base_url and api_key
                else None
            )
        if ptype == "codex":
            from gateway.providers.codex import CodexProvider

            p = CodexProvider(
                name=pname,
                environment=self._codex_environment,
                worker=self._codex_worker,
            )
            return p if p.enabled else None
        if ptype == "kimi_code":
            from gateway.providers.kimi_subscription import (
                KimiSubscriptionProvider,
            )

            p = KimiSubscriptionProvider(
                name=pname,
                environment=self._kimi_environment,
                worker=self._kimi_worker,
            )
            return p if p.enabled else None
        return None

    def _catalog_models_for(self, provider_name: str) -> list[dict[str, Any]]:
        return preset_models(provider_name)

    # ── 查询 ──
    def resolve(self, virtual_model: str) -> Optional[ModelRoute]:
        return self._routes.get(virtual_model)

    def first_route_for(self, provider: str) -> Optional[ModelRoute]:
        for route in self._routes.values():
            if route.provider.name == provider:
                return route
        return None

    def routes_for_provider(self, provider: str) -> list[ModelRoute]:
        return [
            route
            for route in self._routes.values()
            if route.provider.name == provider and route.modality == "chat"
        ]

    def list_models(self) -> list[dict[str, Any]]:
        models: list[dict[str, Any]] = []
        for r in self._routes.values():
            if r.virtual_model == "echo":
                continue
            review_strength = review_strength_from_identifier(r.upstream_model)
            review_vote_candidate = bool(
                r.modality == "chat"
                and r.model_family
                and r.independence_domain
                and review_strength == "strong"
            )
            models.append({
                "id": r.virtual_model,
                "object": "model",
                "owned_by": r.provider.name,
                "tier": r.tier,
                "modality": r.modality,
                "description": r.description,
                "chat_usable": r.modality == "chat",
                "tool_capable": r.tool_capable,
                "skills": list(r.skills),
                # Candidate means route metadata can attempt an independent
                # vote.  The actual response still needs exact served-model
                # attestation at ReviewGate before vote_weight becomes 1.
                "review_vote_candidate": review_vote_candidate,
                "review_strength": review_strength,
            })
        return models

    def catalog_view(self) -> list[dict[str, Any]]:
        """供「连接中心」展示：内置厂商预设目录（含区域/鉴权/base_url/候选模型）。"""
        view: list[dict[str, Any]] = []
        profile = current_runtime_profile()
        for provider in PROVIDER_PRESETS:
            provider_type = provider.get("type", "openai_compat")
            unavailable_reason = (
                "当前运行配置不允许该连接协议"
                if not profile.allows_connection_type(provider_type)
                else _UNAVAILABLE_CONNECTION_REASONS.get(provider["name"])
            )
            view.append({
                "name": provider["name"],
                "label": provider["label"],
                "region": provider.get("region", "intl"),
                "auth": provider.get("auth", "api_key"),
                "type": provider_type,
                "default_base_url": provider.get("base_url", ""),
                "auto_discover_models": provider.get("auto_discover_models", False) is True,
                "note": provider.get("note", ""),
                "models": [dict(m) for m in provider.get("models", [])],
                "connectable": unavailable_reason is None,
                "unavailable_reason": unavailable_reason,
            })
        return view

    # ── 生命周期 ──
    async def reload_connection(self, pname: str) -> None:
        """Atomically replace only one connection and drain its old client.

        Unrelated provider objects are reused byte-for-byte.  Candidate
        construction and conflict validation happen before the live dict
        references change, so failures leave the old route table untouched.
        """

        async with self._reload_lock:
            conn = self.store.get(pname) if self.store is not None else None
            should_route = bool(
                self.store is not None
                and isinstance(conn, dict)
                and self.store.is_verified(pname, conn)
            )
            old_provider = self._providers.get(pname)
            if old_provider is not None or should_route:
                self._assert_retirement_capacity(1)

            candidate_provider: ChatProvider | None = None
            candidate_routes: dict[str, ModelRoute] = {}
            try:
                if should_route and conn is not None:
                    # Build in isolated dictionaries by temporarily collecting
                    # the same materialization used at startup.
                    self.assert_connection_model_ids_available(pname, conn)
                    raw_provider = self._make_provider_from_conn(pname, conn)
                    if raw_provider is not None and raw_provider.enabled:
                        domain_source = dict(conn)
                        if not str(domain_source.get("base_url") or "").strip():
                            provider_target = str(
                                getattr(raw_provider, "base_url", "") or ""
                            ).strip()
                            if provider_target:
                                domain_source["base_url"] = provider_target
                        domain = connection_independence_domain(domain_source)
                        raw_provider.independence_domain = domain
                        candidate_provider = self._wrap_provider(raw_provider)
                        for model in conn.get("enabled_models") or []:
                            model_id = str(model.get("id") or "").strip()
                            upstream = str(
                                model.get("upstream_model") or model_id
                            ).strip()
                            if not model_id or not upstream:
                                continue
                            meta = preset_meta(model_id)
                            candidate_routes[model_id] = ModelRoute(
                                virtual_model=model_id,
                                provider=candidate_provider,
                                upstream_model=upstream,
                                tier=str(model.get("tier") or "default"),
                                description=str(model.get("description") or ""),
                                modality=str(model.get("modality") or "chat"),
                                rank=int(model.get("rank") or meta["rank"] or 0),
                                flagship=bool(
                                    model.get("flagship") or meta["flagship"]
                                ),
                                exec_backend=_connection_exec_backend(conn),
                                independence_domain=domain,
                                model_family=raw_provider.expected_model_family(
                                    upstream
                                ),
                                tool_capable=bool(
                                    model.get(
                                        "tool_capable",
                                        meta.get("tool_capable", True),
                                    )
                                ),
                                skills=tuple(
                                    model.get("skills") or meta.get("skills") or []
                                ),
                            )
            except BaseException:
                if candidate_provider is not None:
                    self._adopt_provider_cleanup((candidate_provider,))
                    try:
                        await self._close_provider_snapshot(
                            {"partial-candidate": candidate_provider}
                        )
                    except BaseException:
                        # Preserve the connection-build root cause.  A failed
                        # cleanup remains in the live router's retry set.
                        pass
                raise

            providers = dict(self._providers)
            routes = {
                model_id: route
                for model_id, route in self._routes.items()
                if route.provider.name != pname
            }
            if candidate_provider is None:
                providers.pop(pname, None)
            else:
                providers[pname] = candidate_provider
                routes.update(candidate_routes)

            # Dict-reference replacement is the only live mutation.  Retirement
            # scheduling below is synchronous and capacity was preflighted.
            self._providers = providers
            self._routes = routes
            if old_provider is not None and old_provider is not candidate_provider:
                self._retire_provider(old_provider)

    async def reload(self) -> None:
        # Build a complete replacement first.  A malformed store snapshot or a
        # provider constructor failure must not tear down the last-known-good
        # routing table before a replacement exists.
        async with self._reload_lock:
            # Reserve enough ownership before _build constructs even the echo
            # client.  A failed partial build can then retain every candidate
            # without growing the retry set past its hard bound.
            self._assert_retirement_capacity(max(1, len(self._providers)))
            build_budget = (
                self._MAX_RETIRED_GENERATIONS - len(self._retired_generations)
            )
            replacement = object.__new__(Router)
            replacement._catalog = self._catalog
            replacement.store = self.store
            # Some fail-closed lifecycle tests deliberately construct a bare
            # Router to exercise partial-build cleanup.  Keep that path free of
            # ambient credentials while preserving injected workers on normal
            # Router instances.
            replacement._codex_worker = getattr(self, "_codex_worker", None)
            replacement._codex_environment = dict(
                getattr(self, "_codex_environment", {})
            )
            replacement._kimi_worker = getattr(self, "_kimi_worker", None)
            replacement._kimi_environment = dict(
                getattr(self, "_kimi_environment", {})
            )
            current_plugin_kernel = getattr(self, "_plugin_kernel", None)
            replacement._plugin_kernel = (
                build_builtin_provider_kernel()
                if current_plugin_kernel is None
                else current_plugin_kernel
            )
            replacement._owns_plugin_kernel = current_plugin_kernel is None
            replacement._providers = {}
            replacement._routes = {}
            replacement._retired_generations = set()
            replacement._reload_lock = asyncio.Lock()
            replacement._build_provider_budget = build_budget
            try:
                replacement._build()
                self._assert_retirement_capacity(len(self._providers))
            except BaseException:
                cleanup_candidates = tuple(replacement._providers.values())
                self._adopt_provider_cleanup(cleanup_candidates)
                try:
                    await self._close_provider_snapshot(replacement._providers)
                except BaseException:
                    # Preserve the build/reload root cause. Provider cleanup
                    # already attempted every peer and logged only a fixed label.
                    pass
                if replacement._owns_plugin_kernel:
                    try:
                        await replacement._plugin_kernel.aclose()
                    except BaseException:
                        pass
                raise

            old_providers = self._providers
            for provider in replacement._providers.values():
                if isinstance(provider, _ProviderGeneration):
                    provider._on_closed = self._generation_closed
            self._providers = replacement._providers
            self._routes = replacement._routes
            if current_plugin_kernel is None:
                self._plugin_kernel = replacement._plugin_kernel
                self._owns_plugin_kernel = True
                replacement._owns_plugin_kernel = False
            replacement._providers = {}
            replacement._routes = {}
            for provider in old_providers.values():
                self._retire_provider(provider)

    def routes_info(self) -> list[dict[str, Any]]:
        """已注册模型的 (model, tier, provider, rank, flagship)，供模式调度按档位+偏好选模型。"""
        return [
            {"model": r.virtual_model, "tier": r.tier, "provider": r.provider.name,
             "upstream_model": r.upstream_model, "model_family": r.model_family,
             "rank": r.rank, "flagship": r.flagship,
             "independence_domain": r.independence_domain,
             "modality": r.modality, "tool_capable": r.tool_capable,
             "skills": list(r.skills),
             "review_strength": review_strength_from_identifier(r.upstream_model),
             "review_vote_candidate": bool(
                 r.modality == "chat"
                 and r.model_family
                 and r.independence_domain
                 and review_strength_from_identifier(r.upstream_model) == "strong"
             )}
            for r in self._routes.values()
        ]

    async def aclose(self) -> None:
        async with self._reload_lock:
            self._adopt_provider_cleanup(tuple(self._providers.values()))
            self._providers = {}
            self._routes = {}
            pending = tuple(self._retired_generations)
        await self._close_provider_snapshot(
            {f"pending-{index}": provider for index, provider in enumerate(pending)}
        )
        if getattr(self, "_owns_plugin_kernel", False):
            await self._plugin_kernel.aclose()
            self._owns_plugin_kernel = False

    @staticmethod
    async def _close_provider_snapshot(providers: dict[str, ChatProvider]) -> None:
        failed_count = 0
        cancellation: asyncio.CancelledError | None = None
        for provider in providers.values():
            try:
                await provider.aclose()
            except asyncio.CancelledError as exc:
                failed_count += 1
                if cancellation is None:
                    cancellation = exc
                _LOG.error("provider close failed during router cleanup")
            except BaseException:
                failed_count += 1
                _LOG.error("provider close failed during router cleanup")
        if cancellation is not None:
            raise cancellation
        if failed_count:
            raise RouterProviderCloseError(failed_count) from None
