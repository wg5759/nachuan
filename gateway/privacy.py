"""隐私与同源隔离策略（P0-1 / P0-2 / P0-3 统一门禁）。

核心原则：
1. 本地离线模型（ollama / local / llama / lmstudio / llamacpp / jan / vllm / echo / loopback）
   绝不静默外联 Bing 搜索、绝不把对话外发给云端模型做记忆抽取或滚动摘要、绝不上传外网图床。
2. 无痕 / 隐私模式（incognito=True 或 privacy_mode=True）彻底零联网搜索、零长期记忆注入、
   零后台记忆抽取、零服务端滚动摘要落库与外发。
3. 后台辅助任务（记忆抽取 / 滚动摘要）默认严格同源（仅使用当前对话所属同一模型/供应商），
   绝不静默跨供应商发给 agnes-flash 或其他第三方便宜模型。
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from gateway.config import get_settings

_LOCAL_PROVIDER_NAMES = frozenset(
    {"local", "ollama", "lmstudio", "llamacpp", "llama.cpp", "llama", "jan", "vllm", "echo"}
)
_LOCAL_MODEL_PREFIXES = (
    "local:",
    "local/",
    "local::",
    "local-",
    "ollama:",
    "ollama/",
    "ollama::",
    "ollama-",
    "llama:",
    "llama/",
    "llama::",
    "llama-",
    "llama2",
    "llama3",
    "llama4",
    "llamacpp:",
    "llamacpp/",
    "llamacpp::",
    "lmstudio:",
    "lmstudio/",
    "lmstudio::",
    "jan:",
    "jan/",
    "jan::",
    "vllm:",
    "vllm/",
    "vllm::",
)


def _read_attr_or_key(source: Any, name: str, default: Any = None) -> Any:
    if source is None:
        return default
    if isinstance(source, Mapping):
        return source.get(name, default)
    value = getattr(source, name, default)
    if value is not default:
        return value
    extra = getattr(source, "model_extra", None)
    if isinstance(extra, Mapping):
        return extra.get(name, default)
    return default


def _as_strict_bool(value: Any) -> bool:
    return value is True


def is_incognito_request(source: Any) -> bool:
    """请求是否开启了无痕 / 隐私模式（兼容 dict 与 Pydantic 模型）。"""
    return _as_strict_bool(_read_attr_or_key(source, "incognito", False)) or _as_strict_bool(
        _read_attr_or_key(source, "privacy_mode", False)
    )


def should_inject_memory(source: Any) -> bool:
    """是否允许向本轮对话注入长期记忆：无痕模式或显式 inject_memory=False 一律禁用。"""
    if is_incognito_request(source):
        return False
    explicit = _read_attr_or_key(source, "inject_memory", None)
    if explicit is False:
        return False
    return True


def is_loopback_base_url(base_url: Any) -> bool:
    """判断给定 base_url 是否指向本机回环或局域网 .local 服务。"""
    raw = str(base_url or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").strip().casefold().rstrip(".")
    except (UnicodeError, ValueError):
        return False
    if not host:
        return False
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _identifier_looks_local(identifier: str) -> bool:
    low = (identifier or "").strip().casefold()
    if not low:
        return False
    if low in _LOCAL_PROVIDER_NAMES:
        return True
    return any(low.startswith(prefix) for prefix in _LOCAL_MODEL_PREFIXES)


def _route_is_local(route: Any) -> bool:
    if route is None:
        return False
    provider = getattr(route, "provider", None)
    provider_name = str(getattr(provider, "name", "") or "").strip().casefold()
    if provider_name in _LOCAL_PROVIDER_NAMES:
        return True
    if is_loopback_base_url(getattr(provider, "base_url", "")):
        return True
    upstream = str(getattr(route, "upstream_model", "") or "")
    if _identifier_looks_local(upstream):
        return True
    virtual = str(getattr(route, "virtual_model", "") or "")
    if _identifier_looks_local(virtual):
        return True
    return False


def is_local_model(router: Any, model_id: str | None) -> bool:
    """判断模型是否属于本地离线推理后端（路由元数据优先 + 名称兜底）。"""
    candidate = str(model_id or "").strip()
    if candidate and _identifier_looks_local(candidate):
        return True
    if router is not None and candidate and hasattr(router, "resolve"):
        try:
            route = router.resolve(candidate)
        except Exception:  # noqa: BLE001
            route = None
        if route is not None:
            if _route_is_local(route):
                return True
            return False
    if router is not None and candidate and hasattr(router, "routes_info"):
        try:
            for info in router.routes_info() or []:
                if info.get("model") == candidate:
                    pname = str(info.get("provider") or "").strip().casefold()
                    upstream = str(info.get("upstream_model") or "")
                    if pname in _LOCAL_PROVIDER_NAMES or _identifier_looks_local(upstream):
                        return True
                    break
        except Exception:  # noqa: BLE001
            pass
    return False


def is_offline_only_router(router: Any) -> bool:
    """当前环境是否处于纯离线状态（显式环境变量或仅配置了本地模型）。"""
    if os.getenv("NACHUAN_OFFLINE_MODE", "").strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if router is None or not hasattr(router, "routes_info"):
        return False
    try:
        infos = [
            info
            for info in (router.routes_info() or [])
            if info.get("model") != "echo" and info.get("modality", "chat") == "chat"
        ]
    except Exception:  # noqa: BLE001
        return False
    if not infos:
        return False
    return all(is_local_model(router, str(info.get("model") or "")) for info in infos)


def _provider_identity_for_route(route: Any) -> str:
    if route is None:
        return ""
    domain = str(getattr(route, "independence_domain", "") or "").strip()
    if domain:
        return domain
    provider = getattr(route, "provider", None)
    return str(getattr(provider, "name", "") or "").strip().casefold()


def is_same_origin_model(router: Any, source_model: str, candidate_model: str) -> bool:
    """校验 candidate_model 与 source_model 是否同源（且本地模型绝不跨去云端）。"""
    src = str(source_model or "").strip()
    cand = str(candidate_model or "").strip()
    if not src or not cand:
        return False
    if src == cand:
        return True
    src_local = is_local_model(router, src)
    cand_local = is_local_model(router, cand)
    if src_local != cand_local:
        return False
    if router is None or not hasattr(router, "resolve"):
        return False
    src_route = router.resolve(src)
    cand_route = router.resolve(cand)
    if src_route is None or cand_route is None:
        return False
    src_id = _provider_identity_for_route(src_route)
    cand_id = _provider_identity_for_route(cand_route)
    if src_id and cand_id:
        return src_id == cand_id
    src_p = getattr(getattr(src_route, "provider", None), "name", None)
    cand_p = getattr(getattr(cand_route, "provider", None), "name", None)
    return bool(src_p and cand_p and src_p == cand_p)


def select_same_origin_helper_model(
    router: Any,
    source_model: str | None = None,
    *,
    incognito: bool = False,
    allow_cross_vendor: bool | None = None,
) -> str | None:
    """为后台记忆抽取 / 滚动摘要选择严格同源的辅助模型。

    规则：
    - 无痕模式 → 永远返回 None（完全跳过）。
    - 指定了 source_model：
      * 本地离线模型：只允许返回自身（绝不外发云端）；不可解析则返回 None。
      * 云端模型：只允许返回同一模型（确保同一供应商、不跨商偷传给第三方便宜模型）；
        不可解析时（例如虚拟舰队名）若未显式放开跨商配置，返回 None。
    - 未指定 source_model：
      * 若路由表内所有非 echo 聊天模型都归属唯一同一供应商（含单测单供应商场景），
        返回该唯一供应商的可用模型（无跨商风险）；
      * 若存在多个不同供应商且未显式允许跨商（allow_cross_vendor=False），返回 None，
        绝不静默发给 agnes-flash 或其他第三方模型。
    """
    if incognito or router is None:
        return None
    if allow_cross_vendor is None:
        try:
            allow_cross_vendor = bool(get_settings().allow_cross_vendor_background_model)
        except Exception:  # noqa: BLE001
            allow_cross_vendor = False

    src = str(source_model or "").strip()
    if src:
        src_local = is_local_model(router, src)
        resolved = router.resolve(src) if hasattr(router, "resolve") else None
        if resolved is not None:
            return src
        if src_local:
            # 本地模型哪怕没在 resolve 命中别名，也绝不允许落到云端模型
            return None
        if not allow_cross_vendor:
            return None

    infos: list[dict[str, Any]] = []
    if hasattr(router, "routes_info"):
        try:
            infos = [
                info
                for info in (router.routes_info() or [])
                if info.get("model") != "echo" and info.get("modality", "chat") == "chat"
            ]
        except Exception:  # noqa: BLE001
            infos = []

    if not infos:
        return None

    # 统计当前已路由聊天模型的供应商集合；如果全部来自同一个供应商，不存在跨商泄露风险。
    provider_keys: set[str] = set()
    for info in infos:
        key = str(info.get("independence_domain") or info.get("provider") or "").strip().casefold()
        if key:
            provider_keys.add(key)

    if len(provider_keys) == 1:
        cheap_tiers = ("cheap", "free")
        same_cheap = [r for r in infos if r.get("tier") in cheap_tiers]
        chosen = str((same_cheap or infos)[0].get("model") or "")
        if chosen and (not hasattr(router, "resolve") or router.resolve(chosen) is not None):
            return chosen
        return None

    if not allow_cross_vendor:
        # 多供应商环境且未指明来源模型：拒绝静默跨商偷传给第三方便宜模型。
        return None

    # 仅在用户显式启用 allow_cross_vendor_background_model 时，才允许按正常档位选择（依然过滤本地/外发冲突）
    from orchestrator.modes import pick_model

    picked = pick_model(router, "cheap")
    if picked and (not hasattr(router, "resolve") or router.resolve(picked) is not None):
        return picked
    return None
