"""网关鉴权：校验请求头里的虚拟 Bearer Key。"""

from __future__ import annotations

import hmac
import os
import re
import sys
from typing import Optional

from fastapi import Header, HTTPException, Request, status

from gateway.config import desktop_engine_keys, get_settings
from gateway.desktop_engine_session_gateway import (
    SESSION_STATE_KEY as DESKTOP_SESSION_STATE_KEY,
    DesktopEngineSessionGatewayApp,
)
from gateway.durable_media_requests import hash_media_principal
from gateway.local_web_session import (
    LocalWebSessionRejected,
    local_web_approval_cookie,
    local_web_runtime_cookie,
)
from gateway.paid_media_engine_session_gateway import (
    SESSION_STATE_KEY as PAID_MEDIA_SESSION_STATE_KEY,
    PaidMediaEngineSessionGatewayApp,
)


APPROVAL_ADMIN_HEADER = "X-Nachuan-Approval-Key"
PAID_MEDIA_HEADER = "X-Nachuan-Paid-Media-Key"
_PAID_MEDIA_KEY_RE = re.compile(r"^sk-paid-media-[0-9a-f]{64}$")
_DESKTOP_APPROVAL_RESOLVE_RE = re.compile(
    rb"^/v1/approvals/[1-9][0-9]*/resolve$"
)
_DESKTOP_CONNECTION_RE = re.compile(
    rb"^/admin/connections/[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
)
_DESKTOP_CHANNEL_RECOVERY_RE = re.compile(
    rb"^/admin/channel-recovery/(?:weixin|feishu)/(inspect|close-without-replay)$"
)
_DESKTOP_SYNC_CAPABILITIES = {
    b"/v1/sync/config": "sync.config",
    b"/v1/sync/login": "sync.auth",
    b"/v1/sync/signup": "sync.auth",
    b"/v1/sync/toggle": "sync.toggle",
    b"/v1/sync/run": "sync.run",
}
_DESKTOP_PLUGIN_UI_SNAPSHOT = b"/internal/v1/desktop/session/plugin-ui-snapshot"


def _desktop_session_failure() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Desktop engine-session capability is unavailable.",
        headers={"Cache-Control": "no-store"},
    )


def _expected_desktop_session_capability(request: Request) -> str | None:
    """Bind the inner dependency to the same exact route/capability manifest."""

    method = request.scope.get("method")
    raw_path = request.scope.get("raw_path")
    query = request.scope.get("query_string", b"")
    if not isinstance(method, str) or type(raw_path) is not bytes or type(query) is not bytes:
        return None
    if method == "GET" and raw_path == b"/v1/approvals" and query:
        return "approval.list"
    if (
        method == "GET"
        and raw_path == _DESKTOP_PLUGIN_UI_SNAPSHOT
        and not query
    ):
        return "plugin.ui.snapshot"
    if (
        method == "POST"
        and not query
        and _DESKTOP_APPROVAL_RESOLVE_RE.fullmatch(raw_path) is not None
    ):
        return "approval.resolve"
    if not query and _DESKTOP_CONNECTION_RE.fullmatch(raw_path) is not None:
        if method == "POST":
            return "connection.save"
        if method == "DELETE":
            return "connection.delete"
    if method == "POST" and not query:
        recovery = _DESKTOP_CHANNEL_RECOVERY_RE.fullmatch(raw_path)
        if recovery is not None:
            return (
                "channel-recovery.inspect"
                if recovery.group(1) == b"inspect"
                else "channel-recovery.close"
            )
    if method == "POST" and not query:
        return _DESKTOP_SYNC_CAPABILITIES.get(raw_path)
    return None


def _desktop_session_credential(request: Request | None) -> str | None:
    """Return the ephemeral Desktop principal or fail closed on stale state."""

    if request is None:
        return None
    scope_state = request.scope.get("state")
    if not isinstance(scope_state, dict) or DESKTOP_SESSION_STATE_KEY not in scope_state:
        return None
    expected_capability = _expected_desktop_session_capability(request)
    verifier = getattr(
        request.app.state, "desktop_engine_session_verifier", None
    )
    if (
        expected_capability is None
        or not isinstance(verifier, DesktopEngineSessionGatewayApp)
        or not verifier.accepts_authenticated_state(
            scope_state[DESKTOP_SESSION_STATE_KEY],
            expected_capability=expected_capability,
        )
    ):
        raise _desktop_session_failure()
    return "desktop-engine-session"


async def require_api_key(
    authorization: Optional[str] = Header(default=None),
    request: Request = None,  # type: ignore[assignment]
) -> str:
    """FastAPI 依赖：校验 Authorization: Bearer <key>，返回该 key。

    接受的 key = 配置的网关 key + 桌面端自动发现的 key（userData/config.json）。
    若一个都没有，默认拒绝启动受保护能力；仅显式设置
    NACHUAN_ALLOW_ANONYMOUS_LOCAL=1 才允许临时本地开发。
    """
    desktop_credential = _desktop_session_credential(request)
    if desktop_credential is not None:
        if authorization is not None or request.headers.getlist("authorization"):
            raise _desktop_session_failure()
        return desktop_credential

    settings = get_settings()
    keys = settings.api_keys | desktop_engine_keys()
    try:
        web_cookie = local_web_runtime_cookie(
            request,
            set(keys),
            port=int(getattr(settings, "gateway_port", 8080) or 8080),
        )
    except LocalWebSessionRejected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="本机 Web 会话无效；请从纳川启动入口重新打开",
            headers={"Cache-Control": "no-store"},
        ) from None
    if web_cookie is not None:
        if authorization is not None:
            if not authorization.lower().startswith("bearer ") or not hmac.compare_digest(
                authorization.split(" ", 1)[1].strip(), web_cookie
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="本机 Web 会话与 Bearer Token 冲突",
                    headers={"Cache-Control": "no-store"},
                )
        return web_cookie
    if not keys:
        if os.getenv("NACHUAN_ALLOW_ANONYMOUS_LOCAL") == "1":
            return "anonymous"
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="网关尚未配置访问 Key；请由桌面端或 supervisor 安全启动",
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少 Bearer Token",
        )
    token = authorization.split(" ", 1)[1].strip()
    if not any(hmac.compare_digest(token, key) for key in keys):
        # 自愈：桌面 config.json 的 key 可能在引擎启动后才生成/更换（lru_cache 里是旧集合）——
        # 拒绝前清缓存重扫一次。机主实测：key 漂移后 app「无可用模型」、两把 key 全 401 的根因之一。
        desktop_engine_keys.cache_clear()
        keys = get_settings().api_keys | desktop_engine_keys()
    if not any(hmac.compare_digest(token, key) for key in keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的 API Key",
        )
    return token


async def require_bridge_or_api_key(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> str:
    """Accept a sealed endpoint-scoped bridge request or normal runtime Bearer.

    The bridge key is deliberately *not* added to ``Settings.api_keys``.  As a
    result it is usable only on endpoints that explicitly opt in to this
    dependency; every administration, execution and approval endpoint keeps
    rejecting it through ``require_api_key``.  The scoped key itself is never an
    HTTP Bearer credential: the bridge protocol middleware authenticates and
    decrypts it before this dependency runs.
    """

    credential = str(
        getattr(request.state, "nachuan_bridge_credential", "") or ""
    )
    if credential in {"bridge:weixin", "bridge:feishu"}:
        return credential
    return await require_api_key(authorization, request=request)


async def require_paid_media_api_key(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_nachuan_paid_media_key: Optional[str] = Header(
        default=None,
        alias=PAID_MEDIA_HEADER,
        description=(
            "Required independent capability for paid image/video creation; "
            "kept optional in schema so missing credentials return a no-store 401."
        ),
    ),
) -> str:
    """Require both the ordinary runtime identity and a paid-media capability.

    The returned value remains the runtime Bearer for ordinary usage accounting.
    The paid key authenticates capability only.  In production, recovery
    identity is the stable Installation Epoch Root principal published by the
    verified controller; the raw paid secret never enters endpoint code or
    durable storage.  Source development retains a compatibility digest.
    """

    # The packaged trust path is the outer raw-ASGI engine-session verifier.
    # Long-lived runtime/paid headers are neither compared nor accepted here.
    # Source runs retain the old two-key dependency strictly for compatibility
    # tests and local migration work; the production outer wrapper never uses it.
    packaged = bool(getattr(sys, "frozen", False))
    if packaged:
        scope_state = request.scope.get("state")
        session = (
            scope_state.get(PAID_MEDIA_SESSION_STATE_KEY)
            if isinstance(scope_state, dict)
            else None
        )
        verifier = getattr(
            request.app.state, "paid_media_engine_session_verifier", None
        )
        valid_session = (
            isinstance(verifier, PaidMediaEngineSessionGatewayApp)
            and verifier.accepts_authenticated_state(session)
        )
        if (
            not valid_session
            or authorization is not None
            or bool(request.headers.getlist(PAID_MEDIA_HEADER))
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Paid-media engine-session capability is unavailable.",
                headers={"Cache-Control": "no-store"},
            )
        authority_mode = str(
            getattr(request.app.state, "paid_media_authority_mode", "") or ""
        )
        principal = str(
            getattr(request.app.state, "paid_media_principal", "") or ""
        )
        if (
            authority_mode != "installation-root"
            or re.fullmatch(r"[0-9a-f]{64}", principal) is None
            or principal == "0" * 64
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Paid-media installation authority is unavailable.",
                headers={"Cache-Control": "no-store"},
            )
        request.state.nachuan_paid_media_principal_hash = principal
        return "paid-engine-session"

    runtime_token = await require_api_key(authorization, request=request)
    settings = get_settings()
    configured = str(
        getattr(settings, "nachuan_paid_media_api_key", "") or ""
    ).strip()
    if not _PAID_MEDIA_KEY_RE.fullmatch(configured):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="付费媒体 Key 未配置或格式无效；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    runtime_keys = set(getattr(settings, "api_keys", set()) or set()) | set(
        desktop_engine_keys()
    )
    if any(hmac.compare_digest(configured, str(key)) for key in runtime_keys):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="付费媒体 Key 与运行时 API Key 重叠；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    approval_key = str(getattr(settings, "approval_admin_key", "") or "").strip()
    if approval_key and hmac.compare_digest(configured, approval_key):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="付费媒体 Key 与审批管理员 Key 重叠；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    channel_keys = {
        str(getattr(settings, name, "") or "").strip()
        for name in (
            "bridge_api_key",
            "nachuan_weixin_bridge_api_key",
            "nachuan_feishu_bridge_api_key",
        )
    }
    channel_keys.discard("")
    if any(hmac.compare_digest(configured, key) for key in channel_keys):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="付费媒体 Key 与渠道 Key 重叠；拒绝创建操作",
            headers={"Cache-Control": "no-store"},
        )
    header_values = request.headers.getlist(PAID_MEDIA_HEADER)
    if len(header_values) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"重复的 {PAID_MEDIA_HEADER}",
            headers={"Cache-Control": "no-store"},
        )
    candidate = (
        header_values[0] if header_values else x_nachuan_paid_media_key or ""
    ).strip()
    if not candidate or not hmac.compare_digest(candidate, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"缺少或无效的 {PAID_MEDIA_HEADER}",
            headers={"Cache-Control": "no-store"},
        )
    authority_mode = str(
        getattr(request.app.state, "paid_media_authority_mode", "") or ""
    )
    if authority_mode == "installation-root" or packaged:
        principal = str(
            getattr(request.app.state, "paid_media_principal", "") or ""
        )
        if (
            authority_mode != "installation-root"
            or re.fullmatch(r"[0-9a-f]{64}", principal) is None
            or principal == "0" * 64
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="付费媒体安装授权不可用；仅允许读取已确认的本地结果",
                headers={"Cache-Control": "no-store"},
            )
        request.state.nachuan_paid_media_principal_hash = principal
    else:
        # Source development intentionally keeps the pre-installation behavior;
        # production never derives a financial recovery domain from this key.
        request.state.nachuan_paid_media_principal_hash = hash_media_principal(
            configured
        )
    return runtime_token


async def require_approval_admin_key(
    x_nachuan_approval_key: Optional[str] = Header(
        default=None,
        alias=APPROVAL_ADMIN_HEADER,
    ),
    request: Request = None,  # type: ignore[assignment]
) -> str:
    """Authenticate the human approval surface with its own secret.

    The ordinary runtime Bearer key deliberately is not accepted here.  Approval
    authority is a separate trust domain: if the secret is missing or overlaps a
    runtime/desktop key, the dependency fails closed instead of silently falling
    back to normal gateway authentication.
    """
    desktop_credential = _desktop_session_credential(request)
    if desktop_credential is not None:
        if x_nachuan_approval_key is not None or request.headers.getlist(
            APPROVAL_ADMIN_HEADER
        ):
            raise _desktop_session_failure()
        return desktop_credential

    settings = get_settings()
    configured = str(getattr(settings, "approval_admin_key", "") or "").strip()
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="审批管理员 Key 尚未配置；拒绝审批操作",
        )

    runtime_keys = set(getattr(settings, "api_keys", set()) or set()) | set(
        desktop_engine_keys()
    )
    if any(hmac.compare_digest(configured, str(key)) for key in runtime_keys):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="审批管理员 Key 与运行时 API Key 重叠；拒绝审批操作",
        )
    try:
        web_cookie = local_web_approval_cookie(
            request,
            configured,
            port=int(getattr(settings, "gateway_port", 8080) or 8080),
        )
    except LocalWebSessionRejected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="本机 Web 审批会话无效；请从纳川启动入口重新打开",
            headers={"Cache-Control": "no-store"},
        ) from None
    if web_cookie:
        candidate_header = (x_nachuan_approval_key or "").strip()
        if candidate_header and not hmac.compare_digest(candidate_header, configured):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="本机 Web 会话与审批 Key 冲突",
                headers={"Cache-Control": "no-store"},
            )
        return "approval-admin"

    candidate = (x_nachuan_approval_key or "").strip()
    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"缺少 {APPROVAL_ADMIN_HEADER}",
        )
    if not hmac.compare_digest(candidate, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的审批管理员 Key",
        )
    # Do not pass the secret further into endpoint code or logs.
    return "approval-admin"
