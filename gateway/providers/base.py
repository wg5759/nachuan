"""Provider 抽象接口：所有来源（火山 / Claude / Codex / 通用兼容）都实现它。

新增一个模型来源 = 新增一个实现本类的文件，再在 config/models.yaml 注册即可，
网关与编排层代码无需改动。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator

from gateway.schemas import ChatCompletionRequest, ImageGenerationRequest, VideoGenerationRequest


class ProviderError(Exception):
    """Provider 调用失败。status_code 用于网关回传给客户端。"""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class ProviderSubmissionOutcomeUnknown(ProviderError):
    """A non-idempotent request may have been accepted by the provider.

    Callers must surface this result without retrying or moving to a fallback
    route, otherwise one user action can execute and be billed more than once.
    """


def friendly_error(exc: object) -> str:
    """把底层异常翻成可公开展示的人话，绝不回显未知原文。"""
    low = str(exc).lower()
    if any(
        k in low
        for k in ("all connection attempts failed", "connecterror", "connection refused", "cannot connect", "connection error")
    ):
        return "连不上上游服务——网络不通或需要代理"
    if any(k in low for k in ("getaddrinfo", "name resolution", "nodename", "no address associated")):
        return "域名解析失败——网络/DNS 问题，可能需要代理"
    if any(k in low for k in ("timed out", "timeout")):
        return "上游响应超时——上游繁忙或网络慢，稍后重试"
    if "ssl" in low or "certificate" in low:
        return "SSL/证书错误——网络中间件或代理问题"
    # 未识别异常可能含 API Key、上游响应体、本机路径、命令行或租户信息。
    # 详细信息只能进入受保护的诊断/审计面，不能成为面向客户的错误文案。
    return "上游请求失败——请稍后重试或到诊断中心查看详情"


def friendly_status(code: int, body: str = "") -> str:
    """把上游 HTTP 状态码翻成可公开展示的人话，不回显响应体。"""
    del body
    if code in (401, 403):
        return f"鉴权失败（{code}）——API Key 无效/失效或无权限，去连接中心检查"
    if code == 404:
        return "找不到接口或模型（404）——检查 base_url 与模型 ID"
    if code == 429:
        return "请求太频繁或超额（429）——稍后再试或检查套餐余量"
    if code >= 500:
        return f"上游服务异常（{code}）——上游临时故障，稍后重试"
    if 400 <= code < 500:
        return f"上游拒绝了请求（{code}）——请检查请求参数或模型配置"
    return f"上游返回了异常状态（{code}）"


class ChatProvider(ABC):
    """统一的聊天补全接口。"""

    #: provider 实例名（与 config/models.yaml 的 providers 键一致）
    name: str = "base"
    #: 是否就绪（如缺少密钥则为 False；未就绪的 provider 其模型不会被注册）
    enabled: bool = True
    #: Explicit opt-in for bounded paid-media asset wire protocols.  Gateway
    #: callers must never infer this capability from the legacy image method.
    paid_media_asset_protocol_versions: frozenset[str] = frozenset()
    # Video has different byte/capacity semantics from image v2.  Adapters
    # must opt in separately after their bounded terminal metadata path is
    # verified; image capability never implies video capability.
    paid_media_video_asset_protocol_versions: frozenset[str] = frozenset()

    def expected_model_family(self, upstream_model: str) -> str | None:
        """Return None unless a provider-specific adapter owns this assertion."""

        del upstream_model
        return None

    def verify_model_identity(
        self,
        upstream_model: str,
        observed_model: str,
    ) -> tuple[str, str] | None:
        """Fail closed unless a provider-specific adapter owns verification."""

        del upstream_model, observed_model
        return None

    @abstractmethod
    async def chat(self, req: ChatCompletionRequest, upstream_model: str) -> dict[str, Any]:
        """非流式：返回一个 OpenAI 兼容的 chat.completion 对象（dict）。"""
        raise NotImplementedError

    async def probe_chat(
        self, req: ChatCompletionRequest, upstream_model: str
    ) -> dict[str, Any]:
        """Verify a chat route; adapters may override with a tighter wire path."""

        return await self.chat(req, upstream_model)

    @abstractmethod
    def stream(
        self, req: ChatCompletionRequest, upstream_model: str
    ) -> AsyncIterator[dict[str, Any]]:
        """流式：异步产出 OpenAI 兼容的 chat.completion.chunk 对象（dict）。

        实现为 async generator。网关负责把这些 dict 包成 SSE 帧。
        """
        raise NotImplementedError

    async def generate_image(
        self, req: ImageGenerationRequest, upstream_model: str
    ) -> dict[str, Any]:
        """生图（默认不支持）；支持生图的 provider 覆盖本方法。"""
        raise ProviderError("该来源不支持生图", status_code=400)

    async def generate_image_asset_urls(
        self, req: ImageGenerationRequest, upstream_model: str
    ) -> dict[str, Any]:
        """Return only bounded URL metadata for paid-media protocol v2."""

        raise ProviderError(
            "provider does not support paid-media asset protocol v2",
            status_code=400,
        )

    async def generate_video(
        self, req: VideoGenerationRequest, upstream_model: str
    ) -> dict[str, Any]:
        """生视频·创建任务（默认不支持）。"""
        raise ProviderError("该来源不支持生视频", status_code=400)

    async def get_video(self, task_id: str) -> dict[str, Any]:
        """生视频·查询任务（默认不支持）。"""
        raise ProviderError("该来源不支持视频查询", status_code=400)

    async def aclose(self) -> None:
        """释放资源（如 httpx client）。默认无操作。"""
        return None
