"""火山引擎方舟（Volcengine Ark）provider。

方舟 OpenAI 兼容端点：
  - 通用:   https://ark.cn-beijing.volces.com/api/v3
  - 编程版: https://ark.cn-beijing.volces.com/api/coding/v3   （编程优化，可选切换）
模型 id 以方舟控制台为准（如 deepseek-v3-2-251201、doubao-seed-* 等）。

火山方舟与 OpenAI 协议完全兼容，故复用通用实现；本类仅提供默认 base_url
与一个清晰的「火山专属」归属点（将来如需处理火山特有行为可在此扩展）。

缓存（省 token，③评估结论）：火山上的 DeepSeek 系模型走「自动前缀缓存」，命中即降价、
无需额外参数——保持稳定的消息前缀即可（见 app.py 记忆注入位置的②调整，自动受益）。
Doubao 系的「上下文缓存」需走有状态 Context API（创建缓存→引用 cache_id），
对个人桌面单会话场景收益有限、复杂度高，暂不接入（将来真有需要再加）。
"""

from __future__ import annotations

from urllib.parse import urlsplit

from gateway.model_identity import exact_verified_model_identity, model_family_from_identifier
from gateway.providers.openai_compat import OpenAICompatProvider

DEFAULT_BASE_URL = "https://ark.cn-beijing.volces.com/api/v3"


class VolcanoProvider(OpenAICompatProvider):
    """Provider-bound Ark adapter; unlike generic compat it may attest exact ids."""

    def __init__(
        self,
        name: str,
        api_key: str,
        base_url: str | None = None,
        timeout: float = 300.0,
    ):
        super().__init__(
            name=name,
            base_url=base_url or DEFAULT_BASE_URL,
            api_key=api_key,
            timeout=timeout,
        )

    def _trusted_identity_endpoint(self) -> bool:
        try:
            parsed = urlsplit(str(getattr(self, "base_url", "") or ""))
            return bool(
                parsed.scheme.casefold() == "https"
                and (parsed.hostname or "").casefold() == "ark.cn-beijing.volces.com"
                and parsed.port in (None, 443)
                and parsed.username is None
                and parsed.password is None
                and not parsed.query
                and not parsed.fragment
                and parsed.path.rstrip("/") in {"/api/v3", "/api/coding/v3"}
            )
        except (UnicodeError, ValueError):
            return False

    def expected_model_family(self, upstream_model: str) -> str | None:
        if not self._trusted_identity_endpoint():
            return None
        return model_family_from_identifier(upstream_model)

    def verify_model_identity(
        self, upstream_model: str, observed_model: str
    ) -> tuple[str, str] | None:
        if not self._trusted_identity_endpoint():
            return None
        return exact_verified_model_identity(upstream_model, observed_model)
