"""Perplexity's split endpoint layout on top of Chat Completions.

Perplexity is OpenAI-compatible for chat payloads, but its API root is not an
OpenAI-style ``/v1`` base: chat uses ``/chat/completions`` while model discovery
uses ``/v1/models``.  Keeping this as a dedicated provider prevents generic
``base_url + '/models'`` discovery from silently targeting the wrong endpoint.

The newer Sonar endpoint (``/v1/sonar``) is deliberately not used here.  It has
its own API contract and must not be presented as Chat Completions until that
request/response schema has a separately tested adapter.
"""

from __future__ import annotations

from gateway.providers.openai_compat import OpenAICompatProvider


PERPLEXITY_OFFICIAL_BASE_URL = "https://api.perplexity.ai"
PERPLEXITY_CHAT_COMPLETIONS_URL = (
    f"{PERPLEXITY_OFFICIAL_BASE_URL}/chat/completions"
)
PERPLEXITY_MODEL_CATALOG_URL = f"{PERPLEXITY_OFFICIAL_BASE_URL}/v1/models"
PERPLEXITY_SONAR_API_URL = f"{PERPLEXITY_OFFICIAL_BASE_URL}/v1/sonar"


def require_official_perplexity_base_url(base_url: str) -> str:
    """Return the one supported base or fail closed.

    Connection normalization canonicalizes a trailing slash before this helper
    is called.  Accepting it here as well keeps direct construction predictable
    without allowing alternate hosts, ports, paths, queries, or fragments.
    """

    if not isinstance(base_url, str):
        raise ValueError("Perplexity base_url must be a string")
    normalized = base_url.strip().rstrip("/")
    if normalized != PERPLEXITY_OFFICIAL_BASE_URL:
        raise ValueError("Perplexity requires its exact official API base")
    return PERPLEXITY_OFFICIAL_BASE_URL


def perplexity_model_catalog_url(base_url: str) -> str:
    require_official_perplexity_base_url(base_url)
    return PERPLEXITY_MODEL_CATALOG_URL


class PerplexityProvider(OpenAICompatProvider):
    """Bounded Chat Completions transport with Perplexity's exact paths."""

    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str,
        timeout: float = 300.0,
    ) -> None:
        super().__init__(
            name=name,
            base_url=require_official_perplexity_base_url(base_url),
            api_key=api_key,
            timeout=timeout,
        )

    @property
    def _endpoint(self) -> str:
        return PERPLEXITY_CHAT_COMPLETIONS_URL

    @property
    def model_catalog_endpoint(self) -> str:
        return PERPLEXITY_MODEL_CATALOG_URL

    @property
    def sonar_endpoint(self) -> str:
        """Expose the known endpoint without claiming protocol support."""

        return PERPLEXITY_SONAR_API_URL
