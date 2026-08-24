"""生图（M3 多模态）：provider 生图方法 + /v1/images/generations 端点 wiring。"""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.providers.base import ProviderError
from gateway.providers.openai_compat import OpenAICompatProvider
from gateway.schemas import ImageGenerationRequest

UP = "https://up.example/v1"


def _req() -> ImageGenerationRequest:
    return ImageGenerationRequest(model="img", prompt="a cat", size="1024x1024")


@respx.mock
async def test_generate_image_ok():
    route = respx.post(f"{UP}/images/generations").mock(
        return_value=httpx.Response(200, json={"data": [{"url": "https://img/x.png"}]})
    )
    p = OpenAICompatProvider(name="t", base_url=UP, api_key="k")
    out = await p.generate_image(_req(), "Agnes-Image-2.1-Flash")
    assert out["data"][0]["url"].endswith(".png")
    assert b"Agnes-Image-2.1-Flash" in route.calls.last.request.content  # 上游模型名替换
    await p.aclose()


@respx.mock
async def test_generate_image_error_maps_status():
    respx.post(f"{UP}/images/generations").mock(return_value=httpx.Response(429, text="rate"))
    p = OpenAICompatProvider(name="t", base_url=UP, api_key="k")
    with pytest.raises(ProviderError) as ei:
        await p.generate_image(_req(), "m")
    assert ei.value.status_code == 429
    await p.aclose()


def test_image_endpoint_unsupported_provider(paid_media_auth_headers):
    # v2 已协商，但 echo 没有声明受控 asset-v2 能力，必须在 provider 前失败关闭。
    with TestClient(app) as c:
        r = c.post(
            "/v1/images/generations",
            headers={
                **paid_media_auth_headers,
                "Idempotency-Key": f"test-image-{uuid4()}",
                "X-Nachuan-Paid-Media-Protocol": "2",
            },
            json={"model": "echo", "prompt": "x"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["code"] == "paid_media_provider_protocol_unsupported"
