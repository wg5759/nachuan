"""ADR-0013 接线测试：真实 Web 构建产物（desktop/out-web）由网关托管的合同。

前置：CI/本地先跑 ``npm --prefix desktop run build:web`` 产出 out-web；
缺失时本文件整组 skip（纯 Python 改动不必先装 Node 工具链）。

合同：
- ``GET /`` 与 ``GET /api-shim.js`` 均 200；
- index.html 在 app module bundle 之前引用 api-shim.js（经典脚本先执行，
  window.api 先于 React 应用就位），且 CSP meta 先于 shim 标签（shim 受 CSP 约束）；
- CSP 未为 Web 形态放宽（connect-src 仍 'self'，同源天然兼容）；
- shim 为经典脚本（非 module），同源托管 text/javascript；
- /v1 保留前缀永不 SPA fallback。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.local_web_ui import mount_local_web_ui

_OUT_WEB = Path(__file__).resolve().parents[1] / "desktop" / "out-web"

pytestmark = pytest.mark.skipif(
    not (_OUT_WEB / "index.html").is_file() or not (_OUT_WEB / "api-shim.js").is_file(),
    reason="desktop/out-web 未构建：先跑 npm --prefix desktop run build:web",
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = FastAPI()
    assert mount_local_web_ui(app, directory=_OUT_WEB) is True
    return TestClient(app)


class TestWebUiShimBundle:
    def test_index_served(self, client: TestClient):
        r = client.get("/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert r.headers["cache-control"] == "no-store"

    def test_shim_served_as_classic_script(self, client: TestClient):
        r = client.get("/api-shim.js")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/javascript")
        # shim 安装了 window.api 的 HTTP 适配层；密钥只保留在标签页会话，
        # durable localStorage 仅用于删除历史纳川密钥项。
        assert "nachuan.web.runtimeKey" in r.text
        assert "sessionStorage" in r.text

    def test_shim_loaded_before_app_bundle(self, client: TestClient):
        html = client.get("/").text
        shim_pos = html.find("api-shim.js")
        bundle = re.search(r'<script type="module"[^>]*src="\./assets/[^"]+\.js"', html)
        assert shim_pos != -1, "index.html 未引用 api-shim.js"
        assert bundle is not None, "index.html 缺少 app module bundle 引用"
        assert shim_pos < bundle.start(), "api-shim.js 必须先于 app bundle 加载"

    def test_shim_tag_is_classic_and_after_csp_meta(self, client: TestClient):
        html = client.get("/").text
        csp_pos = html.find("http-equiv=\"Content-Security-Policy\"")
        shim_tag = re.search(r"<script src=\"\./api-shim\.js\"></script>", html)
        assert csp_pos != -1
        assert shim_tag is not None, "api-shim 必须以经典 script（非 module）加载"
        assert csp_pos < shim_tag.start(), "CSP meta 必须先于 shim 标签生效"

    def test_csp_not_relaxed_for_web(self, client: TestClient):
        html = client.get("/").text
        assert "connect-src 'self' data: blob:" in html
        assert "default-src 'self'" in html
        # 不得出现通配/跨域放宽。
        assert "connect-src *" not in html
        assert "unsafe-eval" not in html

    def test_reserved_prefix_never_spa_fallback(self, client: TestClient):
        assert client.get("/v1/paid-media/web/claim").status_code == 404
        assert client.get("/admin/connections/x").status_code == 404
