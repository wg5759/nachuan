"""本地 Web UI 静态托管合同测试（ADR-0013）。

安全闭集：仅 GET/HEAD、严格根内路径、拒绝穿越/symlink 逃逸/超限文件、
/v1 /admin /internal 等保留前缀绝不 SPA fallback；无外置目录时托管 wheel 内 UI。
"""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.local_web_ui import (
    mount_local_web_ui,
    resolve_web_ui_dir,
)


@pytest.fixture
def web_root(tmp_path):
    root = tmp_path / "web"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<html>nachuan</html>", encoding="utf-8")
    (root / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (root / "assets" / "app.css").write_text("body{}", encoding="utf-8")
    return root


def _mounted_app(root) -> FastAPI:
    app = FastAPI()
    assert mount_local_web_ui(app, directory=root) is True
    return app


class TestResolveDir:
    def test_unset_uses_bundled_web_ui(self, monkeypatch):
        monkeypatch.delenv("NACHUAN_WEB_UI_DIR", raising=False)
        root = resolve_web_ui_dir(None)
        assert root is not None
        assert (root / "index.html").is_file()
        assert (root / "api-shim.js").is_file()

    def test_missing_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NACHUAN_WEB_UI_DIR", str(tmp_path / "nope"))
        assert resolve_web_ui_dir(None) is None

    def test_not_a_directory(self, monkeypatch, tmp_path):
        f = tmp_path / "file"
        f.write_text("x", encoding="utf-8")
        monkeypatch.setenv("NACHUAN_WEB_UI_DIR", str(f))
        assert resolve_web_ui_dir(None) is None

    def test_valid(self, monkeypatch, web_root):
        monkeypatch.setenv("NACHUAN_WEB_UI_DIR", str(web_root))
        assert resolve_web_ui_dir(None) == web_root.resolve()

    def test_missing_index_is_rejected(self, monkeypatch, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setenv("NACHUAN_WEB_UI_DIR", str(empty))
        assert resolve_web_ui_dir(None) is None


class TestMountFailClosed:
    def test_explicit_empty_directory_not_mounted(self):
        app = FastAPI()
        assert mount_local_web_ui(app, directory="") is False
        assert TestClient(app).get("/").status_code == 404


class TestServing:
    def test_index_at_root(self, web_root):
        client = TestClient(_mounted_app(web_root))
        r = client.get("/")
        assert r.status_code == 200
        assert "nachuan" in r.text
        assert r.headers["content-type"].startswith("text/html")
        assert r.headers["cache-control"] == "no-store"

    def test_static_asset_content_type(self, web_root):
        client = TestClient(_mounted_app(web_root))
        r = client.get("/assets/app.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
        r = client.get("/assets/app.css")
        assert r.status_code == 200
        assert "text/css" in r.headers["content-type"]

    def test_spa_fallback(self, web_root):
        client = TestClient(_mounted_app(web_root))
        r = client.get("/chat/some/view")
        assert r.status_code == 200
        assert "nachuan" in r.text

    def test_head_allowed(self, web_root):
        client = TestClient(_mounted_app(web_root))
        assert client.head("/").status_code == 200

    def test_security_headers(self, web_root):
        client = TestClient(_mounted_app(web_root))
        r = client.get("/assets/app.js")
        assert r.headers["x-content-type-options"] == "nosniff"


class TestClosedSet:
    @pytest.mark.parametrize("prefix", ["/v1/unknown", "/admin/x", "/internal/x"])
    def test_reserved_prefixes_never_fall_back(self, web_root, prefix):
        client = TestClient(_mounted_app(web_root))
        assert client.get(prefix).status_code == 404

    def test_missing_asset_is_404_not_index(self, web_root):
        client = TestClient(_mounted_app(web_root))
        assert client.get("/assets/missing.js").status_code == 404

    @pytest.mark.parametrize(
        "path",
        [
            "/%2e%2e/%2e%2e/secret.txt",
            "/..%2f..%2fsecret.txt",
            "/assets/..%2f..%2fsecret.txt",
            "/%2e%2e%5c%2e%2e%5csecret.txt",
        ],
    )
    def test_traversal_rejected(self, web_root, tmp_path, path):
        (tmp_path / "secret.txt").write_text("topsecret", encoding="utf-8")
        client = TestClient(_mounted_app(web_root))
        r = client.get(path)
        assert r.status_code in (400, 404)
        assert "topsecret" not in r.text

    def test_symlink_escape_rejected(self, web_root, tmp_path):
        outside = tmp_path / "secret.txt"
        outside.write_text("topsecret", encoding="utf-8")
        link = web_root / "leak.txt"
        try:
            os.symlink(outside, link)
        except OSError:
            pytest.skip("symlink creation not permitted on this host")
        client = TestClient(_mounted_app(web_root))
        r = client.get("/leak.txt")
        assert r.status_code == 404
        assert "topsecret" not in r.text

    def test_oversize_file_rejected(self, web_root, monkeypatch):
        import gateway.local_web_ui as ui

        monkeypatch.setattr(ui, "_MAX_FILE_BYTES", 8)
        client = TestClient(_mounted_app(web_root))
        assert client.get("/assets/app.js").status_code == 404

    def test_post_not_allowed(self, web_root):
        client = TestClient(_mounted_app(web_root))
        assert client.post("/").status_code == 405


class TestGatewayWiring:
    """真实 gateway.app 接线：env 指向有效目录时必须实际托管 UI。

    在子进程内导入真实应用，避免污染测试进程的全局应用状态；
    禁止用源码字符串存在性冒充接线证据。
    """

    def test_real_gateway_serves_ui_when_env_set(self, tmp_path):
        import subprocess
        import sys

        web = tmp_path / "web"
        web.mkdir()
        (web / "index.html").write_text("<html>nachuan-wiring</html>", encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "NACHUAN_WEB_UI_DIR": str(web),
                "GATEWAY_API_KEYS": "test-key",
                "USAGE_DB_PATH": str(tmp_path / "usage.db"),
                "NACHUAN_EMBED_DISABLED": "1",
                "AGENT_EXEC_WORKDIR": str(tmp_path),
                "DATA_DIR": str(tmp_path / "data"),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        probe = (
            "from fastapi.testclient import TestClient;"
            "from gateway.app import app;"
            "c = TestClient(app);"
            "r = c.get('/');"
            "assert r.status_code == 200, r.status_code;"
            "assert 'nachuan-wiring' in r.text;"
            "r2 = c.get('/v1/definitely-not-a-route');"
            "assert r2.status_code == 404, r2.status_code;"
            "r3 = c.get('/health');"
            "assert r3.status_code == 200, r3.status_code;"
            "print('WIRING-OK')"
        )
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert "WIRING-OK" in result.stdout

    def test_real_gateway_without_env_serves_bundled_ui(self, tmp_path):
        import subprocess
        import sys

        env = os.environ.copy()
        env.pop("NACHUAN_WEB_UI_DIR", None)
        env.update(
            {
                "GATEWAY_API_KEYS": "test-key",
                "USAGE_DB_PATH": str(tmp_path / "usage.db"),
                "NACHUAN_EMBED_DISABLED": "1",
                "AGENT_EXEC_WORKDIR": str(tmp_path),
                "DATA_DIR": str(tmp_path / "data"),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        probe = (
            "from fastapi.testclient import TestClient;"
            "from gateway.app import app;"
            "c = TestClient(app);"
            "r = c.get('/');"
            "assert r.status_code == 200, r.status_code;"
            "assert 'api-shim.js' in r.text;"
            "assert c.get('/api-shim.js').status_code == 200;"
            "print('BUNDLED-UI-OK')"
        )
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert "BUNDLED-UI-OK" in result.stdout
