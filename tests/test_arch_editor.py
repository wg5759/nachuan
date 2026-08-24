"""架构师/编辑：文件解析逻辑 + 路径穿越防护 + 端点校验。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.app import app
from orchestrator.workflows.coding_team import parse_files

AUTH = {"Authorization": "Bearer test-key"}


def test_parse_files_basic():
    text = "前言\n=== src/a.py ===\n```python\nprint('hi')\n```\n=== b.txt ===\nhello\n"
    files = dict(parse_files(text))
    assert files["src/a.py"] == "print('hi')"  # 去掉了 ``` 围栏
    assert files["b.txt"] == "hello"


def test_parse_files_rejects_traversal():
    text = "=== ../evil.py ===\nx\n=== /etc/passwd ===\ny\n"
    assert parse_files(text) == []  # 绝对路径与 .. 穿越都被拒


def test_arch_editor_endpoint_is_fail_closed_until_isolated_worker():
    with TestClient(app) as c:
        r = c.post("/v1/orchestrate/arch-editor", headers=AUTH, json={"task": "x"})
        assert r.status_code == 503
