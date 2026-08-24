"""测试夹具：隔离用量库到临时目录，固定网关 Key。"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

# 测试环境默认禁用本地 embedding：避免每个 TestClient(app) 启动都后台加载 bge(~45s)。
# 需要验证向量的测试用 monkeypatch 直接替换 embedder._INSTANCE.encode 绕过此开关。
os.environ.setdefault("NACHUAN_EMBED_DISABLED", "1")
os.environ.setdefault("AGENT_EXEC_WORKDIR", tempfile.gettempdir())


@pytest.fixture(scope="session", autouse=True)
def _test_env():
    tmp = tempfile.mkdtemp(prefix="aggr-test-")
    os.environ["USAGE_DB_PATH"] = os.path.join(tmp, "usage.db")
    os.environ["GATEWAY_API_KEYS"] = "test-key"
    # 清掉可能已缓存的设置，确保读到上面的测试环境
    from gateway.config import get_settings

    get_settings.cache_clear()
    yield


@pytest.fixture(autouse=True)
def _reset_admission_daily_counter():
    """会话级共享的 admission.db 会把付费 POST 日额度（默认 2000/Key）在全量
    套件中打穿，导致字母序靠后的文件集体 429。每个用例前清空计数表，恢复
    跨文件隔离；不改产品默认值（admission 默认值测试仍见 2000）。
    """

    usage_db = str(os.environ.get("USAGE_DB_PATH") or "")
    if usage_db:
        from pathlib import Path as _Path

        db = _Path(usage_db).parent / "admission.db"
        if db.is_file():
            import sqlite3 as _sqlite3

            conn = _sqlite3.connect(str(db), timeout=5.0)
            try:
                conn.execute("DELETE FROM admission_daily")
                conn.commit()
            except _sqlite3.OperationalError:
                # 表尚未创建时无需清理
                conn.rollback()
            finally:
                conn.close()
    yield


@pytest.fixture(autouse=True)
def _reset_admission_rolling_state():
    """滚动 60 秒 120 次/Key 的内存桶挂在进程级中间件实例上：全量套件连续
    爆发会让窗口跨文件保持满载，后续文件集体 429（独立跑文件不触发）。
    每个用例前清空内存桶；仅当 gateway.app 已被导入才操作。
    """

    appmod = sys.modules.get("gateway.app")
    if appmod is not None:
        seen: set[int] = set()
        stack = [getattr(appmod, "app", None)]
        while stack:
            node = stack.pop()
            if node is None or id(node) in seen:
                continue
            seen.add(id(node))
            states = getattr(node, "_states", None)
            if isinstance(states, dict):
                states.clear()
            if getattr(node, "_global_in_flight", None) is not None:
                try:
                    node._global_in_flight = 0
                except Exception:
                    pass
            for attr in ("app", "_downstream", "downstream", "middleware_stack"):
                stack.append(getattr(node, attr, None))
    yield


@pytest.fixture(autouse=True)
def _restore_process_environment_after_each_test():
    """生产代码可能绕过 monkeypatch 直接写进程环境（如
    enforce_frozen_store_profile 钉死 NACHUAN_RUNTIME_PROFILE/YTDLP_NO_PLUGINS）；
    monkeypatch 只还原它自己写的键。每个用例后整体还原环境，阻断跨文件泄漏
    （曾致 test_tool_agent/test_xreview_roster 等 40+ 用例被 store 剖面误杀）。
    """

    before = dict(os.environ)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(before)


@pytest.fixture
def approval_auth_headers(monkeypatch):
    """Explicitly enter the independent approval-admin trust domain for one test."""
    secret = "sk-approval-test-" + ("a" * 64)
    monkeypatch.setenv("APPROVAL_ADMIN_KEY", secret)
    from gateway.config import get_settings

    get_settings.cache_clear()
    try:
        yield {
            "Authorization": "Bearer test-key",
            "X-Nachuan-Approval-Key": secret,
        }
    finally:
        # monkeypatch restores the environment after fixture teardown; leave no
        # Settings instance containing the test approval secret in the cache.
        get_settings.cache_clear()


@pytest.fixture
def paid_media_auth_headers(monkeypatch):
    """Explicitly enter the engine-only paid-media trust domain for one test."""
    secret = "sk-paid-media-" + ("a" * 64)
    monkeypatch.setenv("NACHUAN_PAID_MEDIA_API_KEY", secret)
    from gateway.config import get_settings

    get_settings.cache_clear()
    try:
        yield {
            "Authorization": "Bearer test-key",
            "X-Nachuan-Paid-Media-Key": secret,
        }
    finally:
        get_settings.cache_clear()
