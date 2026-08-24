"""Supabase 跨设备云同步（orchestrator/cloud_sync）测试：mock REST，不连真云。

覆盖：内容指纹归一一致、配置/登录、push+pull 合并、pull 去重、未就绪降级。
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from pathlib import Path

import httpx
import pytest
import respx

from orchestrator import cloud_sync


@pytest.fixture
def env(tmp_path, monkeypatch):
    """把 cloud_sync 的数据目录指到临时目录，并建好四张本地表（memory 放 1 条）。"""
    monkeypatch.setattr(cloud_sync, "_DATA", tmp_path)
    monkeypatch.setattr(cloud_sync, "_CFG_PATH", tmp_path / "sync.json")
    monkeypatch.setattr(cloud_sync, "is_public_http_url", lambda _url: True)

    # Policy/state tests use portable atomic JSON; DPAPI + ACL are covered by
    # tests/test_secure_store.py and should not make every transition expensive.
    def read(path, *, purpose, migrate_plaintext=False, plaintext_migrator=None):
        del purpose, migrate_plaintext, plaintext_migrator
        return json.loads(Path(path).read_text("utf-8"))

    def write(path, payload, *, purpose):
        del purpose
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(json.dumps(dict(payload)), "utf-8")
        temporary.replace(target)

    monkeypatch.setattr(cloud_sync, "read_protected_json", read)
    monkeypatch.setattr(cloud_sync, "write_protected_json", write)
    m = sqlite3.connect(tmp_path / "memory.db")
    m.execute(
        "CREATE TABLE user_memory(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,"
        "text TEXT,kind TEXT,created_at REAL,updated_at REAL)"
    )
    m.execute(
        "INSERT INTO user_memory(user_id,text,kind,created_at,updated_at) "
        "VALUES('owner','机主最爱数字7','fact',1.0,1.0)"
    )
    m.commit()
    m.close()
    c = sqlite3.connect(tmp_path / "cases.db")
    c.execute(
        "CREATE TABLE cases(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,problem TEXT,"
        "solution TEXT,model TEXT,created_at REAL)"
    )
    c.commit()
    c.close()
    k = sqlite3.connect(tmp_path / "knowledge.db")
    k.execute(
        "CREATE TABLE kb_docs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,title TEXT,"
        "source TEXT,chunks INTEGER,created_at REAL)"
    )
    k.execute(
        "CREATE TABLE kb_chunks(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,"
        "doc_id INTEGER,title TEXT,text TEXT)"
    )
    k.commit()
    k.close()
    return tmp_path


def _ready():
    """写一份"已配置+已登录"的就绪 cfg。"""
    cloud_sync.save_cfg({
        **cloud_sync._DEFAULT_CFG,
        "url": "https://x.supabase.co", "anon_key": "anon", "access_token": "tok",
        "user_id": "uid-1", "local_user": "owner", "enabled": True,
        "device_id": "dev", "last_sync": {},
    })


def test_bind_data_dir_uses_the_gateway_runtime_root(env, tmp_path):
    runtime = (tmp_path / "packaged-data").resolve()
    cloud_sync.bind_data_dir(runtime)

    assert cloud_sync._DATA == runtime
    assert cloud_sync._CFG_PATH == runtime / "sync.json"
    with pytest.raises(ValueError):
        cloud_sync.bind_data_dir("relative-data")


def test_gateway_startup_binds_and_migrates_cloud_credentials_before_worker():
    """The legacy plaintext secret must not wait for the first 120s sync tick."""

    source = (
        Path(__file__).resolve().parents[1] / "gateway" / "app.py"
    ).read_text("utf-8")
    bind = source.index("cloud_sync.bind_data_dir(data_dir)")
    migrate = source.index("await run_in_threadpool(cloud_sync.load_cfg)", bind)
    worker = source.index("spawn_background(_cloud_sync_loop())", migrate)

    assert bind < migrate < worker


def test_legacy_plaintext_cloud_credentials_are_revoked_instead_of_reencrypted():
    legacy = {
        "url": "https://x.supabase.co",
        "anon_key": "legacy-anon",
        "access_token": "legacy-access",
        "refresh_token": "legacy-refresh",
        "enabled": True,
    }

    assert cloud_sync._revoke_legacy_plaintext_cfg(legacy) == {}


def test_norm_and_hash_stable():
    assert cloud_sync._norm("  a\n b  ") == "a b"
    # 归一化后内容相同 → hash 相同（跨设备去重的基石）
    assert cloud_sync._hash("机主 爱 7") == cloud_sync._hash("  机主  爱   7 ")
    assert cloud_sync._hash("a") != cloud_sync._hash("b")


def test_configure_status(env):
    cloud_sync.configure("https://x.supabase.co/", "anon-key")
    s = cloud_sync.status()
    assert s["configured"] and not s["logged_in"]
    assert s["enabled"] is False
    assert s["url"] == "https://x.supabase.co"  # 尾斜杠被去掉
    assert s["target_safe"] is True
    assert s["target_fingerprint"] == cloud_sync.target_fingerprint(
        "https://x.supabase.co/rest/v1/", "anon-key"
    )
    assert s["scope"] == "personal_account"
    assert s["local_user"] == "owner"
    assert s["sync_tables"] == ["memory", "cases", "kb_docs", "kb_chunks"]
    assert not cloud_sync.available()  # 还没登录
    # 容错：填成 .../rest/v1/ 也规整成项目根域名
    cloud_sync.configure("https://x.supabase.co/rest/v1/", "anon-key")
    assert cloud_sync.status()["url"] == "https://x.supabase.co"


def test_target_fingerprint_is_canonical_and_binds_anon_key(env):
    root = cloud_sync.target_fingerprint("https://X.SUPABASE.CO/", "anon-a")
    rest = cloud_sync.target_fingerprint("https://x.supabase.co/rest/v1", "anon-a")
    assert root == rest
    assert root.startswith("sha256:")
    assert root != cloud_sync.target_fingerprint("https://x.supabase.co", "anon-b")


@pytest.mark.parametrize(
    ("new_url", "new_key", "expected_url"),
    [
        ("https://x.supabase.co/auth/v1/", "anon-new", "https://x.supabase.co"),
        ("https://other.supabase.co", "anon", "https://other.supabase.co"),
    ],
)
def test_retarget_revokes_old_session_cursor_and_enablement(
    env, new_url, new_key, expected_url
):
    _ready()
    cfg = cloud_sync.load_cfg()
    cfg.update(
        {
            "refresh_token": "refresh-old",
            "email": "old@example.com",
            "last_sync": {"memory": 99.0},
        }
    )
    cloud_sync.save_cfg(cfg)

    # URL 或 anon key 任一变更，都是新的信任边界。
    cloud_sync.configure(new_url, new_key)

    changed = cloud_sync.load_cfg()
    assert changed["url"] == expected_url
    assert changed["anon_key"] == new_key
    assert changed["access_token"] == ""
    assert changed["refresh_token"] == ""
    assert changed["user_id"] == ""
    assert changed["email"] == ""
    assert changed["last_sync"] == {}
    assert changed["enabled"] is False


def test_same_canonical_target_does_not_revoke_session(env):
    _ready()
    before = cloud_sync.load_cfg()

    cloud_sync.configure("https://X.SUPABASE.CO/rest/v1/", "anon")

    after = cloud_sync.load_cfg()
    assert after["access_token"] == before["access_token"]
    assert after["user_id"] == before["user_id"]
    assert after["enabled"] is True


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://x.supabase.co",
        "https://x.supabase.co/other",
        "https://x.supabase.co?redirect=https://evil.example",
        "https://x.supabase.co/#fragment",
        "https://user:pass@x.supabase.co",
        "https://supabase.co",
        "https://evil.example",
        "https://127.0.0.1",
        "https://169.254.169.254/latest/meta-data",
    ],
)
def test_unsafe_supabase_target_is_rejected_without_touching_old_config(env, unsafe_url):
    _ready()
    before = cloud_sync.load_cfg()

    with pytest.raises(ValueError):
        cloud_sync.configure(unsafe_url, "replacement")

    assert cloud_sync.load_cfg() == before


def test_explicit_supabase_host_allowlist_is_exact_and_still_https_public(
    env, monkeypatch
):
    monkeypatch.setenv("NACHUAN_SUPABASE_HOST_ALLOWLIST", "sync.example.com")
    cloud_sync.configure("https://SYNC.EXAMPLE.COM/", "anon")
    assert cloud_sync.status()["url"] == "https://sync.example.com"

    with pytest.raises(ValueError):
        cloud_sync.configure("https://child.sync.example.com", "anon")


def test_failed_retarget_write_preserves_previous_config(env, monkeypatch):
    _ready()
    before = cloud_sync.load_cfg()
    working_write = cloud_sync.write_protected_json

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic persistence failure")

    monkeypatch.setattr(cloud_sync, "write_protected_json", fail_write)
    with pytest.raises(OSError, match="synthetic persistence failure"):
        cloud_sync.configure("https://other.supabase.co", "other-anon")

    # 解除故障注入后从磁盘重新读，旧目标与会话仍完整。
    monkeypatch.setattr(cloud_sync, "write_protected_json", working_write)
    assert cloud_sync.load_cfg() == before


def test_malformed_state_is_rejected_before_overwriting_previous_config(env):
    _ready()
    before = cloud_sync.load_cfg()
    malformed = {**before, "last_sync": {"memory": float("nan")}}

    with pytest.raises(ValueError, match="last_sync"):
        cloud_sync.save_cfg(malformed)

    assert cloud_sync.load_cfg() == before


def test_inflight_login_cannot_revive_credentials_after_retarget(env, monkeypatch):
    _ready()

    class Response:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "access_token": "stale-access",
                "refresh_token": "stale-refresh",
                "user": {"id": "stale-user"},
            }

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            cloud_sync.configure("https://other.supabase.co", "other-anon")
            return Response()

    monkeypatch.setattr(cloud_sync, "_client", Client)
    result = cloud_sync.login("old@example.com", "pw")

    assert result["ok"] is False
    cfg = cloud_sync.load_cfg()
    assert cfg["url"] == "https://other.supabase.co"
    assert cfg["access_token"] == ""
    assert cfg["refresh_token"] == ""
    assert cfg["user_id"] == ""


def test_inflight_login_is_fenced_across_target_aba_change(env, monkeypatch):
    _ready()

    class Response:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {
                "access_token": "stale-access",
                "refresh_token": "stale-refresh",
                "user": {"id": "stale-user"},
            }

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            cloud_sync.configure("https://other.supabase.co", "other-anon")
            cloud_sync.configure("https://x.supabase.co", "anon")
            return Response()

    monkeypatch.setattr(cloud_sync, "_client", Client)
    result = cloud_sync.login("old@example.com", "pw")

    assert result["ok"] is False
    cfg = cloud_sync.load_cfg()
    assert cfg["url"] == "https://x.supabase.co"
    assert cfg["access_token"] == ""
    assert cfg["refresh_token"] == ""
    assert cfg["user_id"] == ""
    assert cfg["target_epoch"] == 2


@respx.mock
def test_login_then_available(env):
    cloud_sync.configure("https://x.supabase.co", "anon")
    respx.post(re.compile(r".*/auth/v1/token")).mock(
        return_value=httpx.Response(200, json={
            "access_token": "AT", "refresh_token": "RT", "user": {"id": "uid-9"},
        })
    )
    r = cloud_sync.login("a@b.com", "pw")
    assert r["ok"] and r["user_id"] == "uid-9"
    assert not cloud_sync.available()  # 换目标后需要用户显式重开同步
    cloud_sync.set_enabled(True)
    assert cloud_sync.available()


@respx.mock
def test_sync_push_and_pull_merge(env):
    _ready()
    respx.post(re.compile(r".*/rest/v1/.*")).mock(return_value=httpx.Response(201))

    def _pull(request):
        if request.url.path.endswith("/memory"):
            return httpx.Response(200, json=[{
                "content_hash": cloud_sync._hash("远端学到的记忆X"), "text": "远端学到的记忆X",
                "kind": "fact", "created_at": 2.0, "updated_at": 2.0, "deleted": False,
            }])
        return httpx.Response(200, json=[])

    respx.get(re.compile(r".*/rest/v1/.*")).mock(side_effect=_pull)
    res = cloud_sync.sync_all()
    assert res["ok"]
    assert res["pushed"]["memory"] == 1  # 本地 1 条被 push
    assert res["pulled"]["memory"] == 1  # 远端 1 条合并进来
    assert len(cloud_sync._local_rows_memory("owner")) == 2  # 本地现在两条


@respx.mock
def test_pull_dedup_no_duplicate(env):
    _ready()
    respx.post(re.compile(r".*/rest/v1/.*")).mock(return_value=httpx.Response(201))
    same = cloud_sync._hash("机主最爱数字7")  # 与本地已有那条同内容

    def _pull(request):
        if request.url.path.endswith("/memory"):
            return httpx.Response(200, json=[{
                "content_hash": same, "text": "机主最爱数字7", "kind": "fact",
                "created_at": 1.0, "updated_at": 3.0,
            }])
        return httpx.Response(200, json=[])

    respx.get(re.compile(r".*/rest/v1/.*")).mock(side_effect=_pull)
    res = cloud_sync.sync_all()
    assert res["pulled"]["memory"] == 0  # 已有同内容 → 不重复插
    assert len(cloud_sync._local_rows_memory("owner")) == 1


@respx.mock
def test_retarget_during_pull_cannot_merge_old_tenant_rows(env):
    _ready()
    respx.post(re.compile(r".*/rest/v1/.*")).mock(return_value=httpx.Response(201))

    def retarget_then_reply(request):
        if request.url.path.endswith("/memory"):
            cloud_sync.configure("https://other.supabase.co", "other-anon")
            return httpx.Response(
                200,
                json=[
                    {
                        "content_hash": cloud_sync._hash("old tenant secret"),
                        "text": "old tenant secret",
                        "kind": "fact",
                        "created_at": 2.0,
                        "updated_at": 2.0,
                    }
                ],
            )
        return httpx.Response(200, json=[])

    respx.get(re.compile(r".*/rest/v1/.*")).mock(side_effect=retarget_then_reply)
    result = cloud_sync.sync_all()

    assert result["ok"] is False
    assert "TargetChanged" in result["error"]
    assert len(cloud_sync._local_rows_memory("owner")) == 1
    cfg = cloud_sync.load_cfg()
    assert cfg["url"] == "https://other.supabase.co"
    assert cfg["last_sync"] == {}


def test_pull_does_not_hold_config_lock_during_large_local_scan(env, monkeypatch):
    _ready()
    cfg = cloud_sync.load_cfg()
    started = threading.Event()
    release = threading.Event()
    probe_done = threading.Event()
    errors: list[BaseException] = []
    existing = cloud_sync._hash("机主最爱数字7")

    def slow_read(_uid):
        started.set()
        assert release.wait(5)
        return [{"content_hash": existing}]

    class _Response:
        status_code = 200

        @staticmethod
        def json():
            return [{"content_hash": existing, "updated_at": 2.0, "deleted": True}]

    monkeypatch.setitem(cloud_sync.TABLES["memory"], "read", slow_read)
    monkeypatch.setattr(cloud_sync, "_rest", lambda *_args, **_kwargs: _Response())

    def pull_worker():
        try:
            cloud_sync._pull(cfg, "memory")
        except BaseException as exc:  # noqa: BLE001 - surfaced after cleanup
            errors.append(exc)

    worker = threading.Thread(target=pull_worker)
    worker.start()
    assert started.wait(2)

    probe = threading.Thread(target=lambda: (cloud_sync.status(), probe_done.set()))
    probe.start()
    try:
        assert probe_done.wait(1), "status was blocked by the local full-table scan"
    finally:
        release.set()
        worker.join(5)
        probe.join(5)
    assert not errors


def test_second_sync_returns_busy_instead_of_waiting(env):
    assert cloud_sync._sync_lock.acquire(blocking=False)
    try:
        assert cloud_sync.sync_all() == {
            "ok": False,
            "skipped": True,
            "reason": "已有云同步在运行",
        }
    finally:
        cloud_sync._sync_lock.release()


def test_skip_when_not_ready(env):
    res = cloud_sync.sync_all()
    assert res.get("skipped") is True  # 未配置/未登录 → 安全跳过


# ── 企业级知识库接轨：status 列同步 + 同步后 FTS 重建 ────────────────────────


def _seed_kb_doc(db_path, *, title, source="", status="superseded", created_at=1.0):
    """在带 status 列的本地库插一篇文档（先按迁移惯例补列，幂等）。"""
    k = sqlite3.connect(db_path)
    if "status" not in {r[1] for r in k.execute("PRAGMA table_info(kb_docs)")}:
        k.execute("ALTER TABLE kb_docs ADD COLUMN status TEXT DEFAULT 'active'")
    k.execute(
        "INSERT INTO kb_docs(user_id,title,source,chunks,created_at,status) "
        "VALUES('owner',?,?,0,?,?)",
        (title, source, created_at, status),
    )
    k.commit()
    k.close()


def _mock_pull(routes):
    """按 REST 路径尾分发 pull 响应的 respx side_effect。"""
    def _pull(request):
        for suffix, payload in routes.items():
            if request.url.path.endswith(suffix):
                return httpx.Response(200, json=payload)
        return httpx.Response(200, json=[])
    return _pull


@respx.mock
def test_kb_docs_status_sync_roundtrip(env):
    """status 随 kb_docs 同步：push 载荷带 superseded，pull 把远端 archived 写回本地。"""
    _ready()
    pushed = []
    respx.post(re.compile(r".*/rest/v1/.*")).mock(
        side_effect=lambda req: pushed.append(req) or httpx.Response(201)
    )
    remote_doc = {
        "content_hash": cloud_sync._hash("远端手册\n"), "title": "远端手册",
        "source": "", "status": "archived", "created_at": 2.0, "updated_at": 2.0,
    }
    respx.get(re.compile(r".*/rest/v1/.*")).mock(
        side_effect=_mock_pull({"/kb_docs": [remote_doc]})
    )
    _seed_kb_doc(env / "knowledge.db", title="本地旧版", status="superseded")

    res = cloud_sync.sync_all()

    assert res["ok"]
    kb_push = [r for r in pushed if r.url.path.endswith("/kb_docs")]
    assert kb_push, "本地 kb_docs 应被 push"
    payload = json.loads(kb_push[0].content)
    assert payload[0]["status"] == "superseded"  # 对端不再把 superseded 当 active
    local = {r["title"]: r["status"] for r in cloud_sync._local_rows_kb_docs("owner")}
    assert local["远端手册"] == "archived"  # 远端状态写回本地
    assert local["本地旧版"] == "superseded"


@respx.mock
def test_kb_docs_status_old_local_db_fallback(env):
    """老本地库无 status 列：读侧按 active 兜底，写侧按 ALTER 惯例补列，全程不炸。"""
    _ready()  # env fixture 建的 knowledge.db 无 status 列
    pushed = []
    respx.post(re.compile(r".*/rest/v1/.*")).mock(
        side_effect=lambda req: pushed.append(req) or httpx.Response(201)
    )
    remote_doc = {
        "content_hash": cloud_sync._hash("远端归档\n"), "title": "远端归档",
        "source": "", "status": "superseded", "created_at": 2.0, "updated_at": 2.0,
    }
    respx.get(re.compile(r".*/rest/v1/.*")).mock(
        side_effect=_mock_pull({"/kb_docs": [remote_doc]})
    )
    k = sqlite3.connect(env / "knowledge.db")  # 老库直插（无 status 列）
    k.execute(
        "INSERT INTO kb_docs(user_id,title,source,chunks,created_at) "
        "VALUES('owner','老库文档','',0,1.0)"
    )
    k.commit()
    k.close()

    res = cloud_sync.sync_all()

    assert res["ok"]
    kb_push = [r for r in pushed if r.url.path.endswith("/kb_docs")]
    assert json.loads(kb_push[0].content)[0]["status"] == "active"  # 缺列兜底 active
    k = sqlite3.connect(env / "knowledge.db")
    cols = {r[1] for r in k.execute("PRAGMA table_info(kb_docs)")}
    assert "status" in cols  # 插入侧自动补列
    got = k.execute("SELECT status FROM kb_docs WHERE title='远端归档'").fetchone()
    k.close()
    assert got == ("superseded",)


def _remote_kb_pair(doc_title="云端文档", chunk_text="海豚是哺乳动物，生活在海里，以鱼类为食。"):
    """一组互相对应的远端 kb_docs + kb_chunks 行（chunk 靠 doc_hash 找回文档）。"""
    doc_hash = cloud_sync._hash(f"{doc_title}\n")
    doc = {
        "content_hash": doc_hash, "title": doc_title, "source": "",
        "status": "active", "created_at": 2.0, "updated_at": 2.0,
    }
    chunk = {
        "content_hash": cloud_sync._hash(chunk_text), "doc_hash": doc_hash,
        "title": doc_title, "text": chunk_text, "updated_at": 2.0,
    }
    return {"/kb_docs": [doc], "/kb_chunks": [chunk]}


@respx.mock
def test_sync_rebuilds_kb_fts_after_chunk_merge(env):
    """云端 kb_chunks 合并进本地后，kb_fts 自动重建，行数与 kb_chunks 一致。"""
    _ready()
    respx.post(re.compile(r".*/rest/v1/.*")).mock(return_value=httpx.Response(201))
    respx.get(re.compile(r".*/rest/v1/.*")).mock(
        side_effect=_mock_pull(_remote_kb_pair())
    )

    res = cloud_sync.sync_all()

    assert res["ok"] and res["pulled"]["kb_chunks"] == 1
    k = sqlite3.connect(env / "knowledge.db")
    chunks = k.execute("SELECT COUNT(*) FROM kb_chunks").fetchone()[0]
    fts = k.execute("SELECT COUNT(*) FROM kb_fts").fetchone()[0]  # 表由重建钩子创建
    k.close()
    assert fts == chunks == 1


@respx.mock
def test_sync_survives_kb_fts_rebuild_failure(env, monkeypatch):
    """rebuild_fts 打爆也不影响同步结果（静默降级，对齐项目降级哲学）。"""
    from orchestrator.knowledge import KnowledgeBase

    _ready()
    respx.post(re.compile(r".*/rest/v1/.*")).mock(return_value=httpx.Response(201))
    respx.get(re.compile(r".*/rest/v1/.*")).mock(
        side_effect=_mock_pull(_remote_kb_pair())
    )

    def boom(_self):
        raise RuntimeError("fts exploded")

    monkeypatch.setattr(KnowledgeBase, "rebuild_fts", boom)

    res = cloud_sync.sync_all()

    assert res["ok"]
    assert res["pulled"]["kb_chunks"] == 1  # 分块照常落地
    k = sqlite3.connect(env / "knowledge.db")
    n = k.execute("SELECT COUNT(*) FROM kb_chunks").fetchone()[0]
    k.close()
    assert n == 1
