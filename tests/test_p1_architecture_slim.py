"""P1 后端架构瘦身与重构完整自动化测试（P1-1 / P1-2 / P1-3）。"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway.admission import _SQLiteDailyCounter
from gateway.app import app
from gateway.bridge_protocol import PersistentNonceReplayGuard
from gateway.channel_media_requests import DurableChannelMediaRequestStore
from gateway.config import get_settings
from gateway.light_media_idempotency import (
    LightMediaIdempotencyConflict,
    LightMediaIdempotencyStore,
    compute_request_hash,
)
from gateway.privacy_execution import PrivacyTombstoneStore
from gateway.privacy_rights import PrivacyRightsLedger
from gateway.provider_call_ledger import ProviderCallLedger
from gateway.usage import UsageLogger
from gateway.weixin_idempotency import WeixinIdempotencyStore
from orchestrator.agent import ConversationStore
from orchestrator.approval import ApprovalStore
from orchestrator.cases import CaseLibrary
from orchestrator.durable_event_log import DurableWorkflowEventLog
from orchestrator.knowledge import KnowledgeBase
from orchestrator.ledger import TaskLedger
from orchestrator.memory import MemoryStore
from orchestrator.scoreboard import Scoreboard
from orchestrator.undo_receipts import UndoReceiptStore
from storage.unified_db import (
    AUDIT_DB,
    CHANNELS_DB,
    CORE_DB,
    LOGICAL_DB_MAP,
    is_unified_db_path,
    migrate_legacy_dbs_if_needed,
    resolve_db_path,
)

AUTH = {"Authorization": "Bearer test-key"}


# ── 1. P1-1: LightMediaIdempotencyStore 防重、缓存命中、409 冲突检测 ────────


def test_light_media_idempotency_claim_cache_and_conflict(tmp_path: Path) -> None:
    db_path = tmp_path / CORE_DB
    store = LightMediaIdempotencyStore(db_path=db_path, stale_after_sec=60.0)
    try:
        req_hash_a = compute_request_hash({"prompt": "一只橘猫", "size": "1024x1024"})
        req_hash_b = compute_request_hash({"prompt": "一只蓝猫", "size": "1024x1024"})

        # 首次提交：成功占位
        first = store.claim("idem-001", "image", req_hash_a, now=1000.0)
        assert first.state == "claimed"
        assert first.result is None

        # 进行中重复提交：防重拦截
        dup = store.claim("idem-001", "image", req_hash_a, now=1010.0)
        assert dup.state == "in_progress"
        assert dup.status_code == 409

        # 同键不同参数：冲突返回 409 / 可选抛 LightMediaIdempotencyConflict
        conflict = store.claim("idem-001", "image", req_hash_b, now=1011.0)
        assert conflict.state == "conflict"
        assert conflict.status_code == 409
        with pytest.raises(LightMediaIdempotencyConflict) as exc_info:
            store.claim(
                "idem-001", "image", req_hash_b, now=1012.0, raise_on_conflict=True
            )
        assert exc_info.value.status_code == 409

        # 同键不同模态：同样判定冲突
        mod_conflict = store.claim("idem-001", "video", req_hash_a, now=1013.0)
        assert mod_conflict.state == "conflict"
        assert mod_conflict.status_code == 409

        # 完成后同键同参命中缓存结果
        payload = {"url": "https://cdn.example/cat.png", "model": "seedream"}
        assert store.complete("idem-001", payload, now=1020.0) is True
        cached = store.claim("idem-001", "image", req_hash_a, now=1025.0)
        assert cached.state == "cached"
        assert cached.status_code == 200
        assert cached.result == payload

        # 失败后允许同键同参安全重试
        second = store.claim("idem-002", "video", req_hash_b, now=2000.0)
        assert second.state == "claimed"
        assert store.fail("idem-002", "upstream_timeout", now=2005.0) is True
        retry = store.claim("idem-002", "video", req_hash_b, now=2010.0)
        assert retry.state == "claimed"

        # processing 超时后允许接管
        stale_takeover = store.claim("idem-002", "video", req_hash_b, now=2200.0)
        assert stale_takeover.state == "claimed"
    finally:
        store.close()


# ── 2. P1-2: 3 核心库路径路由、legacy 回退与旧单库幂等迁移备份 ──────────────


def test_unified_db_resolve_modes_and_explicit_bypass(tmp_path: Path) -> None:
    # unified 模式映射至 3 核心库
    assert resolve_db_path("conversations", data_dir=tmp_path, db_mode="unified") == tmp_path / CORE_DB
    assert resolve_db_path("memory", data_dir=tmp_path, db_mode="unified") == tmp_path / CORE_DB
    assert resolve_db_path("light_media_idempotency", data_dir=tmp_path, db_mode="unified") == tmp_path / CORE_DB
    assert resolve_db_path("weixin_agent_idempotency", data_dir=tmp_path, db_mode="unified") == tmp_path / CHANNELS_DB
    assert resolve_db_path("bridge_protocol_replay", data_dir=tmp_path, db_mode="unified") == tmp_path / CHANNELS_DB
    assert resolve_db_path("channel_media_requests", data_dir=tmp_path, db_mode="unified") == tmp_path / CHANNELS_DB
    assert resolve_db_path("usage", data_dir=tmp_path, db_mode="unified") == tmp_path / AUDIT_DB
    assert resolve_db_path("provider-calls", data_dir=tmp_path, db_mode="unified") == tmp_path / AUDIT_DB
    assert resolve_db_path("privacy_rights", data_dir=tmp_path, db_mode="unified") == tmp_path / AUDIT_DB

    # legacy 模式原样回退至旧单库
    for logical, (_unified_name, legacy_name) in LOGICAL_DB_MAP.items():
        assert resolve_db_path(logical, data_dir=tmp_path, db_mode="legacy") == tmp_path / legacy_name

    # explicit_path 与 :memory: 绝不劫持
    custom = tmp_path / "custom_test_only.db"
    assert resolve_db_path("conversations", data_dir=tmp_path, explicit_path=custom, db_mode="unified") == custom
    assert str(resolve_db_path("memory", data_dir=tmp_path, explicit_path=":memory:", db_mode="unified")) == ":memory:"
    assert is_unified_db_path(tmp_path / CORE_DB) is True
    assert is_unified_db_path(custom) is False
    assert is_unified_db_path(":memory:") is False


def test_migrate_legacy_dbs_to_three_unified_dbs_and_backup(tmp_path: Path) -> None:
    # 构造 3 组旧单库数据（分别应迁入 core / channels / audit）
    legacy_conv = ConversationStore(db_path=str(tmp_path / "conversations.db"))
    legacy_conv.append("sess:alpha", "user", "你好旧对话")
    legacy_conv.append("sess:alpha", "assistant", "收到旧回复")
    legacy_conv.close()

    legacy_mem = MemoryStore(str(tmp_path / "memory.db"))
    legacy_mem.add("owner", "偏好简体中文")
    legacy_mem.close()

    legacy_usage = UsageLogger(str(tmp_path / "usage.db"))
    legacy_usage.log(api_key="test-key", virtual_model="echo", provider="echo", total_tokens=42, status="ok")
    legacy_usage.close()

    legacy_wx = WeixinIdempotencyStore(tmp_path / "weixin_agent_idempotency.db")
    legacy_wx.close()

    # legacy 模式不执行迁移
    no_op = migrate_legacy_dbs_if_needed(tmp_path, db_mode="legacy")
    assert no_op["skipped"] is True
    assert (tmp_path / "memory.db").is_file()

    # unified 模式执行真实迁移
    report = migrate_legacy_dbs_if_needed(tmp_path, db_mode="unified")
    assert report["errors"] == []
    migrated_sources = {item["source"] for item in report["migrated"]}
    assert {"conversations.db", "memory.db", "usage.db", "weixin_agent_idempotency.db"} <= migrated_sources

    # 旧单库已全部安全移入 legacy_db_backup
    backup_dir = tmp_path / "legacy_db_backup"
    for fname in ("conversations.db", "memory.db", "usage.db", "weixin_agent_idempotency.db"):
        assert not (tmp_path / fname).exists()
        assert (backup_dir / fname).is_file()

    # 3 核心物理库存在且业务模块可直接无误打开、历史数据 0 丢失
    core_conv = ConversationStore(db_path=str(tmp_path / CORE_DB))
    try:
        hist = core_conv.get("sess:alpha")
        assert len(hist) == 2
        assert hist[0]["content"] == "你好旧对话"
        assert hist[1]["content"] == "收到旧回复"
    finally:
        core_conv.close()

    core_mem = MemoryStore(str(tmp_path / CORE_DB))
    try:
        mems = core_mem.all_for("owner")
        assert any("简体中文" in str(m.get("text", "")) for m in mems)
    finally:
        core_mem.close()

    audit_usage = UsageLogger(str(tmp_path / AUDIT_DB))
    try:
        row = audit_usage._conn.execute("SELECT COUNT(*), SUM(total_tokens) FROM usage").fetchone()
        assert row == (1, 42)
    finally:
        audit_usage.close()

    ch_wx = WeixinIdempotencyStore(tmp_path / CHANNELS_DB)
    ch_wx.close()

    # 二次调用幂等跳过
    second_report = migrate_legacy_dbs_if_needed(tmp_path, db_mode="unified")
    assert second_report["migrated"] == []
    assert second_report["errors"] == []


# ── 3. P1-2: 多模块共用 3 核心库零 Schema 冲突 + WAL 并发读写 ───────────────


def test_unified_core_channels_audit_multi_store_coexistence_and_concurrency(
    tmp_path: Path,
) -> None:
    core_path = tmp_path / CORE_DB
    channels_path = tmp_path / CHANNELS_DB
    audit_path = tmp_path / AUDIT_DB

    # 1) 核心库 nachuan_core.db：10 大模块共享同库无任何 schema/application_id 冲突
    conv = ConversationStore(db_path=str(core_path))
    mem = MemoryStore(str(core_path))
    cases = CaseLibrary(str(core_path))
    kb = KnowledgeBase(str(core_path))
    approvals = ApprovalStore(str(core_path))
    ledger = TaskLedger(str(core_path))
    undo = UndoReceiptStore(core_path, secrets.token_bytes(32))
    wf_events = DurableWorkflowEventLog(core_path)
    sb = Scoreboard(str(core_path))
    light_idem = LightMediaIdempotencyStore(db_path=core_path)
    try:
        conv.append("s1", "user", "hello")
        conv.append("s1", "assistant", "world")
        mem.add("owner", "喜欢简洁回答")
        cases.add("owner", "如何收敛 SQLite", "使用 3 核心库 WAL 模式", "gpt-5")
        kb.add_document(
            "owner",
            "架构文档",
            "纳川 P1 架构瘦身将原有的 32 个 SQLite 单库收敛至 3 个核心物理库并启用 WAL 并发。",
            "test",
        )
        aid = approvals.create("owner", "action", "测试审批", {"scope": "test"})
        assert aid > 0
        jid = ledger.create_job("测试目标", [{"title": "步1", "detail": "执行", "kind": "reason"}], user_id="owner")
        assert ledger.to_dict(jid) is not None
        sb.record("echo", "chat", win=True)
        assert light_idem.claim("k-core", "image", "a" * 64).state == "claimed"

        # WAL 并发读写验证
        errors: list[Exception] = []

        def worker(idx: int) -> None:
            try:
                conv.append(f"conc:{idx}", "user", f"msg-{idx}")
                mem.add("owner", f"fact-{idx}")
                sb.record("echo", f"kind-{idx}", win=(idx % 2 == 0))
                light_idem.claim(f"idem-{idx}", "image", f"{idx:064x}")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(worker, range(12)))
        assert errors == []

        # 检查核心库 WAL 模式生效
        with sqlite3.connect(str(core_path)) as chk:
            mode = str(chk.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            assert mode == "wal"
    finally:
        for res in (light_idem, sb, wf_events, undo, ledger, approvals, kb, cases, mem, conv):
            res.close()

    # 重开全部严格校验 store，验证持久化与子集闭集校验 100% 通过
    conv2 = ConversationStore(db_path=str(core_path))
    ledger2 = TaskLedger(str(core_path))
    wf2 = DurableWorkflowEventLog(core_path)
    try:
        assert conv2.get("s1")[0]["content"] == "hello"
        assert ledger2.to_dict(jid)["goal"] == "测试目标"
    finally:
        wf2.close()
        ledger2.close()
        conv2.close()

    # 2) 渠道库 nachuan_channels.db 共存
    wx_idem = WeixinIdempotencyStore(channels_path)
    replay_guard = PersistentNonceReplayGuard(channels_path)
    ch_media = DurableChannelMediaRequestStore(channels_path)
    try:
        now_ts = time.time()
        replay_guard.consume("weixin", "a" * 32, now=now_ts, valid_until=now_ts + 60.0)
    finally:
        ch_media.close()
        replay_guard.close()
        wx_idem.close()

    # 3) 审计库 nachuan_audit.db 共存
    usage = UsageLogger(str(audit_path))
    provider_ledger = ProviderCallLedger(audit_path, required=True)
    privacy_rights = PrivacyRightsLedger(audit_path)
    tombstones = PrivacyTombstoneStore(audit_path)
    admission = _SQLiteDailyCounter(audit_path)
    try:
        usage.log(api_key="k", virtual_model="echo", provider="echo", total_tokens=10, status="ok")
        assert admission.try_consume(bucket_hash="b" * 64, day="2026-11-25", limit=5) is True
        assert tombstones.count_tombstones() == 0
    finally:
        tombstones.close()
        provider_ledger.close()
        usage.close()


# ── 4. P1-3: /v1/conversations 真相源 CRUD + bulk_import 幂等导入与鉴权 ──────


def test_conversations_crud_bulk_import_and_auth(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("NACHUAN_DB_MODE", "unified")
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            # 未鉴权拦截
            assert client.get("/v1/conversations").status_code == 401
            assert client.post("/v1/conversations", json={"title": "unauth"}).status_code == 401

            # 创建会话
            created = client.post(
                "/v1/conversations",
                headers=AUTH,
                json={
                    "id": "conv-server-1",
                    "title": "架构讨论",
                    "kind": "chat",
                    "workdir": "D:/work",
                    "archived": False,
                    "createdAt": 1700000000.0,
                    "updatedAt": 1700000010.0,
                    "messages": [{"role": "user", "content": "第一句"}],
                },
            )
            assert created.status_code == 200
            body = created.json()
            assert body["id"] == "conv-server-1"
            assert body["title"] == "架构讨论"
            assert len(body["messages"]) == 1

            # 列表查询
            listed = client.get("/v1/conversations", headers=AUTH)
            assert listed.status_code == 200
            assert any(item["id"] == "conv-server-1" for item in listed.json()["conversations"])

            # 单条详情
            got = client.get("/v1/conversations/conv-server-1", headers=AUTH)
            assert got.status_code == 200
            assert got.json()["messages"][0]["content"] == "第一句"

            # PATCH 局部更新（标题 + 归档）
            patched = client.patch(
                "/v1/conversations/conv-server-1",
                headers=AUTH,
                json={"title": "架构讨论-已更新", "archived": True, "updatedAt": 1700000020.0},
            )
            assert patched.status_code == 200
            assert patched.json()["title"] == "架构讨论-已更新"
            assert patched.json()["archived"] is True

            # include_archived=false 过滤
            active_only = client.get(
                "/v1/conversations?include_archived=false", headers=AUTH
            )
            assert active_only.status_code == 200
            assert all(item["id"] != "conv-server-1" for item in active_only.json()["conversations"])

            # PUT 全量/富消息更新
            put_res = client.put(
                "/v1/conversations/conv-server-1/messages",
                headers=AUTH,
                json={
                    "messages": [
                        {"role": "user", "content": "第一句"},
                        {"role": "assistant", "content": "完整回复", "model": "echo"},
                    ],
                    "updatedAt": 1700000030.0,
                },
            )
            assert put_res.status_code == 200
            assert len(put_res.json()["messages"]) == 2

            # bulk_import 幂等导入：
            # - conv-server-1 传入更老的 updatedAt(1700000005.0) -> 必须跳过不覆盖
            # - conv-import-new 为新会话 -> 导入
            imp1 = client.post(
                "/v1/conversations/import",
                headers=AUTH,
                json={
                    "items": [
                        {
                            "id": "conv-server-1",
                            "title": "陈旧标题不应覆盖",
                            "updatedAt": 1700000005.0,
                            "messages": [{"role": "user", "content": "stale"}],
                        },
                        {
                            "id": "conv-import-new",
                            "title": "导入会话",
                            "createdAt": 1700000100.0,
                            "updatedAt": 1700000100.0,
                            "messages": [{"role": "user", "content": "from localStorage"}],
                        },
                    ]
                },
            )
            assert imp1.status_code == 200
            stats1 = imp1.json()
            assert stats1["imported"] == 1
            assert stats1["skipped"] == 1
            assert stats1["updated"] == 0

            # 确认 conv-server-1 未被旧版本覆盖
            after_imp1 = client.get("/v1/conversations/conv-server-1", headers=AUTH).json()
            assert after_imp1["title"] == "架构讨论-已更新"
            assert len(after_imp1["messages"]) == 2

            # 再次导入：新版本 updatedAt 更大 -> 正常更新；同版本 -> 幂等跳过
            imp2 = client.post(
                "/v1/conversations/import",
                headers=AUTH,
                json={
                    "items": [
                        {
                            "id": "conv-import-new",
                            "title": "导入会话-新版",
                            "updatedAt": 1700000200.0,
                            "messages": [{"role": "user", "content": "newer"}],
                        }
                    ]
                },
            )
            assert imp2.status_code == 200
            assert imp2.json()["updated"] == 1

            # 删除会话
            deleted = client.delete("/v1/conversations/conv-server-1", headers=AUTH)
            assert deleted.status_code == 200
            assert deleted.json()["ok"] is True
            assert client.get("/v1/conversations/conv-server-1", headers=AUTH).status_code == 404
            assert client.delete("/v1/conversations/conv-server-1", headers=AUTH).status_code == 404
    finally:
        get_settings.cache_clear()


# ── 5. P1-1 & P1-3: /health features 开关、重型冷启解耦与拆解后全部路由可用性 ──


def test_health_features_flags_and_split_routes_availability(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.delenv("NACHUAN_ENABLE_PAID_MEDIA_VAULT", raising=False)
    monkeypatch.delenv("NACHUAN_ENABLE_ENTERPRISE_RAG", raising=False)
    monkeypatch.delenv("NACHUAN_ENABLE_MEDIA_STUDIO", raising=False)
    monkeypatch.setenv("NACHUAN_DB_MODE", "unified")
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            health_resp = client.get("/health")
            assert health_resp.status_code == 200
            h = health_resp.json()
            assert h["status"] == "ok"
            assert h["features"] == {
                "paid_media_vault": False,
                "enterprise_rag": False,
                "media_studio": False,
                "db_mode": "unified",
                "offline_mode": False,
                "outbound_audit": True,
                "coding_control_plane": True,
            }
            # 默认关闭重型 paid-media 保险库，同时挂载轻量媒体幂等存储
            assert isinstance(app.state.light_media_idempotency, LightMediaIdempotencyStore)
            assert app.state.media_requests is None
            assert app.state.channel_media_requests is None
            assert h["checks"]["paid_media_authority"]["reason_code"] == "feature-flag-disabled"

            # 统一 3 库物理文件已按预期生成，不扩散出几十个旧单库文件
            assert (tmp_path / CORE_DB).is_file()
            assert (tmp_path / CHANNELS_DB).is_file()
            assert (tmp_path / AUDIT_DB).is_file()
            assert not (tmp_path / "memory.db").exists()
            assert not (tmp_path / "conversations.db").exists()
            assert not (tmp_path / "ledger.db").exists()

            # 校验拆分后的全部关键路由均可正常响应
            assert client.get("/v1/agent/memory?user_id=owner", headers=AUTH).status_code == 200
            assert client.get("/v1/agent/cases?user_id=owner", headers=AUTH).status_code == 200
            assert client.get("/v1/kb/docs?user_id=owner", headers=AUTH).status_code == 200
            assert client.get("/v1/sync/status", headers=AUTH).status_code == 200
            assert client.get("/v1/audio/model", headers=AUTH).status_code == 200
            assert client.get("/v1/mcp", headers=AUTH).status_code == 200
            assert client.get("/v1/mcp/presets", headers=AUTH).status_code == 200
            assert client.get("/v1/scoreboard", headers=AUTH).status_code == 200
            assert client.post("/v1/intent", headers=AUTH, json={"message": ""}).json() == {"intent": "chat"}
            # enable_media_studio=False 时 /v1/studio/* 返回 503 门禁
            assert client.post("/v1/studio/plan", headers=AUTH, json={"goal": "测试"}).status_code == 503

            # 核对路由表包含全部拆分路由路径（递归展开 APIRouter / _IncludedRouter 容器节点）
            def _collect_paths(routes) -> set[str]:
                found: set[str] = set()
                for route in routes:
                    path_val = getattr(route, "path", "")
                    if path_val:
                        found.add(path_val)
                    sub = getattr(route, "routes", None)
                    if sub:
                        found.update(_collect_paths(sub))
                    orig = getattr(route, "original_router", None)
                    if orig is not None and getattr(orig, "routes", None):
                        found.update(_collect_paths(orig.routes))
                return found

            registered_paths = _collect_paths(app.routes)
            for expected_path in (
                "/v1/conversations",
                "/v1/conversations/import",
                "/v1/conversations/{conv_id}",
                "/v1/conversations/{conv_id}/messages",
                "/v1/agent/memory",
                "/v1/agent/memory/clear",
                "/v1/agent/cases",
                "/v1/kb/docs",
                "/v1/kb/query",
                "/v1/intent",
                "/v1/web/read",
                "/v1/approvals",
                "/v1/approvals/{approval_id}/resolve",
                "/v1/sync/cases/push",
                "/v1/sync/cases/pull",
                "/v1/sync/status",
                "/v1/audio/transcriptions",
                "/v1/audio/model",
                "/v1/translate",
                "/v1/vision",
                "/v1/mcp",
                "/v1/mcp/presets",
                "/v1/orchestrate/panel",
                "/v1/orchestrate/debate",
                "/v1/orchestrate/decompose",
                "/v1/orchestrate/pipeline",
                "/v1/conv/{conv_id}/clear-summary",
                "/v1/route",
                "/v1/scoreboard",
                "/v1/workflows/daily-video/start",
                "/v1/studio/plan",
                "/v1/studio/execute",
                "/v1/lapian",
                "/v1/lapian/url",
            ):
                assert expected_path in registered_paths, f"missing route: {expected_path}"
    finally:
        get_settings.cache_clear()


def test_enable_paid_media_vault_feature_flag_restores_vault_startup(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    monkeypatch.setenv("NACHUAN_ENABLE_PAID_MEDIA_VAULT", "1")
    monkeypatch.setenv("NACHUAN_ENABLE_ENTERPRISE_RAG", "1")
    monkeypatch.setenv("NACHUAN_ENABLE_MEDIA_STUDIO", "1")
    monkeypatch.setenv("NACHUAN_DB_MODE", "unified")
    get_settings.cache_clear()
    try:
        with TestClient(app) as client:
            h = client.get("/health").json()
            assert h["features"] == {
                "paid_media_vault": True,
                "enterprise_rag": True,
                "media_studio": True,
                "db_mode": "unified",
                "offline_mode": False,
                "outbound_audit": True,
                "coding_control_plane": True,
            }
            assert app.state.media_requests is not None
            assert app.state.channel_media_requests is not None
            assert h["checks"]["paid_media_authority"]["mode"] == "development"
    finally:
        get_settings.cache_clear()
