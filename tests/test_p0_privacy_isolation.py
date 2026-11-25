"""P0 隐私安全与同源隔离专项测试（覆盖 P0-1 / P0-2 / P0-3）。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from gateway import app as app_mod
from gateway import failover, privacy, websearch
from gateway.schemas import ChatCompletionRequest, ChatMessage
import orchestrator.conv_summary as conv_summary
import orchestrator.history_compress as history_compress
import orchestrator.imagehost as imagehost
import orchestrator.memory as memory_mod


class _FakeProvider:
    def __init__(self, name: str, base_url: str = "", reply: str = "ok"):
        self.name = name
        self.base_url = base_url
        self.enabled = True
        self.reply = reply
        self.calls: list[tuple[str, list[dict]]] = []

    async def chat(self, req: ChatCompletionRequest, upstream_model: str):
        self.calls.append(
            (upstream_model, [m.model_dump(exclude_none=True) for m in req.messages])
        )
        return {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 0,
            "model": req.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": self.reply},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }


class _MultiVendorRouter:
    """包含多云供应商（openai / agnes / volcano）与本地后端（ollama）的模拟路由表。"""

    def __init__(self, routes: dict[str, SimpleNamespace]):
        self._routes = routes

    def resolve(self, model: str):
        return self._routes.get(model)

    def routes_info(self):
        out = []
        for mid, rt in self._routes.items():
            out.append(
                {
                    "model": mid,
                    "tier": rt.tier,
                    "provider": rt.provider.name,
                    "upstream_model": rt.upstream_model,
                    "independence_domain": rt.independence_domain,
                    "modality": "chat",
                    "rank": rt.rank,
                    "flagship": False,
                }
            )
        return out


def _make_multi_vendor_router():
    p_openai = _FakeProvider("openai", "https://api.openai.com/v1")
    p_agnes = _FakeProvider("agnes", "https://apihub.agnes-ai.com/v1")
    p_ollama = _FakeProvider("ollama", "http://127.0.0.1:11434/v1")
    routes = {
        "gpt-5.4": SimpleNamespace(
            virtual_model="gpt-5.4",
            provider=p_openai,
            upstream_model="gpt-5.4",
            tier="premium",
            rank=1,
            independence_domain="dom:openai",
        ),
        "agnes-flash": SimpleNamespace(
            virtual_model="agnes-flash",
            provider=p_agnes,
            upstream_model="agnes-2.0-flash",
            tier="free",
            rank=1,
            independence_domain="dom:agnes",
        ),
        "qwen-local": SimpleNamespace(
            virtual_model="qwen-local",
            provider=p_ollama,
            upstream_model="qwen2.5:14b",
            tier="free",
            rank=1,
            independence_domain="dom:local",
        ),
    }
    return _MultiVendorRouter(routes), p_openai, p_agnes, p_ollama


# ── P0-1：联网搜索强制门禁与默认关闭 ──────────────────────────────────────────


def test_chat_schema_defaults_and_strips_internal_privacy_fields():
    req = ChatCompletionRequest(
        model="gpt-5.4",
        messages=[ChatMessage(role="user", content="你好")],
    )
    assert req.web_search is False
    assert req.incognito is False
    assert req.privacy_mode is False
    assert req.inject_memory is None

    req_priv = ChatCompletionRequest(
        model="gpt-5.4",
        messages=[ChatMessage(role="user", content="机密")],
        web_search=True,
        incognito=True,
        privacy_mode=True,
        inject_memory=False,
    )
    upstream = req_priv.to_upstream_payload("gpt-5.4", stream=False)
    for k in ("web_search", "incognito", "privacy_mode", "inject_memory"):
        assert k not in upstream


async def test_websearch_blocks_loopback_router_model(monkeypatch):
    router, _p_openai, _p_agnes, _p_ollama = _make_multi_vendor_router()
    searched = {"n": 0}

    async def fake_search(q, n=5, **kw):  # noqa: ANN001, ARG001
        searched["n"] += 1
        return [{"title": "T", "url": "https://example.com", "snippet": "S"}]

    monkeypatch.setattr(websearch, "search", fake_search)

    # qwen-local 名称不带 local 前缀，但其 provider base_url 为 127.0.0.1，必须识别为本地模型并禁搜
    assert privacy.is_local_model(router, "qwen-local") is True
    req_local = ChatCompletionRequest(
        model="qwen-local",
        messages=[ChatMessage(role="user", content="帮我查今天新闻")],
        web_search=True,
    )
    assert await websearch.maybe_augment_request(req_local, router=router) == 0
    assert searched["n"] == 0

    # 云端模型显式开启 web_search=True 且非无痕时正常放行
    req_cloud = ChatCompletionRequest(
        model="gpt-5.4",
        messages=[ChatMessage(role="user", content="帮我查今天新闻")],
        web_search=True,
    )
    assert await websearch.maybe_augment_request(req_cloud, router=router) == 1
    assert searched["n"] == 1


# ── P0-2：记忆抽取 / 滚动摘要严格同源隔离与无痕模式 ──────────────────────────────


def test_select_same_origin_helper_model_never_crosses_vendor():
    router, _p_openai, _p_agnes, _p_ollama = _make_multi_vendor_router()

    # 云端对话：只能用同一模型，绝不偷传给 agnes-flash
    assert (
        privacy.select_same_origin_helper_model(router, source_model="gpt-5.4") == "gpt-5.4"
    )
    # 本地对话：只能用本地模型自身，绝不外发云端
    assert (
        privacy.select_same_origin_helper_model(router, source_model="qwen-local")
        == "qwen-local"
    )
    # 本地别名未注册时：宁可跳过（None）也绝不外发云端
    assert privacy.select_same_origin_helper_model(router, source_model="ollama/missing") is None
    # 多供应商且未指定 source_model 时：默认禁止跨商偷传，返回 None
    assert (
        privacy.select_same_origin_helper_model(
            router, source_model=None, allow_cross_vendor=False
        )
        is None
    )
    # 无痕模式：永远返回 None
    assert (
        privacy.select_same_origin_helper_model(
            router, source_model="gpt-5.4", incognito=True
        )
        is None
    )


def test_same_origin_only_fallback_blocks_cross_vendor_and_long_input_switch():
    huge_req = ChatCompletionRequest(
        model="glm",
        messages=[ChatMessage(role="user", content="字" * (failover.LONG_INPUT_CHARS + 10))],
    )
    # 常规模式下 glm 有跨商 fallback 链且超长文本会优先 GPT_BACKUP
    normal_chain = failover.fallback_chain("glm", huge_req)
    assert "agnes-flash" in normal_chain or failover.GPT_BACKUP in normal_chain

    # 同源隔离上下文内强制只保留 ["glm"]，彻底切断跨供应商 fallback
    with failover.same_origin_only_fallback():
        assert failover.fallback_chain("glm", huge_req) == ["glm"]


async def test_conv_summary_and_history_compress_stay_same_origin_and_respect_incognito(
    monkeypatch, tmp_path
):
    router, _p_openai, _p_agnes, _p_ollama = _make_multi_vendor_router()
    db = tmp_path / "conv_summary.db"
    monkeypatch.setattr(conv_summary, "_db_path", lambda: str(db))
    conv_summary.reset()

    called_models: list[str] = []

    async def fake_chat(r, req):  # noqa: ANN001
        called_models.append(req.model)
        return ({"choices": [{"message": {"content": "同源摘要"}}]}, req.model, None)

    monkeypatch.setattr(failover, "chat_with_fallback", fake_chat)
    long_msgs = [
        {"role": "user" if i % 2 == 0 else "assistant", "content": f"m{i}" + "文" * 300}
        for i in range(40)
    ]

    # 1) 无痕模式：完全跳过滚动摘要，不调任何模型、不落库
    out_inc = await conv_summary.rolling_compress(
        router, "conv-inc", long_msgs, source_model="gpt-5.4", incognito=True
    )
    assert out_inc == long_msgs
    assert called_models == []
    assert conv_summary._get_store().get("conv-inc") == ("", 0)

    # 2) 使用 gpt-5.4 对话：滚动摘要必须走 gpt-5.4，绝不发给 agnes-flash
    out_gpt = await conv_summary.rolling_compress(
        router, "conv-gpt", long_msgs, source_model="gpt-5.4"
    )
    assert out_gpt and "同源摘要" in out_gpt[0]["content"]
    assert called_models == ["gpt-5.4"]

    # 3) 使用本地模型 qwen-local 对话：无状态压缩必须走 qwen-local，绝不发给云端
    called_models.clear()
    out_local = await history_compress.compress_history(
        router, long_msgs, source_model="qwen-local"
    )
    assert out_local and "同源摘要" in out_local[0]["content"]
    assert called_models == ["qwen-local"]

    # 4) 多供应商但未传 source_model：拒绝跨商偷传，原样返回
    called_models.clear()
    out_unknown = await history_compress.compress_history(router, long_msgs)
    assert out_unknown == long_msgs
    assert called_models == []
    conv_summary.reset()


async def test_memory_extract_and_grow_memory_same_origin_and_incognito(
    monkeypatch, tmp_path
):
    router, _p_openai, _p_agnes, _p_ollama = _make_multi_vendor_router()
    store = memory_mod.MemoryStore(str(tmp_path / "mem.db"))
    used_models: list[str] = []

    async def fake_chat(r, req):  # noqa: ANN001
        used_models.append(req.model)
        return (
            {
                "choices": [
                    {
                        "message": {
                            "content": '[{"fact":"用户住杭州","evidence":"我住在杭州"}]'
                        }
                    }
                ]
            },
            req.model,
            None,
        )

    monkeypatch.setattr(memory_mod, "chat_with_fallback", fake_chat)

    # 无痕模式直接跳过
    assert (
        await memory_mod.extract_and_store(
            router,
            store,
            user_id="owner",
            user_msg="我住在杭州，喜欢喝茶",
            assistant_msg="记住了",
            model="gpt-5.4",
            source_model="gpt-5.4",
            incognito=True,
        )
        == []
    )
    assert used_models == []

    # 跨供应商防御：source_model=gpt-5.4 但误传 model=agnes-flash，直接拦截
    assert (
        await memory_mod.extract_and_store(
            router,
            store,
            user_id="owner",
            user_msg="我住在杭州，喜欢喝茶",
            assistant_msg="记住了",
            model="agnes-flash",
            source_model="gpt-5.4",
            same_origin_only=True,
        )
        == []
    )
    assert used_models == []

    # _grow_memory：使用 gpt-5.4 时只调度 gpt-5.4，绝不偷传 agnes-flash
    monkeypatch.setattr(app_mod.app.state, "memory", store, raising=False)
    monkeypatch.setattr(app_mod.app.state, "background_tasks", set(), raising=False)
    task = app_mod._grow_memory(
        router, "我住在杭州，喜欢喝茶", "好的，明白了", source_model="gpt-5.4"
    )
    assert task is not None
    await task
    assert used_models == ["gpt-5.4"]
    assert any("杭州" in m["text"] for m in store.all_for("owner"))

    # _grow_memory 在无痕模式下返回 None，零抽取
    used_models.clear()
    assert (
        app_mod._grow_memory(
            router,
            "我住在上海",
            "好的",
            source_model="gpt-5.4",
            incognito=True,
        )
        is None
    )
    assert used_models == []
    store.close()


def test_chat_completions_incognito_blocks_memory_injection_extraction_and_websearch(
    monkeypatch, tmp_path
):
    router, p_openai, p_agnes, _p_ollama = _make_multi_vendor_router()
    store = memory_mod.MemoryStore(str(tmp_path / "mem_http.db"))
    store.add("owner", "用户秘密偏好是黑咖啡", source="我喜欢黑咖啡")

    monkeypatch.setenv("GATEWAY_API_KEYS", "test-p0-key")
    monkeypatch.setenv("USAGE_DB_PATH", str(tmp_path / "usage.db"))
    app_mod.get_settings.cache_clear()

    searched = {"n": 0}
    grow_calls: list[dict] = []

    async def fake_search(q, n=5, **kw):  # noqa: ANN001, ARG001
        searched["n"] += 1
        return [{"title": "T", "url": "https://example.com", "snippet": "S"}]

    def spy_grow(r, u, a, *, source_model=None, incognito=False):
        grow_calls.append({"source_model": source_model, "incognito": incognito})
        return None

    monkeypatch.setattr(websearch, "search", fake_search)
    monkeypatch.setattr(app_mod, "_grow_memory", spy_grow)

    with TestClient(app_mod.app) as client:
        monkeypatch.setattr(app_mod.app.state, "router", router)
        monkeypatch.setattr(app_mod.app.state, "memory", store)
        headers = {"Authorization": "Bearer test-p0-key"}

        # 1) 无痕模式 + 显式 web_search=True：
        #    必须 0 记忆注入、0 联网搜索、0 记忆抽取
        p_openai.calls.clear()
        resp_inc = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "帮我推荐咖啡"}],
                "web_search": True,
                "incognito": True,
            },
        )
        assert resp_inc.status_code == 200
        assert searched["n"] == 0
        assert grow_calls == []
        assert len(p_openai.calls) == 1
        sent_msgs = p_openai.calls[0][1]
        assert not any("黑咖啡" in str(m.get("content", "")) for m in sent_msgs)

        # 2) 普通云端模式但未显式开启 web_search（默认 False）：
        #    0 联网搜索、正常记忆注入、后台成长严格传 source_model="gpt-5.4"
        p_openai.calls.clear()
        resp_norm = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "帮我推荐咖啡"}],
            },
        )
        assert resp_norm.status_code == 200
        assert searched["n"] == 0
        assert len(p_openai.calls) == 1
        sent_norm = p_openai.calls[0][1]
        assert any("黑咖啡" in str(m.get("content", "")) for m in sent_norm)
        assert grow_calls == [{"source_model": "gpt-5.4", "incognito": False}]
        assert p_agnes.calls == []

        # 3) 显式 inject_memory=False：不注入记忆
        p_openai.calls.clear()
        resp_nomem = client.post(
            "/v1/chat/completions",
            headers=headers,
            json={
                "model": "gpt-5.4",
                "messages": [{"role": "user", "content": "帮我推荐咖啡"}],
                "inject_memory": False,
            },
        )
        assert resp_nomem.status_code == 200
        sent_nomem = p_openai.calls[0][1]
        assert not any("黑咖啡" in str(m.get("content", "")) for m in sent_nomem)

    app_mod.get_settings.cache_clear()
    store.close()


# ── P0-3：Supabase 私有桶 + 短期 Signed URL + 离线门禁 + 清理告警回执 ──────────


class _MockHttpResponse:
    def __init__(self, status_code: int, json_body: dict | None = None):
        self.status_code = status_code
        self._json = json_body
        self.content = b"{}" if json_body is not None else b""

    def json(self):
        return self._json


def test_imagehost_uses_private_signed_url_and_blocks_offline_incognito(
    monkeypatch, caplog
):
    from orchestrator import cloud_sync

    monkeypatch.setattr(
        cloud_sync,
        "load_cfg",
        lambda: {
            "url": "https://demo.supabase.co",
            "anon_key": "anon-key",
            "access_token": "secret-jwt",
        },
    )

    requests_seen: list[tuple[str, str, dict | None]] = []

    class _FakeClient:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):  # noqa: ANN002
            return False

        def post(self, url, headers=None, content=None, json=None):  # noqa: ANN001
            requests_seen.append(("POST", url, json))
            if "/object/sign/" in url:
                rel_path = url.split("/object/sign/", 1)[1]
                return _MockHttpResponse(
                    200,
                    {"signedURL": f"/object/sign/{rel_path}?token=signed-secret-tok"},
                )
            return _MockHttpResponse(200, {"Key": "ok"})

        def delete(self, url, headers=None):  # noqa: ANN001
            requests_seen.append(("DELETE", url, None))
            return _MockHttpResponse(200)

    monkeypatch.setattr(httpx, "Client", _FakeClient)

    # 1) 无痕 / 离线模式绝不发出任何外网请求
    assert imagehost.upload_image(b"\x89PNG\r\n\x1a\n123", incognito=True) == ""
    assert imagehost.upload_image(b"\x89PNG\r\n\x1a\n123", offline_only=True) == ""
    assert requests_seen == []

    # 2) 纯本地 router 同样禁止上传图床
    local_only_router = _MultiVendorRouter(
        {
            "local-qwen": SimpleNamespace(
                virtual_model="local-qwen",
                provider=_FakeProvider("ollama", "http://127.0.0.1:11434/v1"),
                upstream_model="qwen2.5",
                tier="free",
                rank=1,
                independence_domain="dom:local",
            )
        }
    )
    assert imagehost.available(router=local_only_router) is False
    assert imagehost.upload_image(b"\x89PNG\r\n\x1a\n123", router=local_only_router) == ""
    assert requests_seen == []

    # 3) 正常上传：返回短期 Signed URL（默认 600s），绝不是 /object/public/
    signed_url = imagehost.upload_image(b"\x89PNG\r\n\x1a\n123")
    assert signed_url.startswith(
        "https://demo.supabase.co/storage/v1/object/sign/studio-frames/"
    )
    assert "/object/public/" not in signed_url
    assert "?token=signed-secret-tok" in signed_url
    assert requests_seen[1][2] == {"expiresIn": 600}

    # 4) delete_by_url 正确解析 Signed URL 并返回成功回执（请求路径不含 ?token=...）
    receipt = imagehost.delete_by_url(signed_url)
    assert receipt["ok"] is True
    assert receipt["status_code"] == 200
    assert receipt["attempts"] == 1
    assert "?" not in requests_seen[-1][1]


def test_imagehost_delete_failure_retries_logs_warning_without_token_and_returns_receipt(
    monkeypatch, caplog
):
    from orchestrator import cloud_sync

    monkeypatch.setattr(
        cloud_sync,
        "load_cfg",
        lambda: {
            "url": "https://demo.supabase.co",
            "anon_key": "anon-key",
            "access_token": "secret-jwt",
        },
    )
    attempts = {"n": 0}

    class _FailingDeleteClient:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):  # noqa: ANN002
            return False

        def delete(self, url, headers=None):  # noqa: ANN001
            attempts["n"] += 1
            return _MockHttpResponse(500)

    monkeypatch.setattr(httpx, "Client", _FailingDeleteClient)
    signed = "https://demo.supabase.co/storage/v1/object/sign/studio-frames/abc.png?token=SUPER_SECRET_SIG"
    with caplog.at_level("WARNING", logger="orchestrator.imagehost"):
        receipt = imagehost.delete_by_url(signed, retries=1)

    assert receipt["ok"] is False
    assert receipt["status_code"] == 500
    assert receipt["attempts"] == 2
    assert attempts["n"] == 2
    assert "cleanup exhausted retries" in caplog.text
    assert "SUPER_SECRET_SIG" not in caplog.text
