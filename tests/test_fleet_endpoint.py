"""F5 虚拟模型号（纳川舰队）：/v1/models 露出 + /v1/chat/completions 分流 + /v1/agent/run 映射。

Fugu「one model to command them all」的产品形态：nachuan / nachuan-ultra 对外就是两个模型 id，
对内分别走 TRINITY 快档 / Conductor 深档编排。这里全部 mock 编排函数，只测接线正确。
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app

AUTH = {"Authorization": "Bearer test-key"}


class _Router:
    """最小假路由器：routes_info/list_models/resolve 够端点用。"""

    def __init__(self, models: tuple[str, ...] = ("glm",)):
        self._models = list(models)

    def routes_info(self) -> list[dict[str, Any]]:
        return [
            {"model": m, "tier": "cheap", "provider": "p", "rank": 1, "flagship": False}
            for m in self._models
        ]

    def list_models(self) -> list[dict[str, Any]]:
        return [
            {"id": m, "object": "model", "owned_by": "p", "tier": "cheap",
             "modality": "chat", "description": ""}
            for m in self._models
        ]

    def resolve(self, m: str):  # noqa: ANN001
        return None

    async def aclose(self) -> None:  # lifespan 关闭时会调真 Router 的 aclose
        return None


def _fake_result(reply: str = "舰队干完了", model: str = "glm") -> dict[str, Any]:
    receipt = {
        "route_receipt_version": 1,
        "model": model,
        "requested_model": model,
        "actual_model": model,
        "provider": "p",
        "upstream_model": f"{model}-upstream",
        "reported_model": f"{model}-upstream",
        "observed_model": f"{model}-upstream",
        "model_family": "test-family",
        "model_identity_error": None,
        "independence_domain": "sha256:" + "a" * 64,
        "tier": "cheap",
        "flagship": False,
    }
    return {
        "reply": reply, "steps": 3, "model": model,
        "actual_model": model, "actual_models": [model],
        "author_receipts": [receipt],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        "tool_log": [], "file_changes": [], "media": [],
        "mode": "trinity", "reviewed": False, "verified": False,
        "machine_verified": False, "outcome": "completed_unverified",
        "blocked": False, "rounds": 1,
        "_route": {**receipt, "final_model": model, "final_route_receipt": receipt},
    }


def test_models_expose_fleet_only_when_real_models_exist():
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        ids = [m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]]
        assert "nachuan" in ids and "nachuan-ultra" in ids
        c.app.state.router = _Router(())  # 空舰队（无模型）→ 不露出虚拟号
        ids = [m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]]
        assert "nachuan" not in ids and "nachuan-ultra" not in ids
        c.app.state.router = _Router(("echo",))  # 只剩 echo 兜底 → 也不露出（互审补边界）
        ids = [m["id"] for m in c.get("/v1/models", headers=AUTH).json()["data"]]
        assert "nachuan" not in ids and "nachuan-ultra" not in ids


def test_chat_completions_routes_nachuan_to_orchestrated(monkeypatch):
    calls: dict[str, Any] = {}

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        calls["task"] = task
        calls["allow"] = kw.get("allow")
        calls["workdir"] = kw.get("workdir")
        return _fake_result("你好，我是舰队")

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan",
            "messages": [{"role": "user", "content": "帮我调研个事"}],
        })
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "nachuan"
    assert body["choices"][0]["message"]["content"] == "你好，我是舰队"
    assert body["_fleet"]["final_model"] == "glm"
    assert calls["task"] == "帮我调研个事"
    # 标准 chat.completions 只能做 advisory；显式空能力集代表零工具。
    assert calls["allow"] == set()
    # 标准聊天没有宿主文件能力；其元数据工作区也必须固定在专用受管根。
    from orchestrator.workspace_guard import workspace_root
    assert calls["workdir"] == str(workspace_root())


def test_fleet_usage_and_final_model_use_actual_receipt_never_requested_alias(
    monkeypatch,
):
    usage_rows: list[dict[str, Any]] = []

    async def fake_orch(router, task, **kwargs):  # noqa: ANN001
        result = _fake_result("fallback answer", "glm")
        receipt = result["_route"]["final_route_receipt"]
        receipt["requested_model"] = "requested-cheap"
        return result

    async def fake_log(logger, **values):  # noqa: ANN001
        usage_rows.append(values)
        return True

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    monkeypatch.setattr(appmod, "_log_usage_best_effort", fake_log)
    with TestClient(app) as client:
        client.app.state.router = _Router(("glm",))
        response = client.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "nachuan",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    assert response.json()["_fleet"]["final_model"] == "glm"
    assert usage_rows[-1]["virtual_model"] == "nachuan"
    assert usage_rows[-1]["provider"] == "p"
    assert usage_rows[-1]["upstream_model"] == "glm-upstream"
    assert usage_rows[-1]["upstream_model"] != "nachuan"


def test_fleet_unserved_result_never_falls_back_to_virtual_request(monkeypatch):
    usage_rows: list[dict[str, Any]] = []

    async def fake_orch(router, task, **kwargs):  # noqa: ANN001
        receipt = {
            "route_receipt_version": 1,
            "model": None,
            "requested_model": "requested-cheap",
            "actual_model": None,
            "provider": None,
            "upstream_model": None,
            "model_identity_error": "no_final_model_call",
        }
        return {
            "reply": "deterministic fallback",
            "model": "requested-cheap",
            "actual_model": None,
            "actual_models": [],
            "author_receipts": [],
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
            "_route": {
                **receipt,
                "final_model": None,
                "final_route_receipt": receipt,
            },
        }

    async def fake_log(logger, **values):  # noqa: ANN001
        usage_rows.append(values)
        return True

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    monkeypatch.setattr(appmod, "_log_usage_best_effort", fake_log)
    with TestClient(app) as client:
        client.app.state.router = _Router(("glm",))
        response = client.post(
            "/v1/chat/completions",
            headers=AUTH,
            json={
                "model": "nachuan",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    assert response.json()["_fleet"]["final_model"] is None
    assert usage_rows[-1]["upstream_model"] == ""
    assert usage_rows[-1]["upstream_model"] != "nachuan"
    assert usage_rows[-1]["provider"] == "fleet-unserved"


def test_chat_completions_fleet_preserves_current_multimodal_image(monkeypatch):
    """当前 user 的图不能在拆 task/history 时丢掉，否则 worker 只能编造 image URL。"""
    seen: dict[str, Any] = {}

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        seen["task"] = task
        seen["history"] = kw.get("history") or []
        return _fake_result()

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    image = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "引用这张图，做个视频"},
                {"type": "image_url", "image_url": {"url": image}},
            ]}],
        })
    assert r.status_code == 200
    assert seen["task"] == "引用这张图，做个视频"
    assert any(
        isinstance(m.get("content"), list)
        and any(
            isinstance(part, dict)
            and part.get("type") == "image_url"
            and (part.get("image_url") or {}).get("url") == image
            for part in m["content"]
        )
        for m in seen["history"]
    )


def test_chat_completions_routes_ultra_to_conductor(monkeypatch):
    hit = {"conductor": 0, "orch": 0}

    async def fake_cond(router, task, **kw):  # noqa: ANN001
        hit["conductor"] += 1
        return {**_fake_result("深编排结果"), "mode": "conductor"}

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        hit["orch"] += 1
        return _fake_result()

    monkeypatch.setattr(appmod, "run_conductor_agent", fake_cond)
    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan-ultra",
            "messages": [{"role": "user", "content": "复杂任务"}],
        })
    assert r.status_code == 200
    assert hit == {"conductor": 1, "orch": 0}
    assert r.json()["_fleet"]["mode"] == "conductor"


def test_chat_completions_fleet_stream_emits_progress_then_answer(monkeypatch):
    async def fake_orch(router, task, **kw):  # noqa: ANN001
        ev = kw.get("on_event")
        if ev:
            await ev({"type": "route", "model": "glm", "complex": True})
            await ev({"type": "cast", "turn": 1, "role": "worker", "model": "glm"})
        return _fake_result("最终答案在此")

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan", "stream": True,
            "messages": [{"role": "user", "content": "干活"}],
        })
    assert r.status_code == 200
    text = r.text
    assert "路由" in text and "点将#1" in text  # 进度行
    assert "最终答案在此" in text  # 正文
    assert "data: [DONE]" in text  # OpenAI SSE 收尾


def test_fleet_surfaces_pending_videos_nonstream(monkeypatch):
    """#6：编排产出带 pending_videos → 非流式舰队响应把它透出为 _pending_videos（前端据此轮询）。"""
    pv = [{"task_id": "vid-9", "model": "sora-cn", "prompt": "猫跳舞"}]

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        return {**_fake_result("视频在后台生成中"), "pending_videos": pv}

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan",
            "messages": [{"role": "user", "content": "给我做个猫跳舞的视频"}],
        })
    assert r.status_code == 200
    assert r.json()["_pending_videos"] == pv


def test_fleet_surfaces_pending_videos_stream(monkeypatch):
    """#6：流式舰队在末尾以结构化 chunk 发 _pending_videos（前端轮询到成片自动贴回）。"""
    import json as _json

    pv = [{"task_id": "vid-10", "model": "sora-cn", "prompt": "海边日落"}]

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        return {**_fake_result("视频后台生成中"), "pending_videos": pv}

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan", "stream": True,
            "messages": [{"role": "user", "content": "做个海边日落的视频"}],
        })
    assert r.status_code == 200
    # 从 SSE data 行里找到带 _pending_videos 的那个 chunk
    found = None
    for line in r.text.splitlines():
        s = line.strip()
        if s.startswith("data:") and "_pending_videos" in s:
            found = _json.loads(s[5:].strip())
            break
    assert found is not None and found["_pending_videos"] == pv


def test_agent_run_maps_fleet_ids(monkeypatch):
    seen: dict[str, Any] = {}

    async def fake_cond(router, task, **kw):  # noqa: ANN001
        seen["deep"] = True
        return {**_fake_result("动手完成"), "mode": "conductor"}

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        seen["model"] = kw.get("model")
        return _fake_result("动手完成")

    monkeypatch.setattr(appmod, "run_conductor_agent", fake_cond)
    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        # ultra 号 → Conductor
        r = c.post("/v1/agent/run", headers=AUTH, json={"task": "跑活", "model": "nachuan-ultra"})
        assert r.status_code == 200 and seen.get("deep") is True
        seen.clear()  # 互审(Kimi)：两次请求间清痕迹，防交叉污染掩盖路由错误
        # 普通舰队号 → 自动路由（model=None，不是把 'nachuan' 当真模型传下去）
        r = c.post("/v1/agent/run", headers=AUTH, json={"task": "跑活", "model": "nachuan"})
        assert r.status_code == 200 and seen.get("model") is None
        assert seen.get("deep") is None  # 没误入 Conductor 分支


def test_scoreboard_endpoint_returns_rows(monkeypatch):
    """只读战绩看板：/v1/scoreboard 把 scoreboard.dump_all() 原样包成 {"rows": [...]} 返回。"""
    rows = [
        {"model": "glm", "task_kind": "code", "wins": 8, "losses": 2,
         "win_rate": 0.8, "last_at": "2026-07-07T10:00:00"},
        {"model": "kimi", "task_kind": "reason", "wins": 0, "losses": 3,
         "win_rate": 0.0, "last_at": "2026-07-06T09:00:00"},
    ]
    monkeypatch.setattr(appmod.scoreboard, "dump_all", lambda: rows)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.get("/v1/scoreboard", headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"rows": rows}


def test_scoreboard_endpoint_requires_key():
    """无 API key → 拒绝（与其它 /v1 端点一致的鉴权）。"""
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        assert c.get("/v1/scoreboard").status_code in (401, 403)


def test_scoreboard_endpoint_empty_when_no_data(monkeypatch):
    """记分牌空/降级 → 空表（dump_all 内部已吞异常返回 []）；端点给 {"rows": []} 不 500。"""
    monkeypatch.setattr(appmod.scoreboard, "dump_all", lambda: [])
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.get("/v1/scoreboard", headers=AUTH)
    assert r.status_code == 200 and r.json() == {"rows": []}


def test_fleet_chat_failure_paths(monkeypatch):
    """互审(GLM/MiniMax)：编排炸了——非流式要 502 不裸 500；流式要吐失败行不挂死。"""

    async def boom(router, task, **kw):  # noqa: ANN001
        raise RuntimeError("池子全灭")

    monkeypatch.setattr(appmod, "run_orchestrated_agent", boom)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan", "messages": [{"role": "user", "content": "干活"}],
        })
        assert r.status_code == 502 and "舰队编排失败" in r.json()["detail"]
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan", "stream": True,
            "messages": [{"role": "user", "content": "干活"}],
        })
        assert r.status_code == 200  # 流式已开头，失败以内容行呈现
        assert "舰队编排失败" in r.text and "data: [DONE]" in r.text


# ════════════ 批11：workdir 解放 + 记忆进编排（fleet 聊天面）════════════

def test_fleet_ignores_named_workdir_from_untrusted_message(monkeypatch, tmp_path):
    """标准聊天不得因消息里点名任意绝对路径而切换工作区。"""
    seen: dict[str, Any] = {}

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        seen["workdir"] = kw.get("workdir")
        return _fake_result()

    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan",
            "messages": [{"role": "user", "content": f"整理这个文件夹 {tmp_path}"}],
        })
    assert r.status_code == 200
    # 即使路径真实存在且位于临时根下，聊天内容也不能改变固定受管工作区。
    from orchestrator.workspace_guard import workspace_root
    assert seen["workdir"] == str(workspace_root())


def test_fleet_injects_memory_into_orchestration(monkeypatch):
    """记忆进编排：memory_system_note 有内容时，作为一条 system 消息进 history 头部。"""
    seen: dict[str, Any] = {}

    def fake_note(memory, uid, task):  # noqa: ANN001
        seen["note_called"] = (uid, task)
        return ("【记忆】机主偏好美式咖啡", [{"id": 1}])

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        seen["history"] = kw.get("history")
        return _fake_result()

    monkeypatch.setattr(appmod, "memory_system_note", fake_note)
    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan",
            "messages": [{"role": "user", "content": "给我推荐杯咖啡"}],
        })
    assert r.status_code == 200
    assert seen["note_called"][1] == "给我推荐杯咖啡"  # 用当前 task 检索记忆
    blob = str(seen["history"])
    assert "机主偏好美式咖啡" in blob  # 记忆作为 system 进了 history


def test_fleet_grows_memory_after_orchestration(monkeypatch):
    """成长回写：编排结束后用 (task, reply) 调 _grow_memory（吞异常、后台）。"""
    seen: dict[str, Any] = {}

    def fake_grow(router, user_msg, assistant_msg):  # noqa: ANN001
        seen["grow"] = (user_msg, assistant_msg)

    async def fake_orch(router, task, **kw):  # noqa: ANN001
        return _fake_result("这是舰队的回复")

    monkeypatch.setattr(appmod, "_grow_memory", fake_grow)
    monkeypatch.setattr(appmod, "run_orchestrated_agent", fake_orch)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        r = c.post("/v1/chat/completions", headers=AUTH, json={
            "model": "nachuan",
            "messages": [{"role": "user", "content": "聊两句"}],
        })
    assert r.status_code == 200
    assert seen["grow"] == ("聊两句", "这是舰队的回复")


# ════════════ 批11：_resolve_workdir helper 单测 ════════════

def test_resolve_workdir_hits_named_existing_path(tmp_path):
    """消息点名真实存在的绝对路径 → 返回它（文件则返回父目录，由 _extract_workdir 负责）。"""
    got = appmod._resolve_workdir(f"帮我整理 {tmp_path} 里的文件", fallback="/FB")
    assert got == str(tmp_path)


def test_resolve_workdir_ignores_nonexistent_path():
    """点名的路径不存在 → 忽略，回退 fallback（不误把不存在的路径当工作区）。"""
    got = appmod._resolve_workdir(r"去 D:\这个目录多半不存在_zzz9\x 干活", fallback="/FB")
    assert got == "/FB"


def test_resolve_workdir_no_path_falls_back():
    """消息里没有绝对路径 → 直接回退 fallback。"""
    got = appmod._resolve_workdir("随便聊聊今天天气", fallback="/FB")
    assert got == "/FB"


def test_resolve_workdir_file_returns_parent(tmp_path):
    """点名的是文件 → 返回其父目录（_extract_workdir 行为）。"""
    f = tmp_path / "note.txt"
    f.write_text("x", encoding="utf-8")
    got = appmod._resolve_workdir(f"看看 {f}", fallback="/FB")
    assert got == str(tmp_path)


def test_exec_gate_is_closed_before_capability_for_every_mode(monkeypatch):
    """No plan/full/capability value can reconnect the retired host executor."""
    calls: list[str] = []

    async def fake_exec(_router, task, **_kwargs):
        calls.append(task)
        raise AssertionError("retired host executor must not be called")

    monkeypatch.setattr(appmod, "_run_agent_exec", fake_exec)
    with TestClient(app) as c:
        c.app.state.router = _Router(("glm",))
        task = "【之前的对话】\n我：你好\n\n【现在的指令】\n整理一下这个文件夹"
        for mode, approval_id in (
            ("plan", None),
            ("auto", None),
            ("full", 1),
        ):
            payload = {"task": task, "mode": mode}
            if approval_id is not None:
                payload["approval_id"] = approval_id
            response = c.post("/v1/agent/exec", headers=AUTH, json=payload)
            assert response.status_code == 503
            assert "低权限执行 worker" in response.json()["detail"]
    assert calls == []
