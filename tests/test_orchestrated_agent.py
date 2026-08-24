"""编排型 super-agent：路由 → (复杂则)规划 → 带工具执行 → 跨厂验证 → 不过升级重跑。

用 fake router + monkeypatch chat_with_fallback 走通四条主路径：
- 简单任务 → 快路径（0 次规划/验证 LLM 调用）；
- 复杂任务 → 规划 + 执行 + 验证全走到；
- 验证不过 → 升级到更强模型并重试；
- on_event 收到预期事件类型序列。

fake router 的 routes_info/resolve 写法参照 tests/test_modes.py；tool_capable 用 monkeypatch
控制 preset_meta（不依赖真实 catalog 型号名，版本无关）。
"""

from __future__ import annotations

import hashlib
import asyncio
from types import SimpleNamespace

import pytest

import orchestrator.orchestrated_agent as oa
import orchestrator.scoreboard as sb
from tests.review_fixtures import (
    trusted_chat_result,
    trusted_review_provenance,
    trusted_review_request_sha256,
    trusted_route,
    with_author_receipt,
)


async def test_expired_shared_wall_never_starts_stage() -> None:
    calls = {"n": 0}

    async def stage() -> str:
        calls["n"] += 1
        return "late"

    with pytest.raises(asyncio.TimeoutError):
        await oa._await_with_wall(stage, 0.0)
    assert calls["n"] == 0
import orchestrator.tool_agent as ta


@pytest.fixture(autouse=True)
def _isolate_scoreboard(monkeypatch, tmp_path):
    """把记分牌库指到本测试专属 tmp（照 test_scoreboard 的隔离法）：

    编排里既有 F6 记账钩子会写记分牌、批6① 首轮点将短路(pick_by_record)会读记分牌——若不隔离，
    这些假模型名(cheapA/premB/premC)会污染真实 data/scoreboard.db，且首轮短路会因真库脏数据
    抢占本该走点将官探针/既有流的用例。每个测试各自一份空库 → 短路读到空(返回 None) → 行为确定。
    """
    db = tmp_path / "scoreboard.db"
    monkeypatch.setattr(sb, "_db_path", lambda: str(db))
    sb.reset()
    yield
    sb.reset()

# ── 测试用模型清单：一个便宜 + 三个独立 premium；第三个给总结后的第二终审 ──
# rank 越小越强。cheapA=便宜可调工具；premB(万擎)rank5，premC(斯坦)rank2 更强、不同厂。
_ROUTES = [
    {"model": "cheapA", "provider": "vendorX", "upstream_model": "qwen-turbo", "model_family": "alibaba-qwen", "tier": "cheap", "rank": 1, "flagship": False},
    {"model": "premB", "provider": "vendorX", "upstream_model": "gpt-4o", "model_family": "openai", "tier": "premium", "rank": 5, "flagship": False},
    {"model": "premC", "provider": "vendorY", "upstream_model": "claude-sonnet-4-6", "model_family": "anthropic", "tier": "premium", "rank": 2, "flagship": False},
    {"model": "premD", "provider": "vendorZ", "upstream_model": "gemini-2.5-pro", "model_family": "google-gemini", "tier": "premium", "rank": 6, "flagship": False},
]
# 默认全部能 function-calling；个别用例再 monkeypatch 收窄。
_TOOL_CAPABLE = {"cheapA": True, "premB": True, "premC": True, "premD": True}
_TEST_MODEL_IDENTITIES = {
    "cheapA": ("qwen-turbo", "alibaba-qwen"),
    "premB": ("gpt-4o", "openai"),
    "premC": ("claude-sonnet-4-6", "anthropic"),
    "premD": ("gemini-2.5-pro", "google-gemini"),
    "flagD": ("gemini-2.5-pro", "google-gemini"),
    "reviewE": ("deepseek-v3", "deepseek"),
    "pB": ("gpt-4o", "openai"),
    "pC": ("claude-sonnet-4-6", "anthropic"),
    "pD": ("gemini-2.5-pro", "google-gemini"),
    "fE": ("deepseek-v3", "deepseek"),
    "onlyP": ("gpt-4o", "openai"),
    "premOnly": ("gpt-4o", "openai"),
    "unranked": ("gpt-4o", "openai"),
    "ranked": ("claude-sonnet-4-6", "anthropic"),
}


class _Router:
    """最小 router：只实现编排器/执行器用到的 routes_info + resolve。"""

    def __init__(self, routes=None):
        self._routes = []
        for source in routes or _ROUTES:
            row = dict(source)
            upstream, family = _TEST_MODEL_IDENTITIES[row["model"]]
            row.setdefault("upstream_model", upstream)
            row.setdefault("model_family", family)
            self._routes.append(row)

    def routes_info(self):
        rows = [dict(r) for r in self._routes]
        for row in rows:
            row.setdefault(
                "independence_domain",
                "sha256:" + hashlib.sha256(row["provider"].encode()).hexdigest(),
            )
        return rows

    def list_models(self):
        return [
            {"id": r["model"], "owned_by": r["provider"], "tier": r["tier"],
             "modality": "chat", "description": r["model"]}
            for r in self._routes
        ]

    def resolve(self, model):
        r = next((x for x in self.routes_info() if x["model"] == model), None)
        if r is None:
            return None
        return trusted_route(r)


def _chat_reply(router, req, content):  # noqa: ANN001
    route = router.resolve(req.model)
    assert route is not None
    response = {
        "model": route.upstream_model,
        "choices": [{"message": {"content": content}}],
    }
    return trusted_chat_result(
        request_payload=req.model_dump(exclude_none=True),
        response=response,
        requested_model=req.model,
        actual_model=req.model,
        route=route,
    )


def _patch_tool_capable(monkeypatch, table=None):
    """把 preset_meta 换成查表版：让测试完全掌控每个假模型的 tool_capable，不碰真 catalog。"""
    tbl = table or _TOOL_CAPABLE

    def fake_meta(model_id):
        return {"rank": 0, "flagship": False, "tool_capable": tbl.get(model_id, True)}

    monkeypatch.setattr(oa, "preset_meta", fake_meta)


# ────────────────────────────── 快路径（简单任务） ──────────────────────────────
async def test_simple_task_fast_path_no_planning(monkeypatch, tmp_path):
    """简单任务：直接 run_tool_agent，0 次编排 LLM 调用（无规划/无验证）。"""
    _patch_tool_capable(monkeypatch)
    orch_calls = {"n": 0}  # 编排层自己的 LLM 调用（规划/验证）次数

    async def fake_orch_chat(router, req):
        orch_calls["n"] += 1
        return _chat_reply(router, req, "PASS")

    async def fake_run(router, model, task, **kw):
        return with_author_receipt(router, model, {
            "reply": "done-simple", "steps": 1, "model": model, "usage": {},
            "tool_log": ["read_file(a) -> ok"], "file_changes": [], "media": [],
        })

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(_Router(), "你好", workdir=str(tmp_path))

    assert res["reply"] == "done-simple"
    assert res["_route"]["fast_path"] is True
    assert res["_route"]["model"] == "cheapA"  # 简单 → 便宜 tool_capable
    assert res["plan"] is None
    assert res["verified"] is None  # 快路径不验证
    assert res["escalated"] is False
    assert res["rounds"] == 1
    assert orch_calls["n"] == 0  # 关键：没有任何规划/验证的额外 LLM 调用
    # 保留 run_tool_agent 的键（app.py/前端依赖）
    assert set(["reply", "steps", "model", "usage", "tool_log", "file_changes", "media"]) <= set(res)


async def test_fast_path_unserved_result_never_launders_requested_model(
    monkeypatch, tmp_path
):
    _patch_tool_capable(monkeypatch)

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "deterministic fallback",
            "steps": 0,
            "model": model,
            "actual_model": None,
            "actual_models": [],
            "author_receipts": [],
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(oa, "run_tool_agent", fake_run)
    result = await oa.run_orchestrated_agent(
        _Router(), "你好", workdir=str(tmp_path)
    )

    assert result["model"] is None
    assert result["_route"]["model"] is None
    assert result["_route"]["requested_model"] == "cheapA"
    assert result["_route"]["final_model"] is None
    assert result["_route"]["final_route_receipt"]["model"] is None
    assert result["_route"]["final_route_receipt"]["model_identity_error"] == "no_final_model_call"


async def test_fast_path_failover_binds_final_identity_to_actual_receipt(
    monkeypatch, tmp_path
):
    _patch_tool_capable(monkeypatch)

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return with_author_receipt(
            router,
            "premB",
            {
                "reply": "served by fallback",
                "steps": 1,
                "model": model,
                "usage": {},
                "tool_log": [],
                "file_changes": [],
                "media": [],
            },
            requested_model=model,
        )

    monkeypatch.setattr(oa, "run_tool_agent", fake_run)
    result = await oa.run_orchestrated_agent(
        _Router(), "你好", workdir=str(tmp_path)
    )

    assert result["model"] == "premB"
    assert result["_route"]["model"] == "premB"
    assert result["_route"]["requested_model"] == "cheapA"
    assert result["_route"]["actual_model"] == "premB"
    assert result["_route"]["final_model"] == "premB"
    assert result["_route"]["final_route_receipt"]["route_receipt_version"] == 1


def test_needs_tools_sentinel():
    """路由第3步哨兵：动手/工具/购物/本机路径 = 要动手 → 判复杂上强模型；纯闲聊不算。"""
    assert oa._needs_tools("打开淘宝，找下玻璃鱼缸")
    assert oa._needs_tools("帮我下载这个文件")
    assert oa._needs_tools("看看 D:\\项目\\a.py 写了啥")  # 本机路径
    assert not oa._needs_tools("你好")
    assert not oa._needs_tools("讲个笑话")
    assert not oa._needs_tools("什么是相对论")


async def test_tool_heavy_routes_to_capable_not_cheap(monkeypatch, tmp_path):
    """机主实测根修：动手活(打开淘宝)不再被判简单丢给便宜模型——判复杂、选够强模型、不走无升级快路径。"""
    _patch_tool_capable(monkeypatch)

    async def fake_orch_chat(router, req):  # noqa: ANN001
        return _chat_reply(router, req, "1. 开浏览器\n2. 搜\nPASS")

    async def fake_run(router, model, task, **kw):  # noqa: ANN001
        return with_author_receipt(router, model, {
            "reply": "done", "steps": 3, "model": model, "usage": {},
            "tool_log": ["web_read(taobao) -> ok"], "file_changes": [], "media": [],
        })

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(), "打开淘宝，找下玻璃鱼缸", workdir=str(tmp_path), trinity=False
    )
    assert res["_route"]["complex"] is True       # 判复杂（哨兵命中）
    assert res["_route"]["fast_path"] is False     # 不走无升级的快路径
    assert res["_route"]["model"] != "cheapA"      # 不再是最便宜模型
    assert res["_route"]["model"] == "premC"       # 选了够强的 tool_capable（rank2）


async def test_tool_heavy_trinity_seeds_strong_first_cast(monkeypatch, tmp_path):
    """舰队路(trinity)根修：点将官按 chat 战绩会点 agnes-flash → 动手活直接用强模型开局(first_cast)。"""
    _patch_tool_capable(monkeypatch)
    captured: dict = {}

    async def fake_trinity(router, task, **kw):  # noqa: ANN001
        captured["first_cast"] = kw.get("first_cast")
        return {"reply": "done", "steps": 3, "model": kw.get("first_cast"), "usage": {},
                "tool_log": [], "file_changes": [], "media": [], "verified": True, "rounds": 1}

    # 若点将官被调用会点 cheapA（用来证明它被跳过了）
    monkeypatch.setattr(oa.coordinator, "pick_by_record", lambda *a, **k: "cheapA")
    monkeypatch.setattr(oa, "run_trinity_agent", fake_trinity)

    res = await oa.run_orchestrated_agent(
        _Router(), "打开淘宝，找下玻璃鱼缸", workdir=str(tmp_path), trinity=True
    )
    # first_cast 必须是 dict（run_trinity_agent 会 first_cast.get("model")）——传字符串会炸 'str' has no 'get'。
    assert isinstance(captured["first_cast"], dict)
    assert captured["first_cast"].get("model") == "premC"  # 用强模型开局，不是点将官点的 cheapA
    assert res["reply"] == "done"


async def test_trinity_falls_back_to_llm_cast_without_local_neural_runtime(
    monkeypatch, tmp_path
):
    """text-first 环境没有 NumPy/神经点将时，协作仍用点将官继续，不静默停摆。"""
    _patch_tool_capable(monkeypatch)
    calls = {"pick_next": 0, "first_cast": None}

    monkeypatch.setattr(oa.coordinator, "pick_by_record", lambda *a, **k: None)

    async def fake_pick_next(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["pick_next"] += 1
        return {"model": "premB", "role": "thinker", "instruction": "先分析权衡"}

    async def fake_trinity(router, task, **kwargs):  # noqa: ANN001
        calls["first_cast"] = kwargs.get("first_cast")
        return {
            "reply": "fallback-cast-ok",
            "steps": 1,
            "model": "premB",
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
            "verified": True,
            "rounds": 1,
        }

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick_next)
    monkeypatch.setattr(oa, "run_trinity_agent", fake_trinity)

    result = await oa.run_orchestrated_agent(
        _Router(),
        "请比较三种分布式一致性算法的权衡并给出详细结论",
        workdir=str(tmp_path),
        trinity=True,
        fast_first=False,
    )

    assert calls["pick_next"] == 1
    assert calls["first_cast"] == {
        "model": "premB",
        "role": "thinker",
        "instruction": "先分析权衡",
    }
    assert result["reply"] == "fallback-cast-ok"


# ────────────────────────────── 复杂任务：规划+执行+验证全走到 ──────────────────────────────
async def test_complex_task_plans_executes_verifies(monkeypatch, tmp_path):
    """复杂任务：选强 premium 模型 → 规划 → 执行 → 跨厂验证达标一次过。"""
    _patch_tool_capable(monkeypatch)
    orch_prompts: list[str] = []

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        orch_prompts.append(text)
        if "你是本任务的发起者" in text:
            return _chat_reply(router, req, "发起者汇总后的最终交付")
        if "独立审核官" in text:  # 验证请求 → 达标
            return _chat_reply(router, req, "看起来完成了\nPASS")
        # 否则是规划请求
        return _chat_reply(router, req, "1. 建目录\n2. 写文件\n验收：文件存在")

    run_calls = {"n": 0, "history": None}

    async def fake_run(router, model, task, **kw):
        run_calls["n"] += 1
        run_calls["history"] = kw.get("history")
        return with_author_receipt(router, model, {
            "reply": "已完成复杂任务", "steps": 3, "model": model, "usage": {},
            "tool_log": ["write_file(x) -> ok"], "file_changes": [], "media": [],
        })

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    # 用带"重构/架构"关键词的任务确保被判为复杂
    res = await oa.run_orchestrated_agent(
        _Router(), "请分析并重构这个复杂算法模块，给出优化策略", workdir=str(tmp_path), fast_first=False
    )

    assert res["_route"]["fast_path"] is False
    assert res["_route"]["model"] == "premC"  # premium 里 rank 最小(最强)的 tool_capable
    assert res["plan"] and "写文件" in res["plan"]
    assert res["reviewed"] is True
    assert res["verified"] is False
    assert res["outcome"] == "completed_unverified"
    assert res["escalated"] is False
    assert res["reply"] == "发起者汇总后的最终交付"
    assert res["_route"]["initiator_vote_weight"] == 0
    assert res["_route"]["initial_reviewer"] == "premB"
    assert res["_route"]["reviewer"] == "premD"
    assert res["rounds"] == 1
    assert run_calls["n"] == 1  # 一次过，只执行一轮
    # 计划被注入执行 history
    assert any(m.get("role") == "system" and "执行计划" in str(m.get("content"))
               for m in (run_calls["history"] or []))
    # 至少一次规划 + 一次验证 LLM 调用
    assert len(orch_prompts) >= 2


async def test_complex_task_rejects_failover_model_as_initiator_summary(
    monkeypatch, tmp_path
):
    """The summary stage must be served by the original initiator, not fallback."""

    _patch_tool_capable(monkeypatch)

    async def fake_orch_chat(router, req):  # noqa: ANN001
        text = str(req.messages[-1].content or "")
        if "你是本任务的发起者" in text:
            served = "premD"
            route = router.resolve(served)
            response = {
                "model": route.upstream_model,
                "choices": [{"message": {"content": "fallback summary"}}],
            }
            return trusted_chat_result(
                request_payload=req.model_dump(exclude_none=True),
                response=response,
                requested_model=req.model,
                actual_model=served,
                route=route,
            )
        if "独立审核官" in text:
            return _chat_reply(router, req, "independent\nPASS")
        return _chat_reply(router, req, "1. execute\n2. verify")

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return with_author_receipt(router, model, {
            "reply": "reviewed worker draft",
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": ["read_file(x) -> ok"],
            "file_changes": [],
            "media": [],
        })

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    result = await oa.run_orchestrated_agent(
        _Router(),
        "请分析并重构这个复杂算法模块，给出优化策略",
        workdir=str(tmp_path),
        fast_first=False,
    )

    assert result["reply"] == "reviewed worker draft"
    assert result["_route"]["summary_model_requested"] == "premC"
    assert result["_route"]["summary_model"] == "premD"
    assert result["_route"]["post_summary_review_error"] == (
        "initiator_summary_actual_mismatch"
    )
    assert result["reviewed"] is False
    assert result["_route"]["reviewer_vote_weight"] == 0


# ────────────────────────────── 验证不过 → 升级更强模型重试 ──────────────────────────────
async def test_verify_fail_escalates_to_stronger_model(monkeypatch, tmp_path):
    """验证不过：执行模型从 premC 升级到更强档（放开 flagship），带评语重规划并重跑。"""
    # 加一个王牌(flagship, rank0=最强)做升级目标
    routes = _ROUTES + [
        {"model": "flagD", "provider": "vendorZ", "tier": "premium", "rank": 0, "flagship": True},
        {"model": "reviewE", "provider": "vendorW", "tier": "premium", "rank": 9, "flagship": False},
    ]
    _patch_tool_capable(monkeypatch, {
        "cheapA": True, "premB": True, "premC": True, "flagD": True, "reviewE": True,
    })

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "你是本任务的发起者" in text:
            return _chat_reply(router, req, "发起者汇总升级后的最终交付")
        if "独立审核官" in text:  # 验证：第一轮 FAIL，之后 PASS
            return _chat_reply(router, req, f"评审\n{verdict_seq.pop(0)}")
        return _chat_reply(router, req, "1. 步骤A\n验收：X")  # 规划

    verdict_seq = ["FAIL:还差一步", "PASS"]

    exec_models: list[str] = []

    async def fake_run(router, model, task, **kw):
        exec_models.append(model)
        return with_author_receipt(router, model, {
            "reply": f"用{model}的产出", "steps": 2, "model": model, "usage": {},
            "tool_log": [f"run({model})"], "file_changes": [], "media": [],
        })

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(routes), "设计并实现一个可扩展的复杂系统架构", workdir=str(tmp_path), fast_first=False
    )

    # 首跑 premC → 验证 FAIL → 升级到更强的 flagD 重跑 → PASS
    assert exec_models[0] == "premC"
    assert exec_models[1] == "flagD"
    assert res["escalated"] is True
    # Earlier qualified rejection was absorbed into the replan lineage.  The
    # four registered strong families are now all contributors, so no fifth
    # identity remains for the summary's final review.  Draft PASS is not reused.
    assert res["reviewed"] is False
    assert res["verified"] is False
    assert res["rounds"] == 2
    assert res["reply"] == "发起者汇总升级后的最终交付"
    assert res["outcome"] == "partial"
    assert res["_route"]["draft_reviewed"] is True
    assert res["_route"]["post_summary_review_error"] == (
        "no_strong_independent_final_reviewer"
    )


def test_escalation_treats_zero_rank_non_flagship_as_unranked(monkeypatch):
    routes = [
        {
            "model": "unranked",
            "provider": "vendor-a",
            "tier": "premium",
            "rank": 0,
            "flagship": False,
        },
        {
            "model": "ranked",
            "provider": "vendor-b",
            "tier": "premium",
            "rank": 7,
            "flagship": False,
        },
    ]
    _patch_tool_capable(monkeypatch, {"unranked": True, "ranked": True})

    assert oa._escalate_model(_Router(routes), "unranked") == "ranked"
    assert oa._escalate_model(_Router(routes), "ranked") == "ranked"


async def test_exec_stall_triggers_escalation_even_if_verify_passes(monkeypatch, tmp_path):
    """执行返回 stopped_reason=stall 时，即便审核放行也要升级重跑（执行本身没干顺）。"""
    routes = _ROUTES + [
        {"model": "flagD", "provider": "vendorZ", "tier": "premium", "rank": 0,
         "flagship": True},
    ]
    _patch_tool_capable(
        monkeypatch, {"cheapA": True, "premB": True, "premC": True, "flagD": True}
    )

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "PASS")  # 审核总放行
        return _chat_reply(router, req, "计划")

    exec_models: list[str] = []

    async def fake_run(router, model, task, **kw):
        exec_models.append(model)
        out = {"reply": f"{model}产出", "steps": 2, "model": model, "usage": {},
               "tool_log": [f"t({model})"], "file_changes": [], "media": []}
        if len(exec_models) == 1:  # 首跑：报 stall
            out["stopped_reason"] = "stall"
        return out

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(routes), "请一步步推导并优化这个复杂算法", workdir=str(tmp_path), fast_first=False
    )

    assert len(exec_models) == 2  # 首跑 stall → 升级重跑一次
    assert exec_models[1] != exec_models[0]  # 换了更强模型
    assert res["escalated"] is True


async def test_escalation_capped_at_max_rounds(monkeypatch, tmp_path):
    """验证一直不过：升级重跑封顶 _MAX_ROUNDS 轮，返回尽力而为结果并标 verified=False。"""
    # 给足够多的不同强度 premium，保证每轮都能换到更强、不会因"无更强"提前 break
    routes = [
        {"model": "cheapA", "provider": "vX", "tier": "cheap", "rank": 1, "flagship": False},
        {"model": "pB", "provider": "vX", "tier": "premium", "rank": 9, "flagship": False},
        {"model": "pC", "provider": "vY", "tier": "premium", "rank": 5, "flagship": False},
        {"model": "pD", "provider": "vZ", "tier": "premium", "rank": 2, "flagship": False},
        {"model": "fE", "provider": "vW", "tier": "premium", "rank": 0, "flagship": True},
    ]
    _patch_tool_capable(monkeypatch, {m["model"]: True for m in routes})

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:  # 审核永远不过
            return _chat_reply(router, req, "FAIL:仍不达标")
        return _chat_reply(router, req, "计划")

    runs = {"n": 0}

    async def fake_run(router, model, task, **kw):
        runs["n"] += 1
        return {"reply": f"{model}尽力", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)
    monkeypatch.setattr(
        oa,
        "_pick_tool_capable",
        lambda router, tier, **kwargs: "pB" if tier == "premium" else None,
    )

    res = await oa.run_orchestrated_agent(
        _Router(routes), "设计并实现复杂可扩展系统架构", workdir=str(tmp_path),
        trinity=False, fast_first=False,
    )

    # 首跑 + 最多 _MAX_ROUNDS 轮升级 = _MAX_ROUNDS + 1 次执行（有界，不无限）
    assert runs["n"] == oa._MAX_ROUNDS + 1
    assert res["rounds"] == oa._MAX_ROUNDS + 1
    assert res["verified"] is False
    assert res["escalated"] is True


async def test_no_stronger_model_stops_without_wasted_rerun(monkeypatch, tmp_path):
    """只有一个 premium 可用时，验证不过也不做无谓重跑（无更强可换）→ 只执行一次。"""
    routes = [
        {"model": "cheapA", "provider": "vX", "tier": "cheap", "rank": 1, "flagship": False},
        {"model": "onlyP", "provider": "vX", "tier": "premium", "rank": 2, "flagship": False},
    ]
    _patch_tool_capable(monkeypatch, {"cheapA": True, "onlyP": True})

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "FAIL:不行")
        return _chat_reply(router, req, "计划")

    runs = {"n": 0}

    async def fake_run(router, model, task, **kw):
        runs["n"] += 1
        return {"reply": "尽力", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(routes), "分析并重构复杂系统架构", workdir=str(tmp_path), fast_first=False
    )

    assert runs["n"] == 1  # 无更强可升级 → 不重跑
    assert res["escalated"] is False
    assert res["verified"] is False


# ────────────────────────────── on_event 事件序列 ──────────────────────────────
async def test_on_event_sequence_complex(monkeypatch, tmp_path):
    """复杂一次过：事件应含 route → plan → step → verify → done。"""
    _patch_tool_capable(monkeypatch)

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "PASS")
        return _chat_reply(router, req, "计划一二三")

    async def fake_run(router, model, task, **kw):
        oe = kw.get("on_event")  # 真 run_tool_agent 现在每步实时推——mock 也照做，模拟实时流式
        for entry in ("a", "b"):
            if oe:
                await oe({"type": "step", "log": entry})
        return {"reply": "ok", "steps": 2, "model": model, "usage": {},
                "tool_log": ["a", "b"], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    events: list[dict] = []

    async def on_event(ev):
        events.append(ev)

    await oa.run_orchestrated_agent(
        _Router(), "分析并重构复杂系统并给出优化", workdir=str(tmp_path),
        on_event=on_event, fast_first=False,  # 隔离快档，专测编排事件序列
    )

    types = [e["type"] for e in events]
    assert types[0] == "route"
    assert "plan" in types
    assert types.count("step") == 2  # 两条 tool_log 各推一次
    assert "verify" in types
    assert types[-1] == "done"


async def test_on_event_sequence_fast_path(monkeypatch, tmp_path):
    """简单任务快路径：事件只应有 route → step* → done（无 plan/verify）。"""
    _patch_tool_capable(monkeypatch)

    async def fake_orch_chat(router, req):  # 不该被调到
        raise AssertionError("快路径不应发生编排 LLM 调用")

    async def fake_run(router, model, task, **kw):
        oe = kw.get("on_event")  # 模拟实时逐步流式
        if oe:
            await oe({"type": "step", "log": "only-one"})
        return {"reply": "hi", "steps": 1, "model": model, "usage": {},
                "tool_log": ["only-one"], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    events: list[dict] = []

    async def on_event(ev):
        events.append(ev)

    await oa.run_orchestrated_agent(_Router(), "谢谢", workdir=str(tmp_path), on_event=on_event)

    types = [e["type"] for e in events]
    assert types[0] == "route"
    assert types[-1] == "done"
    assert "plan" not in types
    assert "verify" not in types
    assert types.count("step") == 1


# ────────────────────────────── tool_capable 过滤 ──────────────────────────────
async def test_routing_skips_non_tool_capable_premium(monkeypatch, tmp_path):
    """强档里最强的那个若不能 function-calling，应跳过它、选次强的 tool_capable premium。"""
    # premC 最强但标记不能调工具 → 应退而选 premB
    _patch_tool_capable(monkeypatch, {"cheapA": True, "premB": True, "premC": False})

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "PASS")
        return _chat_reply(router, req, "计划")

    picked: list[str] = []

    async def fake_run(router, model, task, **kw):
        picked.append(model)
        return with_author_receipt(router, model, {
            "reply": "ok", "steps": 1, "model": model, "usage": {},
            "tool_log": [], "file_changes": [], "media": [],
        })

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(), "请分析并重构这个复杂模块", workdir=str(tmp_path), fast_first=False
    )
    assert picked[0] == "premB"  # 跳过不可调工具的 premC
    assert res["_route"]["model"] == "premB"


# ────────────────────────────── 显式 model 尊重 ──────────────────────────────
async def test_explicit_model_is_respected(monkeypatch, tmp_path):
    """显式传 model：即便任务复杂也用指定模型执行（仍走规划+验证编排）。"""
    _patch_tool_capable(monkeypatch)

    async def fake_orch_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "PASS")
        return _chat_reply(router, req, "计划")

    picked: list[str] = []

    async def fake_run(router, model, task, **kw):
        picked.append(model)
        return {"reply": "ok", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构复杂系统", workdir=str(tmp_path), model="cheapA"
    )
    assert picked[0] == "cheapA"  # 尊重显式 model，不自动改选 premium
    assert res["_route"]["forced_model"] is True


async def test_explicit_model_is_not_replaced_when_independent_review_is_unavailable(
    monkeypatch, tmp_path
):
    """A user-selected model stays authoritative across orchestration rounds."""
    _patch_tool_capable(monkeypatch)
    monkeypatch.setattr(oa, "resolve_workspace", lambda path: path)

    async def fake_orch_chat(router, req):  # noqa: ANN001
        return _chat_reply(router, req, "plan")

    picked: list[str] = []

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        picked.append(model)
        return with_author_receipt(
            router,
            model,
            {
                "reply": f"served-by-{model}",
                "steps": 1,
                "model": model,
                "usage": {},
                "tool_log": [],
                "file_changes": [],
                "media": [],
            },
        )

    async def unavailable_review(*args, **kwargs):  # noqa: ANN001
        return None, "no independent reviewer"

    monkeypatch.setattr(oa, "chat_with_fallback", fake_orch_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)
    monkeypatch.setattr(oa, "_review_with_gate", unavailable_review)

    result = await oa.run_orchestrated_agent(
        _Router(),
        "analyze and refactor this complex system",
        workdir=str(tmp_path),
        model="cheapA",
        fast_first=False,
    )

    assert picked == ["cheapA"]
    assert result["model"] == "cheapA"
    assert result["escalated"] is False


def test_echo_is_never_an_escalation_target_for_a_real_model(monkeypatch):
    _patch_tool_capable(monkeypatch, {"customLocal": True, "echo": True})
    router = SimpleNamespace(
        routes_info=lambda: [
            {
                "model": "customLocal",
                "tier": "local",
                "rank": None,
                "flagship": False,
            },
            {
                "model": "echo",
                "tier": "free",
                "rank": 0,
                "flagship": False,
            },
        ]
    )

    assert oa._escalate_model(router, "customLocal") == "customLocal"


async def test_fast_first_skips_orchestration_when_cheap_succeeds(monkeypatch, tmp_path):
    """先快后升(机主实测根修)：即使被判 complex，先让便宜模型直接上手；干成了立刻返回，
    绝不进规划/点将（"分析下这个文件"5-15s 出活，而不是 43s 还在写计划）。"""
    _patch_tool_capable(monkeypatch)
    calls = {"tool": 0, "plan": 0, "pick": 0}

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        calls["tool"] += 1
        return {"reply": "读完了，这个文件夹有 4 个文档…", "steps": 2, "model": model,
                "usage": {}, "tool_log": ["list_dir(...) -> ok"], "file_changes": [], "media": []}

    async def fake_plan(*a, **k):  # noqa: ANN001
        calls["plan"] += 1
        return "不该被调用"

    async def fake_pick(*a, **k):  # noqa: ANN001
        calls["pick"] += 1
        return None

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa, "_make_plan", fake_plan)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    res = await oa.run_orchestrated_agent(
        _Router(), "分析下这个项目的整体框架和逻辑", workdir=str(tmp_path)
    )
    assert calls["tool"] == 1 and calls["plan"] == 0 and calls["pick"] == 0
    assert res["_route"].get("fast_first") is True
    assert "4 个文档" in res["reply"]


async def test_fast_first_unserved_reply_keeps_requested_separate(monkeypatch, tmp_path):
    _patch_tool_capable(monkeypatch)

    async def fake_tool(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "deterministic quick fallback",
            "steps": 0,
            "model": model,
            "actual_model": None,
            "actual_models": [],
            "author_receipts": [],
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    result = await oa.run_orchestrated_agent(
        _Router(), "分析下这个项目的整体框架和逻辑", workdir=str(tmp_path)
    )

    assert result["_route"]["fast_first"] is True
    assert result["model"] is None
    assert result["_route"]["model"] is None
    assert result["_route"]["requested_model"] == "cheapA"
    assert result["_route"]["final_model"] is None


async def test_complex_unserved_final_never_falls_back_to_requested(
    monkeypatch, tmp_path
):
    _patch_tool_capable(monkeypatch)

    async def fake_plan(*args, **kwargs):  # noqa: ANN002, ANN003
        return "plan"

    async def fake_tool(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "deterministic complex fallback",
            "steps": 0,
            "model": model,
            "actual_model": None,
            "actual_models": [],
            "author_receipts": [],
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }

    async def fake_review(*args, **kwargs):  # noqa: ANN002, ANN003
        return None, "FAIL"

    monkeypatch.setattr(oa, "_make_plan", fake_plan)
    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa, "_review_with_gate", fake_review)
    monkeypatch.setattr(oa, "_escalate_model", lambda router, current: current)

    result = await oa.run_orchestrated_agent(
        _Router(),
        "分析并重构复杂系统架构",
        workdir=str(tmp_path),
        model="cheapA",
        trinity=False,
        fast_first=False,
    )

    assert result["model"] is None
    assert result["_route"]["model"] is None
    assert result["_route"]["requested_model"] == "cheapA"
    assert result["_route"]["final_model"] is None
    assert result["_route"]["final_route_receipt"]["model_identity_error"] == "no_final_model_call"


async def test_fast_first_escalates_when_cheap_stalls(monkeypatch, tmp_path):
    """先快后升：便宜模型停滞(stall) → 升编排（探针/规划照走），不带走 quick 的烂结果。"""
    _patch_tool_capable(monkeypatch)
    seen = {"tool": 0}

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        seen["tool"] += 1
        if seen["tool"] == 1:  # 第一次=快档，停滞
            return {"reply": "", "steps": 10, "model": model, "usage": {},
                    "tool_log": [], "file_changes": [], "media": [], "stopped_reason": "stall"}
        return {"reply": "编排干完了", "steps": 3, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    async def fake_pick(*a, **k):  # noqa: ANN001
        return None  # 点将官不可用 → 走老编排流

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        return True, "PASS"

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    async def fake_plan2(*a, **k):  # noqa: ANN001
        return "1. 干活"

    monkeypatch.setattr(oa, "_make_plan", fake_plan2)
    res = await oa.run_orchestrated_agent(
        _Router(), "分析下这个项目的整体框架和逻辑", workdir=str(tmp_path)
    )
    assert seen["tool"] >= 2  # 快档一次 + 编排至少一次
    assert res["reply"] == "编排干完了"


async def test_fast_first_skipped_when_only_premium(monkeypatch, tmp_path):
    """#1 互审：池里没有真便宜档(退化到 premium/echo) → 不跑快档，直接进编排(不用贵模型瞎探路)。"""
    routes = [{"model": "premOnly", "provider": "vX", "tier": "premium", "rank": 1, "flagship": False}]
    _patch_tool_capable(monkeypatch, {"premOnly": True})
    seen = {"tool": [], "plan": 0}

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        seen["tool"].append((model, kw.get("preload_context")))
        return {"reply": "编排干完", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    async def fake_pick(*a, **k):  # noqa: ANN001
        return None

    async def fake_plan2(*a, **k):  # noqa: ANN001
        seen["plan"] += 1
        return "1. 干活"

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        return True, "PASS"

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "_make_plan", fake_plan2)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    res = await oa.run_orchestrated_agent(
        _Router(routes), "分析下这个复杂项目的架构", workdir=str(tmp_path)
    )
    # 没有 fast_first 那次(premium 不当快档)；直接编排规划
    assert res["_route"].get("fast_first") is not True
    assert seen["plan"] == 1


async def test_fast_first_hard_exception_escalates(monkeypatch, tmp_path):
    """#2 互审：快档 run_tool_agent 抛硬异常(非超时) → 吞掉升编排，绝不让快档死=编排死。"""
    _patch_tool_capable(monkeypatch)
    seen = {"n": 0}

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        seen["n"] += 1
        if seen["n"] == 1:
            raise RuntimeError("快档炸了")
        return {"reply": "编排救回", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    async def fake_pick(*a, **k):  # noqa: ANN001
        return None

    async def fake_plan2(*a, **k):  # noqa: ANN001
        return "1. 干活"

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        return True, "PASS"

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "_make_plan", fake_plan2)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    res = await oa.run_orchestrated_agent(
        _Router(), "分析下这个复杂项目的架构", workdir=str(tmp_path)
    )
    assert seen["n"] >= 2 and res["reply"] == "编排救回"


async def test_worker_wall_cap_skips_verify_and_replan(monkeypatch, tmp_path):
    """A worker that exhausts the shared budget cannot receive fresh review calls."""
    _patch_tool_capable(monkeypatch)
    calls = {"plan": 0, "verify": 0, "worker": 0}

    async def fake_plan(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["plan"] += 1
        return "1. execute"

    async def fake_worker(router, model, task, **kwargs):  # noqa: ANN001
        calls["worker"] += 1
        return {
            "reply": "partial",
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
            "stopped_reason": "wall_cap",
        }

    async def fake_verify(*args, **kwargs):  # noqa: ANN002, ANN003
        calls["verify"] += 1
        return True, "PASS"

    monkeypatch.setattr(oa, "_make_plan", fake_plan)
    monkeypatch.setattr(oa, "run_tool_agent", fake_worker)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    result = await oa.run_orchestrated_agent(
        _Router(),
        "分析并重构这个复杂系统",
        workdir=str(tmp_path),
        model="cheapA",
        trinity=False,
        fast_first=False,
    )

    assert calls == {"plan": 1, "verify": 0, "worker": 1}
    assert result["stopped_reason"] == "wall_cap"
    assert result["verified"] is False


async def test_fast_first_forces_no_preload(monkeypatch, tmp_path):
    """#4 互审：快档强制 preload_context=False(要快)，不吃 KB/工作区预读。"""
    _patch_tool_capable(monkeypatch)
    captured = {}

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        captured["preload"] = kw.get("preload_context")
        return {"reply": "读完了", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    await oa.run_orchestrated_agent(
        _Router(), "分析下这个复杂项目", workdir=str(tmp_path), preload_context=True
    )
    assert captured["preload"] is False  # 即便外部传 True，快档也强制 False


async def test_harness_persists_and_resumes(monkeypatch, tmp_path):
    """长任务 harness 端到端：第一次跑落盘任务状态；第二次续跑把上次进度注入 history。"""
    import orchestrator.task_state as ts
    _patch_tool_capable(monkeypatch)

    captured = {"hist": None}

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        captured["hist"] = kw.get("history")
        return {"reply": "读完代码，改了结构", "steps": 2, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    async def fake_pick(*a, **k):  # noqa: ANN001
        return None  # 不走 TRINITY，走 plan 路

    async def fake_plan(*a, **k):  # noqa: ANN001
        return "1. 读代码\n2. 改结构\n3. 跑测试"

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        return False, "还没跑测试"  # 未完成 → 状态留"未完成"，可续跑

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "_make_plan", fake_plan)
    monkeypatch.setattr(oa, "_verify", fake_verify)

    wd = str(tmp_path)
    # 第一次：新长任务 → 落盘 .纳川/任务.json
    await oa.run_orchestrated_agent(
        _Router(), "重构这个项目的架构和逻辑", workdir=wd, harness=True, fast_first=False
    )
    st = ts.load(wd)
    assert st is not None and st["goal"] == "重构这个项目的架构和逻辑"
    assert [s["title"] for s in st["steps"]] == ["读代码", "改结构", "跑测试"]

    # 第二次：续跑指令 → resume_context 应被注入进 fake_tool 收到的 history
    captured["hist"] = None
    await oa.run_orchestrated_agent(
        _Router(), "继续", workdir=wd, harness=True, fast_first=False
    )
    joined = " ".join(str(m.get("content")) for m in (captured["hist"] or []))
    assert "接着上次" in joined and "重构这个项目" in joined  # 上次进度注入了


async def test_harness_off_no_state_file(monkeypatch, tmp_path):
    """harness=False（纯聊天/无目标）→ 绝不往 workdir 写 .纳川 状态文件。"""
    _patch_tool_capable(monkeypatch)

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        return {"reply": "答完了", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    async def fake_pick(*a, **k):  # noqa: ANN001
        return None

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "_make_plan", lambda *a, **k: _async_ret("1. x"))
    monkeypatch.setattr(oa, "_verify", lambda *a, **k: _async_ret((True, "PASS")))
    await oa.run_orchestrated_agent(
        _Router(), "分析并重构复杂系统", workdir=str(tmp_path), harness=False, fast_first=False
    )
    assert not (tmp_path / ".纳川").exists()  # 没开 harness → 不落盘


def _async_ret(v):
    async def _f(*a, **k):  # noqa: ANN001
        return v
    return _f()


async def test_harness_never_executes_workspace_verify_command_on_host(monkeypatch, tmp_path):
    """工作区测试等价于代码执行；无隔离 worker 时只能提示，不得在宿主上跑。"""
    import orchestrator.task_state as ts
    _patch_tool_capable(monkeypatch)
    # 让 workdir 看起来是 py 项目 → 自动探测到 pytest 验证命令
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    async def fake_tool(router, model, task, **kw):  # noqa: ANN001
        return with_author_receipt(router, model, {
            "reply": "我改完了", "steps": 1, "model": model, "usage": {},
            "tool_log": [], "file_changes": [], "media": [],
        })

    async def fake_pick(*a, **k):  # noqa: ANN001
        return None

    async def fake_plan(*a, **k):  # noqa: ANN001
        return "1. 改代码\n2. 跑测试"

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        candidate = str(result.get("reply") or "")
        route = router.resolve(reviewer)
        return oa.review_observation(
            router,
            requested_model=reviewer,
            served_model=reviewer,
            route=route,
            response={
                "model": route.upstream_model,
                "choices": [{"message": {"content": "PASS"}}],
            },
            verdict="PASS",
            reviewed_output=candidate,
                provider_provenance=trusted_review_provenance(
                requested_model=reviewer,
                actual_model=reviewer,
                route=route,
                verdict="PASS",
                    reviewed_output=candidate,
                ),
                expected_provider_request_sha256=trusted_review_request_sha256(
                    actual_model=reviewer,
                    reviewed_output=candidate,
                ),
            )

    async def fake_summary(router, model, prompt):  # noqa: ANN001
        route = router.resolve(model)
        return (
            "发起者汇总后的最终交付",
            model,
            route,
            {"model": route.upstream_model},
        )

    monkeypatch.setattr(oa, "run_tool_agent", fake_tool)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "_make_plan", fake_plan)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    monkeypatch.setattr(oa, "_llm_observed_response", fake_summary)

    res = await oa.run_orchestrated_agent(
        _Router(), "把这个项目的导出功能改好", workdir=str(tmp_path),
        harness=True, fast_first=False,
    )
    # 跨模型审查通过，但没有机器执行证据，必须诚实标成未验证完成。
    assert res["verified"] is False
    assert res["reviewed"] is True
    assert res["verification_level"] == "model_review_only"
    assert res["verification_required"] == "python -m pytest -q"
    assert res["outcome"] == "completed_unverified"
    # 旧状态即使含 verify_cmd，也只作为固定规则重新探测出的提示，绝不成为执行权限。
    assert ts.get_verify_cmd(str(tmp_path)) == "python -m pytest -q"


async def test_review_pass_from_failover_to_actual_executor_has_zero_vote(
    monkeypatch, tmp_path
):
    """Requested reviewer != requested worker is irrelevant after both calls fail over.

    The worker request targets premC but is actually served by premB.  The review request
    then targets/lands on premB too.  A textual PASS is therefore self-review and must be
    discarded rather than turning the result into reviewed/verified output.
    """
    _patch_tool_capable(monkeypatch)

    async def fake_chat(router, req):  # noqa: ANN001
        prompt = str(req.messages[-1].content or "")
        if "独立审核官" in prompt:
            served = "premB"  # same actual model that produced the worker result
            text = "PASS"
        else:
            served = req.model
            text = "1. 执行\n2. 验收"
        return (
            {
                "model": router.resolve(served).upstream_model,
                "choices": [{"message": {"content": text}}],
            },
            served,
            router.resolve(served),
        )

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        assert model == "premC"  # requested worker
        return {
            "reply": "由故障转移后的 premB 生成",
            "steps": 1,
            "model": "premC",  # backward-compatible display/requested identity
            "actual_model": "premB",
            "actual_models": ["premB"],
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(oa, "chat_with_fallback", fake_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    result = await oa.run_orchestrated_agent(
        _Router(),
        "分析并重构这个复杂系统架构",
        workdir=str(tmp_path),
        trinity=False,
        fast_first=False,
    )

    assert result["reviewed"] is False
    assert result["verified"] is False
    assert result["_route"]["reviewer_vote_weight"] == 0


def test_actual_author_fields_are_presence_sensitive():
    assert oa._actual_author_models({
        "model": "requested", "actual_model": None, "actual_models": [],
    }) == []
    assert oa._actual_author_models({
        "model": "requested", "actual_model": "", "actual_models": [],
    }) == [""]
    assert oa._actual_author_models({
        "model": "requested", "actual_model": "premC",
        "actual_models": ["premB", "premC"],
    }) == ["premB", "premC"]
    # Only a legacy double that completely omits truth fields may use display `model`.
    assert oa._actual_author_models({"model": "legacy-served"}) == ["legacy-served"]
