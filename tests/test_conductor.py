"""F4 Conductor-lite 工作流 DAG（orchestrator/conductor.py）测试。

覆盖：
- plan_workflow：正常解析 / 前向引用违规重试后修好 / 两次违规→None / 池外模型被同档替代；
- run_conductor_agent：正常 DAG 分层并行（access_list [[],[],[0,1]] → 前两节点同层并行）/
  上下文正确传递（节点2 能看到节点0 产出）/ 终审 FAIL→重规划一轮 / planner 挂→退化 TRINITY /
  返回 dict 键完整。

版本无关手法（照抄 test_trinity / test_coordinator_pick）：假 router 只实现 routes_info；
monkeypatch coordinator.preset_meta + scoreboard.win_rate/summary_line 掌控快照（不碰真
catalog/sqlite），monkeypatch conductor.chat_with_fallback（planner 出 DAG JSON）/
conductor.run_tool_agent（节点产出）/ orchestrated_agent._verify（终审判词）。均不碰真 LLM。
"""

from __future__ import annotations

import hashlib
import json

import orchestrator.conductor as cd
import orchestrator.coordinator as co
import orchestrator.orchestrated_agent as oa
import orchestrator.scoreboard as sb
from orchestrator.workspace_guard import workspace_root
from tests.review_fixtures import (
    trusted_chat_result,
    trusted_review_provenance,
    trusted_review_request_sha256,
    trusted_route,
    with_author_receipt,
)

# 便宜 + 四个不同厂 premium：失败反馈进入 lineage 后仍有第三方可做下一轮终审。
_ROUTES = [
    {"model": "cheapA", "provider": "vX", "upstream_model": "qwen-turbo", "model_family": "alibaba-qwen", "tier": "cheap", "rank": 1, "flagship": False},
    {"model": "premB", "provider": "vX", "upstream_model": "gpt-4o", "model_family": "openai", "tier": "premium", "rank": 5, "flagship": False},
    {"model": "premC", "provider": "vY", "upstream_model": "claude-sonnet-4-6", "model_family": "anthropic", "tier": "premium", "rank": 2, "flagship": False},
    {"model": "premD", "provider": "vZ", "upstream_model": "gemini-2.5-pro", "model_family": "google-gemini", "tier": "premium", "rank": 7, "flagship": False},
    {"model": "premE", "provider": "vW", "upstream_model": "deepseek-v3", "model_family": "deepseek", "tier": "premium", "rank": 8, "flagship": False},
]


class _Router:
    def __init__(self, routes=None):
        self._routes = routes or _ROUTES

    def routes_info(self):
        rows = [dict(r) for r in self._routes]
        for row in rows:
            row.setdefault(
                "independence_domain",
                "sha256:" + hashlib.sha256(row["provider"].encode()).hexdigest(),
            )
        return rows

    def resolve(self, model):  # noqa: ANN201
        row = next((item for item in self.routes_info() if item["model"] == model), None)
        return trusted_route(row) if row else None


def _patch_pool(monkeypatch, tbl=None):
    """掌控 pool_snapshot 的数据来源：preset_meta（modality/skills/tool_capable）+ 战绩置空。"""
    tbl = tbl or {"cheapA": True, "premB": True, "premC": True, "premD": True, "premE": True}

    def fake_meta(model_id):
        return {
            "rank": 0, "flagship": False,
            "tool_capable": tbl.get(model_id, True),
            "skills": ["code"], "modality": "chat",
        }

    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)
    monkeypatch.setattr(sb, "summary_line", lambda models, kind: "")


def _patch_planner(monkeypatch, replies):
    """让 conductor 里的 chat_with_fallback（planner 出 DAG）按 `replies` 逐次返回。

    replies 可为 str（单次）或 list（多次，逐次消费；用尽后重复最后一个）。
    每个元素是 planner 的原始回复文本（通常是 DAG JSON，可含话痨/围栏）。
    """
    seq = [replies] if isinstance(replies, str) else list(replies)

    async def fake_chat(router, req):
        content = seq.pop(0) if len(seq) > 1 else (seq[0] if seq else "{}")
        route = router.resolve(req.model)
        return (
            {
                "model": route.upstream_model,
                "choices": [{"message": {"content": content}}],
            },
            req.model,
            route,
        )

    monkeypatch.setattr(cd, "chat_with_fallback", fake_chat)


def _patch_nodes(monkeypatch, sink=None, *, captured_tasks=None):
    """节点执行：conductor.run_tool_agent 记录被点模型 + 收到的 task 文本，返回标准 dict。"""
    async def fake_run(router, model, task, **kw):
        if sink is not None:
            sink.append(model)
        if captured_tasks is not None:
            captured_tasks.append((model, task))
        return with_author_receipt(router, model, {
            "reply": f"{model}的产出", "steps": 2, "model": model,
            "usage": {"total_tokens": 4}, "tool_log": [f"write_file({model})"],
            "file_changes": [f"f_{model}.txt"], "media": [],
        })

    monkeypatch.setattr(cd, "run_tool_agent", fake_run)


def _patch_verify(monkeypatch, verdicts):
    """终审：按 `verdicts` 返回带 actual served identity 的 observation。

    verdicts 是 bool 列表（True=PASS）；用尽后重复最后一个。
    """
    seq = list(verdicts)

    async def fake_verify(router, reviewer, task, plan, result):
        ok = seq.pop(0) if len(seq) > 1 else seq[0]
        route = next(row for row in router.routes_info() if row["model"] == reviewer)
        verdict = "PASS" if ok else "FAIL"
        candidate = str(result.get("reply") or "")
        invocation_route = router.resolve(reviewer)
        return oa.review_observation(
            router,
            requested_model=reviewer,
            served_model=reviewer,
            route=invocation_route,
            response={
                "model": route["upstream_model"],
                "choices": [{"message": {"content": verdict}}],
            },
            verdict=verdict,
            reviewed_output=candidate,
            provider_provenance=trusted_review_provenance(
                requested_model=reviewer,
                actual_model=reviewer,
                route=invocation_route,
                verdict=verdict,
                reviewed_output=candidate,
            ),
            expected_provider_request_sha256=trusted_review_request_sha256(
                actual_model=reviewer,
                reviewed_output=candidate,
            ),
        )

    async def fake_summary_or_synthesis(router, model, prompt):  # noqa: ANN001
        route = router.resolve(model)
        marker = "当前草稿：\n"
        if marker in prompt:
            content = prompt.split(marker, 1)[1].split(
                "\n\n合格的外部互审结果", 1
            )[0]
        else:
            content = "合成后的统一答案"
        return content, model, route, {"model": route.upstream_model}

    monkeypatch.setattr(oa, "_verify", fake_verify)
    monkeypatch.setattr(oa, "_llm_observed_response", fake_summary_or_synthesis)


def _dag_json(model_id, subtasks, access_list) -> str:
    return json.dumps({"model_id": model_id, "subtasks": subtasks, "access_list": access_list})


# ══════════════════════════════ plan_workflow ══════════════════════════════


async def test_plan_workflow_parses_valid_dag(monkeypatch):
    """planner 产出合法三平行列表 → 解析并规整返回。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(
        ["premB", "premC", "cheapA"],
        ["查资料", "写实现", "整合润色"],
        [[], [0], [0, 1]],
    ))
    dag = await cd.plan_workflow(_Router(), "做一个复杂功能", task_kind="code")
    assert dag is not None
    assert dag["model_id"] == ["premB", "premC", "cheapA"]
    assert dag["access_list"] == [[], [0], [0, 1]]
    assert len(dag["subtasks"]) == 3


async def test_plan_workflow_wrapped_in_fence_and_prose(monkeypatch):
    """planner 把 JSON 包在 ```json 围栏 + 前后废话里 → _extract_json_obj 仍能抽出并解析。"""
    _patch_pool(monkeypatch)
    body = _dag_json(["premB", "premC"], ["A", "B"], [[], [0]])
    _patch_planner(monkeypatch, f"好的，这是计划：\n```json\n{body}\n```\n希望有用。")
    dag = await cd.plan_workflow(_Router(), "任务", task_kind="code")
    assert dag is not None
    assert dag["model_id"] == ["premB", "premC"]


async def test_plan_workflow_forward_ref_retry_then_fixed(monkeypatch):
    """首版含前向引用（access_list[1] 引用了 2，2>1 违规）→ 带违规说明重试 → 第二版修好。"""
    _patch_pool(monkeypatch)
    bad = _dag_json(["premB", "premC", "cheapA"], ["a", "b", "c"], [[], [2], [0]])   # 第1步引用2：前向引用
    good = _dag_json(["premB", "premC", "cheapA"], ["a", "b", "c"], [[], [0], [0, 1]])
    _patch_planner(monkeypatch, [bad, good])
    dag = await cd.plan_workflow(_Router(), "任务", task_kind="code")
    assert dag is not None
    assert dag["access_list"] == [[], [0], [0, 1]]   # 采用了修好的第二版


async def test_plan_workflow_two_bad_returns_none(monkeypatch):
    """两次都违规（长度不等）→ 返回 None（调用方退化）。"""
    _patch_pool(monkeypatch)
    bad = _dag_json(["premB", "premC"], ["only-one"], [[], [0]])   # subtasks 长度=1 ≠ 2
    _patch_planner(monkeypatch, [bad, bad])
    dag = await cd.plan_workflow(_Router(), "任务", task_kind="code")
    assert dag is None


async def test_plan_workflow_out_of_pool_model_substituted(monkeypatch):
    """model_id 含池外/幻觉模型『gpt-999』→ 同档近似替代为池内 tool_capable 模型，不判违规。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(
        ["gpt-999", "premC"], ["a", "b"], [[], [0]],
    ))
    dag = await cd.plan_workflow(_Router(), "任务", task_kind="code")
    assert dag is not None
    assert dag["model_id"][0] in {"cheapA", "premB", "premC"}   # 被替换成池内模型
    assert dag["model_id"][0] != "gpt-999"
    assert dag["model_id"][1] == "premC"


async def test_plan_workflow_t_too_large_returns_none(monkeypatch):
    """步数 T 超过上限（7 > 6）两次 → None。"""
    _patch_pool(monkeypatch)
    big = _dag_json(["premB"] * 7, ["x"] * 7, [[]] + [[0]] * 6)
    _patch_planner(monkeypatch, [big, big])
    dag = await cd.plan_workflow(_Router(), "任务", task_kind="code")
    assert dag is None


# ══════════════════════════════ run_conductor_agent ══════════════════════════════


async def test_conductor_layered_parallel_execution(monkeypatch):
    """access_list [[],[],[0,1]] → 节点0/1 同层（并行），节点2 依赖二者在末层。

    验证分层正确：末层只有节点2（单节点，reply 即主答案）；三节点都被执行。
    """
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(
        ["premB", "premC", "cheapA"],
        ["并行A", "并行B", "汇总"],
        [[], [], [0, 1]],
    ))
    workers: list[str] = []
    _patch_nodes(monkeypatch, workers)
    _patch_verify(monkeypatch, [True])

    # 直接验证分层：节点0/1 无依赖同层，节点2 依赖 0、1 → 独占末层。
    layers = cd._topo_layers([[], [], [0, 1]])
    assert layers == [[0, 1], [2]]

    res = await cd.run_conductor_agent(
        _Router(), "复杂任务并行拆解", workdir=str(workspace_root())
    )

    assert res["mode"] == "conductor"
    assert res["reviewed"] is True
    assert res["verified"] is False
    assert res["outcome"] == "completed_unverified"
    assert set(workers) == {"premB", "premC", "cheapA"}   # 三节点都跑了
    assert res["reply"] == "cheapA的产出"                  # 末层单节点（节点2=cheapA）reply 为主答案
    assert res["dag"]["access_list"] == [[], [], [0, 1]]


async def test_conductor_context_passed_to_dependents(monkeypatch):
    """上下文传递：节点1 依赖节点0（access [[],[0]]）→ 节点1 的 task 里应含节点0 的产出摘要。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(
        ["premB", "premC"], ["先做基础", "在基础上扩展"], [[], [0]],
    ))
    captured: list[tuple] = []
    _patch_nodes(monkeypatch, captured_tasks=captured)
    _patch_verify(monkeypatch, [True])

    await cd.run_conductor_agent(_Router(), "两步依赖任务", workdir=str(workspace_root()))

    # 节点1（premC）收到的 task 应含「前序产出 #0」+ 节点0（premB）的产出。
    node1 = next(t for (m, t) in captured if m == "premC")
    assert "前序产出 #0" in node1
    assert "premB的产出" in node1
    # 节点0（premB）无前序，task 里不应有「前序产出」字样。
    node0 = next(t for (m, t) in captured if m == "premB")
    assert "前序产出" not in node0


async def test_conductor_verify_fail_triggers_replan(monkeypatch):
    """终审首轮 FAIL → 带评语重规划一轮 → 第二版 DAG 执行 → 二审 PASS。rounds=2。"""
    _patch_pool(monkeypatch)
    dag1 = _dag_json(["premB"], ["初版"], [[]])
    dag2 = _dag_json(["premC"], ["改进版"], [[]])
    _patch_planner(monkeypatch, [dag1, dag2])   # 首次规划 dag1；重规划得 dag2
    workers: list[str] = []
    _patch_nodes(monkeypatch, workers)
    _patch_verify(monkeypatch, [False, True])   # 首审 FAIL、二审 PASS

    res = await cd.run_conductor_agent(
        _Router(), "需要重规划的复杂任务", workdir=str(workspace_root())
    )

    assert res["rounds"] == 2
    # The first qualified rejection is part of the replan lineage.  After the
    # second draft PASS and initiator summary, all four registered strong
    # families are already contributors, so there is no fifth independent vote.
    assert res["reviewed"] is False
    assert res["verified"] is False
    assert res["outcome"] == "partial"
    assert res["_route"]["post_summary_review_error"] == (
        "no_strong_independent_final_reviewer"
    )
    assert workers == ["premB", "premC"]        # 两版各执行一次
    assert res["dag"]["model_id"] == ["premC"]  # 最终采用的是重规划后的 DAG


async def test_conductor_wall_cap_skips_verify_and_replan(monkeypatch):
    """A node exhausting the shared wall budget terminates the whole DAG round."""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(["premB"], ["耗尽预算"], [[]]))
    calls = {"worker": 0, "verify": 0}

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

    monkeypatch.setattr(cd, "run_tool_agent", fake_worker)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    result = await cd.run_conductor_agent(
        _Router(), "共享预算任务", workdir=str(workspace_root())
    )

    assert calls == {"worker": 1, "verify": 0}
    assert result["rounds"] == 1
    assert result["verified"] is False
    assert result["stopped_reason"] == "wall_cap"


async def test_conductor_planner_dead_falls_back_to_trinity(monkeypatch):
    """plan_workflow 拿不到 DAG（planner 出的全是垃圾）→ 原样退化 run_trinity_agent。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, "这不是 JSON，只是一段废话")   # 解析不出 → 两次都 None

    called = {"trinity": False}

    async def fake_trinity(router, task, **kw):
        called["trinity"] = True
        return {"reply": "trinity产出", "mode": "trinity", "verified": True,
                "steps": 1, "model": "premB", "usage": {}, "tool_log": [],
                "file_changes": [], "media": [], "turns": 1, "rounds": 1}

    monkeypatch.setattr(oa, "run_trinity_agent", fake_trinity)

    res = await cd.run_conductor_agent(_Router(), "复杂任务", workdir=str(workspace_root()))

    assert called["trinity"] is True
    assert res["mode"] == "trinity"
    assert res["reply"] == "trinity产出"


async def test_conductor_multi_tail_synthesizes(monkeypatch):
    """末层多节点（access [[],[]] → 两节点都在末层）→ planner 合成一段主答案（1 次 LLM）。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(
        ["premB", "premC"], ["产出X", "产出Y"], [[], []],
    ))
    _patch_nodes(monkeypatch)
    _patch_verify(monkeypatch, [True])

    synth_called = {"n": 0}

    async def fake_synth_llm(router, model, prompt):
        route = router.resolve(model)
        if "你是本任务的发起者" in prompt:
            return (
                "合成后的统一答案",
                model,
                route,
                {"model": route.upstream_model},
            )
        synth_called["n"] += 1
        return (
            "合成后的统一答案",
            model,
            route,
            {"model": route.upstream_model},
        )

    monkeypatch.setattr(oa, "_llm_observed_response", fake_synth_llm)

    res = await cd.run_conductor_agent(
        _Router(), "两路并行且都是末层", workdir=str(workspace_root())
    )

    layers = cd._topo_layers([[], []])
    assert layers == [[0, 1]]                       # 两节点同为末层
    assert synth_called["n"] == 1                   # 合成恰好调 1 次
    assert res["reply"] == "合成后的统一答案"
    assert res["model"] == "premC"
    assert res["actual_model"] == "premC"
    assert res["_route"]["final_model"] == "premC"
    assert res["_route"]["final_route_receipt"]["route_receipt_version"] == 1


async def test_conductor_synthesis_failover_reports_actual_final_author(monkeypatch):
    """Requested planner cannot hide the actual model that authored synthesis."""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(
        ["premB", "premC"], ["产出X", "产出Y"], [[], []],
    ))
    _patch_nodes(monkeypatch)
    _patch_verify(monkeypatch, [True])

    async def fake_synth_llm(router, model, prompt):  # noqa: ANN001
        assert model == "premC"
        route = router.resolve("premD")
        response = {
            "model": route.upstream_model,
            "choices": [{"message": {"content": "由故障转移模型合成"}}],
        }
        call = trusted_chat_result(
            request_payload={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
            },
            response=response,
            requested_model=model,
            actual_model="premD",
            route=route,
        )
        return oa._ObservedModelResponse(
            "由故障转移模型合成",
            "premD",
            route,
            response,
            getattr(call, "provenance", None),
        )

    monkeypatch.setattr(oa, "_llm_observed_response", fake_synth_llm)

    result = await cd.run_conductor_agent(
        _Router(), "多尾合成故障转移", workdir=str(workspace_root())
    )

    assert result["reply"] == "由故障转移模型合成"
    assert result["model"] == "premD"
    assert result["actual_model"] == "premD"
    assert result["_route"]["final_model"] == "premD"
    receipt = result["_route"]["final_route_receipt"]
    assert receipt["requested_model"] == "premC"
    assert receipt["actual_model"] == "premD"
    assert receipt["model"] == "premD"
    assert receipt["route_receipt_version"] == 1
    assert result["_route"]["post_summary_review_error"] == (
        "initiator_summary_actual_mismatch"
    )
    assert result["reviewed"] is False


async def test_conductor_return_dict_shape_complete(monkeypatch):
    """返回 dict 键完整：与 run_trinity_agent 同构 + conductor 元信息。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(["premB", "premC"], ["a", "b"], [[], [0]]))
    _patch_nodes(monkeypatch)
    _patch_verify(monkeypatch, [True])

    res = await cd.run_conductor_agent(_Router(), "复杂任务", workdir=str(workspace_root()))

    for key in ("reply", "steps", "model", "usage", "tool_log", "file_changes",
                "media", "mode", "dag", "verified", "rounds", "_route"):
        assert key in res, f"缺少返回键 {key}"
    assert res["mode"] == "conductor"
    assert res["reviewed"] is True
    assert res["verified"] is False
    assert res["rounds"] == 1
    assert isinstance(res["dag"], dict) and "model_id" in res["dag"]
    # 累积正确：两节点各贡献 usage/tool_log/file_changes。
    assert res["usage"]["total_tokens"] == 8            # 4 + 4
    assert len(res["tool_log"]) == 2
    assert len(res["file_changes"]) == 2
    assert res["_route"]["mode"] == "conductor"


async def test_conductor_records_win_on_pass(monkeypatch):
    """终审 PASS → 全部参与模型记 win。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(["premB", "premC"], ["a", "b"], [[], [0]]))
    _patch_nodes(monkeypatch)
    _patch_verify(monkeypatch, [True])

    recorded: list[tuple] = []
    monkeypatch.setattr(cd.scoreboard, "record",
                        lambda model, kind, win: recorded.append((model, kind, win)))

    await cd.run_conductor_agent(_Router(), "复杂任务", workdir=str(workspace_root()))

    wins = {m for (m, k, w) in recorded if w is True}
    assert "premB" in wins and "premC" in wins


async def test_conductor_records_loss_on_final_fail(monkeypatch):
    """终审始终 FAIL（重规划后仍不过）→ 末层模型记 loss；返回 verified=False 尽力而为。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, [
        _dag_json(["premB", "premC"], ["a", "b"], [[], [0]]),   # 首版
        _dag_json(["premB", "premC"], ["a2", "b2"], [[], [0]]),  # 重规划版
    ])
    _patch_nodes(monkeypatch)
    _patch_verify(monkeypatch, [False, False])   # 两轮都 FAIL

    recorded: list[tuple] = []
    monkeypatch.setattr(cd.scoreboard, "record",
                        lambda model, kind, win: recorded.append((model, kind, win)))

    res = await cd.run_conductor_agent(
        _Router(), "始终不过的复杂任务", workdir=str(workspace_root())
    )

    assert res["verified"] is False
    assert res["rounds"] == 2                     # 首轮 + 重规划一轮
    losses = {m for (m, k, w) in recorded if w is False}
    assert "premC" in losses                      # 末层模型（节点1=premC）记 loss


async def test_conductor_node_failure_does_not_crash_dag(monkeypatch):
    """单节点 run_tool_agent 抛异常 → 该节点产出记「(节点失败:…)」，DAG 继续、不整体崩。"""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(["premB", "premC"], ["会炸的一步", "正常步"], [[], [0]]))
    _patch_verify(monkeypatch, [True])

    async def fake_run(router, model, task, **kw):
        if model == "premB":
            raise RuntimeError("模拟节点崩溃")
        return with_author_receipt(router, model, {
            "reply": f"{model}的产出", "steps": 1, "model": model, "usage": {},
            "tool_log": [], "file_changes": [], "media": [],
        })

    monkeypatch.setattr(cd, "run_tool_agent", fake_run)

    res = await cd.run_conductor_agent(
        _Router(), "含崩溃节点的任务", workdir=str(workspace_root())
    )

    # 没有抛出异常，整个 DAG 跑完，末层（premC）正常产出为主答案。
    assert res["mode"] == "conductor"
    assert res["reply"] == "premC的产出"


async def test_conductor_all_node_errors_never_report_requested_model_as_actual(
    monkeypatch,
):
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(["premB"], ["会失败"], [[]]))
    _patch_verify(monkeypatch, [True])

    async def fake_run(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("all nodes failed")

    monkeypatch.setattr(cd, "run_tool_agent", fake_run)

    result = await cd.run_conductor_agent(
        _Router(), "全部节点失败", workdir=str(workspace_root())
    )

    assert result["reply"] == "节点执行失败；内部详情已隐藏，编排将按失败状态继续收口。"
    assert result["model"] is None
    assert result["actual_model"] is None
    assert result["actual_models"] == []
    assert result["_route"]["final_model"] is None
    assert result["_route"]["final_author_models"] == []
    assert result["_route"]["final_output_kind"] == "system_placeholder"


async def test_conductor_review_failover_to_actual_node_author_has_zero_vote(monkeypatch):
    """DAG requested ids cannot hide that node and reviewer actually used one model."""
    _patch_pool(monkeypatch)
    _patch_planner(monkeypatch, _dag_json(["cheapA"], ["执行"], [[]]))
    monkeypatch.setattr(cd, "_MAX_REPLAN", 0)

    async def fake_node(router, model, task, **kwargs):  # noqa: ANN001
        assert model == "cheapA"
        return with_author_receipt(router, "premD", {
            "reply": "实际由 premD 生成",
            "steps": 1,
            "model": "premD",
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }, requested_model="cheapA")

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        candidate = str(result.get("reply") or "")
        invocation_route = router.resolve("premD")
        return oa.review_observation(
            router,
            requested_model=reviewer,
            served_model="premD",
            route=invocation_route,
            response={
                "model": "gemini-2.5-pro",
                "choices": [{"message": {"content": "PASS"}}],
            },
            verdict="PASS",
            reviewed_output=candidate,
                provider_provenance=trusted_review_provenance(
                requested_model=reviewer,
                actual_model="premD",
                route=invocation_route,
                verdict="PASS",
                    reviewed_output=candidate,
                ),
                expected_provider_request_sha256=trusted_review_request_sha256(
                    actual_model="premD",
                    reviewed_output=candidate,
                ),
            )

    monkeypatch.setattr(cd, "run_tool_agent", fake_node)
    monkeypatch.setattr(oa, "_verify", fake_verify)

    result = await cd.run_conductor_agent(
        _Router(), "复杂 DAG", workdir=str(workspace_root())
    )

    assert result["reviewed"] is False
    assert result["verified"] is False
    assert result["_route"]["reviewer_vote_weight"] == 0
    assert result["_route"]["review_reason"] == "reviewer_is_lineage_contributor"
