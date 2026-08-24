"""F3 TRINITY 三角色轮转 + 接线：

- 正常 thinker→worker→verifier ACCEPT 流；
- verifier REJECT → 继续轮转直到 ACCEPT；
- 点将官全程 None → 规则兜底流（worker→verifier）仍能走完；
- K 用尽（一直 REJECT）→ 优雅收尾，返回尽力而为结果并标 verified=False；
- 记账：verifier 结论对「本轮之前干活的 worker」调 scoreboard.record；
- 接线：run_orchestrated_agent 复杂任务 + 点将官可用 → 走 TRINITY；探针 None → 退回既有编排流。

版本无关手法：假 router 只实现 routes_info；直接 monkeypatch coordinator.pick_next 精确控制
点将序列，monkeypatch run_tool_agent（worker 产出）与 chat_with_fallback（thinker 文本 / verifier
判词），monkeypatch scoreboard.record 记账断言。均不碰真 catalog/sqlite/LLM。
"""

from __future__ import annotations

import hashlib
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


@pytest.fixture(autouse=True)
def _isolate_scoreboard(monkeypatch, tmp_path):
    """把记分牌库指到本测试专属 tmp（照 test_scoreboard 隔离法）：TRINITY 的 F6 记账钩子会写库、
    批6① 首轮点将短路会读库；隔离后每个测试各自一份空库，假模型名不污染真库、行为确定。"""
    db = tmp_path / "scoreboard.db"
    monkeypatch.setattr(sb, "_db_path", lambda: str(db))
    sb.reset()
    yield
    sb.reset()


# 便宜 + 四个不同厂 premium；thinker+worker 占两厂、初审再占一厂后，
# 仍须保留第四个强身份给“发起者总结”的第二次独立终审。
_ROUTES = [
    {"model": "cheapA", "provider": "vX", "upstream_model": "qwen-turbo", "model_family": "alibaba-qwen", "tier": "cheap", "rank": 1, "flagship": False},
    {"model": "premB", "provider": "vX", "upstream_model": "gpt-4o", "model_family": "openai", "tier": "premium", "rank": 5, "flagship": False},
    {"model": "premC", "provider": "vY", "upstream_model": "claude-sonnet-4-6", "model_family": "anthropic", "tier": "premium", "rank": 2, "flagship": False},
    {"model": "premD", "provider": "vZ", "upstream_model": "gemini-2.5-pro", "model_family": "google-gemini", "tier": "premium", "rank": 6, "flagship": False},
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

    def list_models(self):
        return [{"id": r["model"], "owned_by": r["provider"], "tier": r["tier"],
                 "modality": "chat", "description": r["model"]} for r in self._routes]

    def resolve(self, model):
        row = next((item for item in self.routes_info() if item["model"] == model), None)
        if row is None:
            return None
        return trusted_route(row)


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


def _patch_meta(monkeypatch, tbl=None):
    tbl = tbl or {"cheapA": True, "premB": True, "premC": True, "premD": True, "premE": True}

    def fake_meta(model_id):
        return {"rank": 0, "flagship": False, "tool_capable": tbl.get(model_id, True)}

    monkeypatch.setattr(oa, "preset_meta", fake_meta)


def _script_casts(monkeypatch, casts):
    """让 coordinator.pick_next 按 `casts` 列表逐轮返回（用尽后返回 None）。"""
    seq = list(casts)

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        return seq.pop(0) if seq else None

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)


def _patch_worker(monkeypatch, sink=None, *, stopped=None):
    """worker：run_tool_agent 记录被点模型、返回带 reply/tool_log 的标准 dict。"""
    async def fake_run(router, model, task, **kw):
        if sink is not None:
            sink.append(model)
        out = with_author_receipt(router, model, {
            "reply": f"{model}干完了", "steps": 2, "model": model, "usage": {"total_tokens": 5},
            "tool_log": [f"write_file({model})"], "file_changes": [], "media": [],
        })
        sr = stopped(model) if callable(stopped) else stopped
        if sr:
            out["stopped_reason"] = sr
        return out

    monkeypatch.setattr(oa, "run_tool_agent", fake_run)


def _patch_llm(monkeypatch, verdicts=None, *, think_text="思路：先做A再做B"):
    """thinker 文本 + verifier 判词都走 chat_with_fallback；按 prompt 是否含审核关键词分流。

    verdicts：verifier 判词序列（依次消费，如 ['FAIL:差一步','PASS']）；缺省一律 PASS。
    """
    vseq = list(verdicts or [])

    async def fake_chat(router, req):
        text = req.messages[-1].content
        if "你是本任务的发起者" in text:
            return _chat_reply(router, req, "发起者依据合格互审形成的最终总结")
        if "审核" in text or "达标" in text or "PASS" in text:  # _verify 的提示词特征
            v = vseq.pop(0) if vseq else "PASS"
            return _chat_reply(router, req, v)
        return _chat_reply(router, req, think_text)

    monkeypatch.setattr(oa, "chat_with_fallback", fake_chat)


def _trusted_direct_review(router, requested, served, result, verdict="PASS"):  # noqa: ANN001
    candidate = str(result.get("reply") or "")
    route = router.resolve(served)
    assert route is not None
    response = {
        "model": route.upstream_model,
        "choices": [{"message": {"content": verdict}}],
    }
    return oa.review_observation(
        router,
        requested_model=requested,
        served_model=served,
        route=route,
        response=response,
        verdict=verdict,
        reviewed_output=candidate,
        provider_provenance=trusted_review_provenance(
            requested_model=requested,
            actual_model=served,
            route=route,
            verdict=verdict,
            reviewed_output=candidate,
        ),
        expected_provider_request_sha256=trusted_review_request_sha256(
            actual_model=served,
            reviewed_output=candidate,
        ),
    )


# ────────────────────────────── 正常 thinker→worker→verifier ACCEPT ──────────────────────────────
async def test_trinity_think_work_verify_accept(monkeypatch, tmp_path):
    """点将官依次派 thinker→worker→verifier；verifier ACCEPT → 终止收工。"""
    _patch_meta(monkeypatch)
    _script_casts(monkeypatch, [
        {"model": "premC", "role": "thinker", "instruction": "拆解"},
        {"model": "premB", "role": "worker", "instruction": "动手实现"},
        {"model": "premD", "role": "verifier", "instruction": "审核"},
    ])
    workers: list[str] = []
    _patch_worker(monkeypatch, workers)
    _patch_llm(monkeypatch, verdicts=["看起来完成了\nPASS"])

    res = await oa.run_trinity_agent(_Router(), "重构复杂模块", workdir=str(tmp_path))

    assert res["reviewed"] is True
    assert res["verified"] is False
    assert res["turns"] == 3
    assert res["mode"] == "trinity"
    assert workers == ["premB"]                    # 只有 worker 那轮真干活
    assert res["reply"] == "发起者依据合格互审形成的最终总结"
    assert res["model"] == "premC"                # 发起者总结，不是审核者代写
    assert res["_route"]["initiator_vote_weight"] == 0
    assert res["_route"]["initial_reviewer"] == "premD"
    assert res["_route"]["reviewer"] == "premE"  # 第二次终审必须换独立身份
    roles = [c["role"] for c in res["cast_log"]]
    assert roles == ["thinker", "worker", "verifier"]
    # 累计：file_changes/media/usage 从 worker 汇总
    assert res["usage"]["total_tokens"] == 5
    assert res["tool_log"] == ["write_file(premB)"]


# ────────────────────────────── verifier REJECT → 继续轮转 ──────────────────────────────
async def test_trinity_reject_then_continue_to_accept(monkeypatch, tmp_path):
    """verifier 先 REJECT（评语进 transcript）→ 再派 worker 重做 → 第二次 verifier ACCEPT。"""
    _patch_meta(monkeypatch)
    _script_casts(monkeypatch, [
        {"model": "premB", "role": "worker", "instruction": "做"},
        {"model": "premC", "role": "verifier", "instruction": "审"},
        {"model": "premB", "role": "worker", "instruction": "改进"},
        {"model": "premC", "role": "verifier", "instruction": "复审"},
    ])
    workers: list[str] = []
    _patch_worker(monkeypatch, workers)
    _patch_llm(monkeypatch, verdicts=["FAIL:还差校验", "PASS"])

    res = await oa.run_trinity_agent(_Router(), "实现可扩展系统", workdir=str(tmp_path))

    assert res["reviewed"] is True
    assert res["verified"] is False
    assert res["turns"] == 4                        # worker→verify(REJECT)→worker→verify(ACCEPT)
    assert workers == ["premB", "premB"]            # 干了两轮活
    roles = [c["role"] for c in res["cast_log"]]
    assert roles == ["worker", "verifier", "worker", "verifier"]


# ────────────────────────────── 点将官全程 None → 兜底流仍完成 ──────────────────────────────
async def test_trinity_all_none_falls_back_to_worker_then_verifier(monkeypatch, tmp_path):
    """点将官全程返回 None：第 1 轮兜底 worker（选 tool_capable premium），之后兜底 verifier。

    首轮 worker 兜底选 _pick_tool_capable(premium)=premC(rank2 最强)；下一轮兜底 verifier 走
    _cross_vendor_premium(premC)→不同厂的 premB。verifier PASS → 收工。
    """
    _patch_meta(monkeypatch)
    _script_casts(monkeypatch, [])                  # 永远 None
    workers: list[str] = []
    _patch_worker(monkeypatch, workers)
    _patch_llm(monkeypatch, verdicts=["PASS"])

    res = await oa.run_trinity_agent(_Router(), "分析并重构复杂架构", workdir=str(tmp_path))

    assert res["reviewed"] is True
    assert res["verified"] is False
    assert workers == ["premC"]                     # 首轮兜底 worker = 最强 tool_capable premium
    roles = [c["role"] for c in res["cast_log"]]
    assert roles[0] == "worker"                     # 首轮必是 worker（无产出可验）
    assert "verifier" in roles                      # 之后兜底 verifier
    assert all(c["fallback"] for c in res["cast_log"])  # 全是规则兜底


# ────────────────────────────── K 用尽 → 优雅收尾 ──────────────────────────────
async def test_trinity_k_exhausted_graceful(monkeypatch, tmp_path):
    """verifier 一直 REJECT，K=5 轮用尽 → 不再轮转，返回尽力而为结果并标 verified=False。"""
    _patch_meta(monkeypatch)
    # 交替 worker/verifier，点满超过 5 轮；实际只会执行前 5 轮（_TRINITY_MAX_TURNS）。
    casts = []
    for _ in range(6):
        casts.append({"model": "premB", "role": "worker", "instruction": "做"})
        casts.append({"model": "premC", "role": "verifier", "instruction": "审"})
    _script_casts(monkeypatch, casts)
    workers: list[str] = []
    _patch_worker(monkeypatch, workers)
    _patch_llm(monkeypatch, verdicts=["FAIL:不行"] * 10)  # 永远不过

    res = await oa.run_trinity_agent(_Router(), "设计并实现复杂系统", workdir=str(tmp_path))

    assert res["verified"] is False
    assert res["turns"] == oa._TRINITY_MAX_TURNS     # 有界，不无限轮转
    assert res["reply"]                              # 仍返回尽力而为的产出
    assert len(workers) >= 1                          # 至少干过活


# ────────────────────────────── 记账被调用 ──────────────────────────────
async def test_trinity_records_scoreboard_on_verdict(monkeypatch, tmp_path):
    """verifier 结论 → 对『本轮之前干活的 worker』scoreboard.record(win/loss)。"""
    _patch_meta(monkeypatch)
    _script_casts(monkeypatch, [
        {"model": "premB", "role": "worker", "instruction": "做"},
        {"model": "premC", "role": "verifier", "instruction": "审"},
    ])
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["PASS"])

    recorded: list[tuple] = []
    monkeypatch.setattr(oa.scoreboard, "record",
                        lambda model, kind, win: recorded.append((model, kind, win)))

    res = await oa.run_trinity_agent(_Router(), "重构复杂算法模块", workdir=str(tmp_path))

    assert res["reviewed"] is True
    assert res["verified"] is False
    # verifier ACCEPT → 给干活的 premB 记一场 win（task_kind 来自 classify，此任务含"重构/算法"→reason 或 code）
    assert any(m == "premB" and win is True for (m, kind, win) in recorded)


async def test_trinity_records_loss_on_reject(monkeypatch, tmp_path):
    """verifier REJECT → 给 worker 记 loss。"""
    _patch_meta(monkeypatch)
    _script_casts(monkeypatch, [
        {"model": "premB", "role": "worker", "instruction": "做"},
        {"model": "premC", "role": "verifier", "instruction": "审"},
        {"model": "premC", "role": "verifier", "instruction": "审"},  # 占位，避免立即 None 兜底扰乱
    ])
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["FAIL:缺", "FAIL:仍缺"])

    recorded: list[tuple] = []
    monkeypatch.setattr(oa.scoreboard, "record",
                        lambda model, kind, win: recorded.append((model, kind, win)))

    await oa.run_trinity_agent(_Router(), "分析并重构复杂系统", workdir=str(tmp_path))

    assert any(m == "premB" and win is False for (m, kind, win) in recorded)


# ────────────────────────────── 护栏：worker 连败 → transcript 提示升级 ──────────────────────────────
async def test_trinity_worker_repeated_failure_hints_escalation(monkeypatch, tmp_path):
    """同一 worker 连续被 REJECT 2 次 → transcript 里出现『换更强模型』提示（点将官自然升级）。

    用打桩 pick_next 捕获它每轮收到的 transcript，断言护栏提示已注入。
    """
    _patch_meta(monkeypatch)
    seen_transcripts: list[str] = []
    plan = [
        {"model": "premB", "role": "worker", "instruction": "做"},
        {"model": "premC", "role": "verifier", "instruction": "审"},
        {"model": "premB", "role": "worker", "instruction": "再做"},
        {"model": "premC", "role": "verifier", "instruction": "再审"},
        {"model": "premB", "role": "worker", "instruction": "三做"},
    ]
    seq = list(plan)

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        seen_transcripts.append(transcript)
        return seq.pop(0) if seq else None

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["FAIL:一", "FAIL:二", "FAIL:三"])

    await oa.run_trinity_agent(_Router(), "实现复杂可扩展系统架构", workdir=str(tmp_path))

    # 两次 REJECT 后，某轮点将时 transcript 应已含护栏升级提示。
    assert any("换更强模型" in t for t in seen_transcripts)


# ────────────────────────────── 接线：探针成功 → 走 TRINITY ──────────────────────────────
async def test_wiring_complex_task_enters_trinity(monkeypatch, tmp_path):
    """run_orchestrated_agent 复杂任务 + 点将官探针可用 → 分流到 run_trinity_agent（mode=trinity）。"""
    _patch_meta(monkeypatch)
    # 关掉战绩短路（本用例专测点将官探针路径，不让战绩短路抢占首轮 → 与真实 db 状态解耦）。
    monkeypatch.setattr(oa.coordinator, "pick_by_record", lambda router, tk, **kw: None)

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        # 探针 + 首轮点 worker，第二轮 verifier，之后 None
        if "worker(" in transcript or "thinker(" in transcript:
            return {"model": "premC", "role": "verifier", "instruction": "审"}
        return {"model": "premB", "role": "worker", "instruction": "做"}

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["PASS"])

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构这个复杂系统架构", workdir=str(tmp_path), fast_first=False
    )
    assert res.get("mode") == "trinity"
    assert res["_route"]["mode"] == "trinity"
    assert res["reviewed"] is True
    assert res["verified"] is False


async def test_wiring_record_shortcircuit_skips_probe_pick_next(monkeypatch, tmp_path):
    """战绩短路（批6①）：pick_by_record 命中 → 首轮探针不发 pick_next（0 点将官调用），
    命中结果直用为 first_cast，且 cast_log 首轮带 by=record；轮转中仍用 pick_next。"""
    _patch_meta(monkeypatch)

    # 战绩短路：命中冠军 premC 当 worker。
    def fake_by_record(router, task_kind, *, need_tools=False, min_games=3):
        return {"model": "premC", "role": "worker", "instruction": "", "by": "record"}

    monkeypatch.setattr(oa.coordinator, "pick_by_record", fake_by_record)

    # pick_next 计数：探针那次**不该**调它；第二轮 verifier 才调一次。
    pick_calls = {"n": 0}

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        pick_calls["n"] += 1
        return {"model": "premC", "role": "verifier", "instruction": "审"}

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["PASS"])

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构这个复杂系统架构", workdir=str(tmp_path), fast_first=False
    )
    assert res.get("mode") == "trinity"
    assert res["reviewed"] is True
    assert res["verified"] is False
    # 首轮由战绩短路承担（by=record），worker=premC，未走 pick_next；
    first = res["cast_log"][0]
    assert first["model"] == "premC" and first["role"] == "worker" and first["turn"] == 1
    assert first.get("by") == "record"
    # pick_next 只在第二轮（verifier）被调 1 次——探针那次被战绩短路跳过了。
    assert pick_calls["n"] == 1


async def test_wiring_neural_pick_skips_probe_pick_next(monkeypatch, tmp_path):
    """神经点将（批8③）：战绩未命中 → pick_neural 命中 → 首轮探针不发 pick_next（0 点将官调用），
    命中结果直用为 first_cast，cast_log 首轮带 by=neural；轮转中仍用 pick_next。"""
    import orchestrator.neural_coordinator as ncmod

    _patch_meta(monkeypatch)
    # 战绩短路未命中（让神经点将接棒承担首轮）。
    monkeypatch.setattr(oa.coordinator, "pick_by_record", lambda router, tk, **kw: None)
    # 神经点将命中 premC 当 worker（带 by=neural）。
    monkeypatch.setattr(
        ncmod, "pick_neural",
        lambda router, transcript, *, task_kind="general", need_tools=False: {
            "model": "premC", "role": "worker", "instruction": "", "by": "neural"},
    )

    pick_calls = {"n": 0}

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        pick_calls["n"] += 1
        return {"model": "premC", "role": "verifier", "instruction": "审"}

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["PASS"])

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构这个复杂系统架构", workdir=str(tmp_path), fast_first=False
    )
    assert res.get("mode") == "trinity"
    assert res["reviewed"] is True
    assert res["verified"] is False
    # 首轮由神经点将承担（by=neural），worker=premC，未走 pick_next 探针；
    first = res["cast_log"][0]
    assert first["model"] == "premC" and first["role"] == "worker" and first["turn"] == 1
    assert first.get("by") == "neural"
    # pick_next 只在第二轮（verifier）被调 1 次——探针那次被神经点将跳过了。
    assert pick_calls["n"] == 1


async def test_wiring_neural_miss_falls_through_to_pick_next(monkeypatch, tmp_path):
    """神经点将未命中（pick_neural 返回 None）→ 照旧走 pick_next 探针，行为不变。"""
    import orchestrator.neural_coordinator as ncmod

    _patch_meta(monkeypatch)
    monkeypatch.setattr(oa.coordinator, "pick_by_record", lambda router, tk, **kw: None)
    monkeypatch.setattr(
        ncmod, "pick_neural",
        lambda router, transcript, *, task_kind="general", need_tools=False: None,  # 未命中
    )

    pick_calls = {"n": 0}

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        pick_calls["n"] += 1
        if "worker(" in transcript or "thinker(" in transcript:
            return {"model": "premC", "role": "verifier", "instruction": "审"}
        return {"model": "premB", "role": "worker", "instruction": "做"}

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["PASS"])

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构这个复杂系统架构", workdir=str(tmp_path), fast_first=False
    )
    assert res.get("mode") == "trinity"
    # 神经未命中 → 探针发了 pick_next（≥1 次），首轮 worker 是探针给的 premB、无 by 键。
    assert pick_calls["n"] >= 1
    assert res["cast_log"][0]["model"] == "premB"
    assert "by" not in res["cast_log"][0]


async def test_wiring_record_miss_uses_probe_pick_next(monkeypatch, tmp_path):
    """战绩未命中（pick_by_record 返回 None）→ 照旧走 pick_next 探针，行为不变。"""
    _patch_meta(monkeypatch)
    monkeypatch.setattr(
        oa.coordinator, "pick_by_record",
        lambda router, task_kind, **kw: None,  # 未命中
    )

    pick_calls = {"n": 0}

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        pick_calls["n"] += 1
        if "worker(" in transcript or "thinker(" in transcript:
            return {"model": "premC", "role": "verifier", "instruction": "审"}
        return {"model": "premB", "role": "worker", "instruction": "做"}

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    _patch_worker(monkeypatch, [])
    _patch_llm(monkeypatch, verdicts=["PASS"])

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构这个复杂系统架构", workdir=str(tmp_path), fast_first=False
    )
    assert res.get("mode") == "trinity"
    # 未命中 → 探针发了 pick_next（≥1 次），首轮 worker 是探针给的 premB、无 by 键。
    assert pick_calls["n"] >= 1
    assert res["cast_log"][0]["model"] == "premB"
    assert "by" not in res["cast_log"][0]


async def test_wiring_probe_none_falls_back_to_legacy_flow(monkeypatch, tmp_path):
    """点将官探针返回 None → 不进 TRINITY，退回既有 plan→execute→verify 流（保持老行为）。"""
    _patch_meta(monkeypatch)
    # 战绩短路也返回 None（两条首轮点将来源都失效）→ 才该退回既有流；与真实 db 状态解耦。
    monkeypatch.setattr(oa.coordinator, "pick_by_record", lambda router, tk, **kw: None)

    async def always_none(router, transcript, *, task_kind="general", need_tools=False):
        return None

    monkeypatch.setattr(oa.coordinator, "pick_next", always_none)

    # 老流程用的是 chat_with_fallback 做规划/验证 + run_tool_agent 执行。
    async def fake_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "PASS")
        return _chat_reply(router, req, "1. 步骤\n验收：X")

    ran: list[str] = []

    async def fake_run(router, model, task, **kw):
        ran.append(model)
        return {"reply": "老流程产出", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构这个复杂系统架构", workdir=str(tmp_path), fast_first=False
    )
    # 退回既有流：有 plan、有 fast_path 键、非 trinity 模式
    assert res.get("mode") != "trinity"
    assert res["_route"].get("fast_path") is False
    assert res["plan"] is not None
    assert res["reply"] == "老流程产出"
    assert ran  # 老流程的 run_tool_agent 确实被调用


async def test_wiring_forced_model_skips_trinity(monkeypatch, tmp_path):
    """显式指定 model → 尊重用户选择，不走 TRINITY（即便任务复杂）。"""
    _patch_meta(monkeypatch)

    picked_called = {"n": 0}

    async def fake_pick(router, transcript, *, task_kind="general", need_tools=False):
        picked_called["n"] += 1
        return {"model": "premB", "role": "worker", "instruction": "做"}

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)

    async def fake_chat(router, req):
        text = req.messages[-1].content
        if "独立审核官" in text:
            return _chat_reply(router, req, "PASS")
        return _chat_reply(router, req, "计划")

    async def fake_run(router, model, task, **kw):
        return {"reply": "ok", "steps": 1, "model": model, "usage": {},
                "tool_log": [], "file_changes": [], "media": []}

    monkeypatch.setattr(oa, "chat_with_fallback", fake_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    res = await oa.run_orchestrated_agent(
        _Router(), "分析并重构复杂系统", workdir=str(tmp_path), model="cheapA"
    )
    assert res.get("mode") != "trinity"          # 显式 model 不进 TRINITY
    assert picked_called["n"] == 0                # 连探针都不发（forced 短路）
    assert res["_route"]["forced_model"] is True


async def test_first_cast_skips_duplicate_pick(monkeypatch, tmp_path):
    """免双重点将：传入 first_cast 后，首轮不再调 pick_next（探针结果直用）。"""
    import orchestrator.coordinator as co

    _patch_meta(monkeypatch)
    picks = {"n": 0}

    async def fake_pick(router, transcript, **kw):
        picks["n"] += 1
        return {"model": "premC", "role": "verifier", "instruction": ""}

    async def fake_worker(router, model, task, **kw):
        return with_author_receipt(router, model, {
            "reply": "干完了", "steps": 1, "model": model, "usage": {},
            "tool_log": [], "file_changes": [], "media": [],
        })

    async def fake_verify(router, reviewer, task, plan, result):
        return _trusted_direct_review(router, reviewer, reviewer, result)

    monkeypatch.setattr(co, "pick_next", fake_pick)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "run_tool_agent", fake_worker)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    monkeypatch.setattr(oa.scoreboard, "record", lambda *a, **k: None)
    _patch_llm(monkeypatch)

    res = await oa.run_trinity_agent(
        _Router(), "复杂活", workdir=str(tmp_path),
        first_cast={"model": "premB", "role": "worker", "instruction": "上"},
    )
    # 首轮用 first_cast（0 次 pick），第二轮 verifier 才点了 1 次
    assert picks["n"] == 1
    assert res["reviewed"] is True
    assert res["verified"] is False
    assert res["cast_log"][0]["model"] == "premB" and res["cast_log"][0]["turn"] == 1


async def test_verifier_never_reviews_own_work(monkeypatch, tmp_path):
    """独立性闸：点将官让刚干活的 worker 自己当 verifier → 确定性换成跨厂 premium。"""
    import orchestrator.coordinator as co

    _patch_meta(monkeypatch)
    seen: list[str] = []

    async def fake_pick(router, transcript, **kw):
        # 故意点「刚干活的 premB」当审核官（自己审自己）
        return {"model": "premB", "role": "verifier", "instruction": ""}

    async def fake_worker(router, model, task, **kw):
        return with_author_receipt(router, model, {
            "reply": "干完了", "steps": 1, "model": model, "usage": {},
            "tool_log": [], "file_changes": [], "media": [],
        })

    async def fake_verify(router, reviewer, task, plan, result):
        seen.append(reviewer)
        return _trusted_direct_review(router, reviewer, reviewer, result)

    monkeypatch.setattr(co, "pick_next", fake_pick)
    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "run_tool_agent", fake_worker)
    monkeypatch.setattr(oa, "_verify", fake_verify)
    monkeypatch.setattr(oa.scoreboard, "record", lambda *a, **k: None)
    _patch_llm(monkeypatch)

    res = await oa.run_trinity_agent(
        _Router(), "复杂活", workdir=str(tmp_path),
        first_cast={"model": "premB", "role": "worker", "instruction": "上"},
    )
    assert res["reviewed"] is True
    assert res["verified"] is False
    assert seen == ["premC", "premD"]  # 草稿初审 + 总结终审，均不得是 premB


async def test_trinity_review_failover_to_actual_worker_has_zero_vote(monkeypatch, tmp_path):
    """Reviewer request is independent, but its actual failover target authored the work."""
    _patch_meta(monkeypatch)
    monkeypatch.setattr(oa, "_TRINITY_MAX_TURNS", 2)

    async def fake_pick(router, transcript, **kwargs):  # noqa: ANN001
        return {"model": "premB", "role": "verifier", "instruction": "审"}

    async def fake_worker(router, model, task, **kwargs):  # noqa: ANN001
        assert model == "premB"
        return with_author_receipt(router, "premC", {
            "reply": "实际由 premC 生成",
            "steps": 1,
            "model": "premB",
            "actual_model": "premC",
            "actual_models": ["premC"],
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }, requested_model="premB")

    async def fake_verify(router, reviewer, task, plan, result):  # noqa: ANN001
        assert reviewer == "premB"
        return _trusted_direct_review(router, reviewer, "premC", result)

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "run_tool_agent", fake_worker)
    monkeypatch.setattr(oa, "_verify", fake_verify)

    result = await oa.run_trinity_agent(
        _Router(),
        "复杂活",
        workdir=str(tmp_path),
        first_cast={"model": "premB", "role": "worker", "instruction": "做"},
    )

    assert result["reviewed"] is False
    assert result["verified"] is False
    assert result["_route"]["reviewer_vote_weight"] == 0
    assert result["_route"]["review_reason"] == "reviewer_is_lineage_contributor"
