"""单答模式：smart / cascade / economy / best —— 把一次请求路由到合适的模型。

返回标准 chat.completion 字典 + 额外 `_route` 元信息（用了哪个模型、是否升级）。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from gateway import quota_state
from gateway.catalog import rank_sort_key
from gateway.failover import ChatFallbackResult, chat_with_fallback
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.route_attestation import (
    bind_model_review_call,
    canonical_provider_request_sha256,
)
from gateway.schemas import ChatCompletionRequest
from orchestrator.classify import classify
from orchestrator.review_gate import (
    ReviewDecision,
    ReviewGate,
    review_observation,
    reviewed_output_sha256,
    verdict_pass,
)
from orchestrator.workflows.common import route_receipt

_CHEAP_TIERS = ("cheap", "free")
# 选模型一律「按档位 + rank/flagship（来自 catalog.py 预设 / 连接中心）」动态决定，
# 代码里不写死任何型号名——厂商怎么升版本（v3→v4、5.4→5.5）都不过时。


def pick_model(router: Any, tier: str, *, allow_flagship: bool = False) -> str | None:
    """按档位选模型：premium 档默认排除 flagship 王牌（除非 allow_flagship，自动路由不烧王牌）；
    候选内 flagship 优先、其余按 rank 升序（越小越优先，0/未设排最后）。
    无匹配时兜底任意可用（含 echo，便于测试/降级）。版本无关：不写死任何型号名。"""
    infos = router.routes_info()
    if not infos:
        return None
    if tier == "cheap":
        cands = [r for r in infos if r["model"] != "echo" and r["tier"] in _CHEAP_TIERS]
    elif tier == "premium":
        cands = [
            r for r in infos
            if r["tier"] == "premium" and (allow_flagship or not r.get("flagship"))
        ]
    else:
        cands = [r for r in infos if r["model"] != "echo"]
    if not cands:
        cands = infos  # 兜底（测试环境只有 echo，或某档暂无模型）
    # 额度感知（路由第2步）：冷却中(429/超额)的模型沉底——优先选还有额度的，全冷却时仍兜底给一个。
    cands = sorted(cands, key=lambda r: (
        0 if quota_state.available(r["model"]) else 1,
        0 if r.get("flagship") else 1,
        rank_sort_key(r.get("rank")),
    ))
    return cands[0]["model"]


async def _ask_observed(
    router: Any,
    model_id: str,
    messages: list[dict[str, Any]],
    *,
    role: str,
    wall_deadline: float | None = None,
) -> tuple[dict[str, Any], str, Any]:
    """调用模型并保留备用链实际服务身份。

    常规生成只需要文本，但互审的票权必须绑定 served model/route；
    请求了审核官却回落到发起模型，仍然是自审。
    """
    req = ChatCompletionRequest(model=model_id, messages=messages)  # type: ignore[arg-type]
    with bind_provider_call_scope(role=role):
        if wall_deadline is None:
            call_result = await chat_with_fallback(router, req)
        else:
            remaining = wall_deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError("shared advisory deadline expired")
            call_result = await asyncio.wait_for(
                chat_with_fallback(router, req), timeout=remaining
            )
    res, served, route = call_result
    return ChatFallbackResult(
        res,
        str(served or ""),
        route,
        getattr(call_result, "provenance", None),
    )


async def _ask(
    router: Any,
    model_id: str,
    messages: list[dict[str, Any]],
    *,
    role: str,
) -> dict[str, Any]:
    # 经失败转移：模型满/报错自动转备用链（智能/级联/议会等全模式生效）
    res, _served, _route = await _ask_observed(router, model_id, messages, role=role)
    return res


async def _ask_with_receipt(
    router: Any,
    model_id: str,
    messages: list[dict[str, Any]],
    *,
    role: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    response, served, route = await _ask_observed(
        router, model_id, messages, role=role
    )
    return response, route_receipt(
        requested_model=model_id,
        actual_model=served or None,
        route=route,
        response=response,
    )


def _mode_route(
    mode: str,
    receipt: dict[str, Any],
    receipts: list[dict[str, Any]],
    **extra: Any,
) -> dict[str, Any]:
    return {"mode": mode, **receipt, **extra, "call_receipts": list(receipts)}


def _text(resp: dict[str, Any]) -> str:
    return (resp.get("choices") or [{}])[0].get("message", {}).get("content") or ""


def _verdict_pass(text: str) -> bool:
    """Compatibility name; verdict semantics live exclusively in review_gate."""
    return verdict_pass(text)


def _prompt(messages: list[dict[str, Any]]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            c = m.get("content")
            return c if isinstance(c, str) else str(c)
    return ""


async def run_economy(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    model = pick_model(router, "cheap")
    resp, receipt = await _ask_with_receipt(
        router, model, messages, role="economy.answer"
    )
    resp["_route"] = _mode_route("economy", receipt, [receipt])
    return resp


async def run_best(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    # 最强模式：允许动用 flagship 王牌；取 premium 档最优（偏好在 catalog.py 的 rank/flagship）。
    model = pick_model(router, "premium", allow_flagship=True)
    resp, receipt = await _ask_with_receipt(
        router, model, messages, role="best.answer"
    )
    resp["_route"] = _mode_route("best", receipt, [receipt])
    return resp


async def run_smart(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    c = classify(_prompt(messages))
    tier = "premium" if c["difficulty"] == "hard" else "cheap"
    model = pick_model(router, tier)
    resp, receipt = await _ask_with_receipt(
        router, model, messages, role="smart.answer"
    )
    resp["_route"] = _mode_route("smart", receipt, [receipt], classify=c)
    return resp


async def run_cascade(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    prompt = _prompt(messages)
    cheap = pick_model(router, "cheap")
    receipts: list[dict[str, Any]] = []
    resp, first_receipt = await _ask_with_receipt(
        router, cheap, messages, role="cascade.draft"
    )
    receipts.append(first_receipt)
    ans = _text(resp)
    # 便宜模型自检：答案够不够好
    verdict, verdict_receipt = await _ask_with_receipt(
        router,
        cheap,
        [{"role": "user", "content": f"问题：{prompt}\n\n候选答案：{ans}\n\n该答案是否准确且完整？只回复 OK 或 NEEDS_BETTER。"}],
        role="cascade.self_review",
    )
    receipts.append(verdict_receipt)
    if _verdict_pass(_text(verdict)):
        resp["_route"] = _mode_route(
            "cascade", first_receipt, receipts, escalated=False
        )
        return resp
    premium = pick_model(router, "premium")
    resp2, final_receipt = await _ask_with_receipt(
        router, premium, messages, role="cascade.escalated_answer"
    )
    receipts.append(final_receipt)
    resp2["_route"] = _mode_route(
        "cascade",
        final_receipt,
        receipts,
        escalated=True,
        first_requested_model=cheap,
        first_actual_model=first_receipt.get("actual_model"),
    )
    return resp2


async def _run_harness_legacy(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """厚 Harness（自适应·弱模型增强）：规划→实现→评估→带评语重试→不过才升级强模型。

    给免费/便宜模型套一层外部编排，把它的下限拉高（Anthropic“做厚”思路 + Reflexion 重试）；
    弱模型在脚手架下能解就不烧强模型——这正是“让 Agnes 跟强模型学、省额度”的落点。
    """
    prompt = _prompt(messages)
    weak = pick_model(router, "cheap")
    # 1. 规划：弱模型先列要点，作为后续实现的脚手架
    plan = _text(
        await _ask(
            router,
            weak,
            [{"role": "user", "content": f"为完成下面任务，先列 3-5 步简要解题计划（只列要点，不作答）：\n{prompt}"}],
            role="harness_legacy.plan",
        )
    )
    critique = ""
    last: dict[str, Any] | None = None
    for rnd in range(2):  # 最多 2 轮：弱模型按计划实现 + 自评找茬
        guide = f"解题计划：\n{plan}"
        if critique:
            guide += f"\n\n上一版的问题（请针对性改正）：\n{critique}"
        last = await _ask(
            router,
            weak,
            [{"role": "system", "content": guide}, *messages],
            role=f"harness_legacy.draft.round_{rnd + 1}",
        )
        verdict = _text(
            await _ask(
                router,
                weak,
                [{"role": "user", "content": f"任务：{prompt}\n\n答案：{_text(last)}\n\n严格找茬：是否正确且完整？只回复 OK，或 NEEDS_WORK: <具体问题>。"}],
                role=f"harness_legacy.self_review.round_{rnd + 1}",
            )
        )
        if _verdict_pass(verdict):
            last["_route"] = {"mode": "harness", "model": weak, "rounds": rnd + 1, "escalated": False}
            return last
        critique = verdict
    # 弱模型搞不定 → 升级强模型（调用方可据此把强模型解法存为案例，接 M3）
    strong = pick_model(router, "premium")
    resp = await _ask(
        router, strong, messages, role="harness_legacy.escalated_answer"
    )
    resp["_route"] = {"mode": "harness", "model": strong, "rounds": 2, "escalated": True, "weak": weak}
    return resp


async def run_harness(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """Adaptive weak-model harness with a receipt for every model hop."""

    prompt = _prompt(messages)
    weak = pick_model(router, "cheap")
    receipts: list[dict[str, Any]] = []
    plan_response, plan_receipt = await _ask_with_receipt(
        router,
        weak,
        [{"role": "user", "content": f"先列 3-5 步执行计划，不要直接作答：\n{prompt}"}],
        role="harness.plan",
    )
    receipts.append(plan_receipt)
    plan = _text(plan_response)
    critique = ""
    for rnd in range(2):
        guide = f"执行计划：\n{plan}"
        if critique:
            guide += f"\n\n上一版问题，请针对性修正：\n{critique}"
        draft, draft_receipt = await _ask_with_receipt(
            router,
            weak,
            [{"role": "system", "content": guide}, *messages],
            role=f"harness.draft.round_{rnd + 1}",
        )
        receipts.append(draft_receipt)
        verdict_response, verdict_receipt = await _ask_with_receipt(
            router,
            weak,
            [{
                "role": "user",
                "content": (
                    f"任务：{prompt}\n\n答案：{_text(draft)}\n\n"
                    "严格找茬并检查是否正确完整；只回复 OK，或 NEEDS_WORK: <问题>。"
                ),
            }],
            role=f"harness.self_review.round_{rnd + 1}",
        )
        receipts.append(verdict_receipt)
        critique = _text(verdict_response)
        if _verdict_pass(critique):
            draft["_route"] = _mode_route(
                "harness",
                draft_receipt,
                receipts,
                rounds=rnd + 1,
                escalated=False,
            )
            return draft

    strong = pick_model(router, "premium")
    response, final_receipt = await _ask_with_receipt(
        router, strong, messages, role="harness.escalated_answer"
    )
    receipts.append(final_receipt)
    response["_route"] = _mode_route(
        "harness",
        final_receipt,
        receipts,
        rounds=2,
        escalated=True,
        weak_requested_model=weak,
    )
    return response


def _multistep(prompt: str) -> bool:
    """粗判是否多步/可拆分（适合组队分工/并行）。"""
    import re

    return bool(re.search(r"\n\s*[1-9一二三四五]\s*[.、)]|步骤|分别|并行|多个|依次|拆解|清单|逐一", prompt))


def _context_followup(messages: list[dict[str, Any]]) -> bool:
    return any(
        m.get("role") == "system"
        and isinstance(m.get("content"), str)
        and ("短追问" in m["content"] or "不是让你解释这个短语本身" in m["content"])
        for m in messages
    )


async def run_auto(router: Any, messages: list[dict[str, Any]]) -> dict[str, Any]:
    """自动智能（日常默认）：分诊→易/中难/组队 自适应，用户无感。

    易：便宜模型直答；难：便宜模型带"做厚"脚手架尽量自解、不行升级强模型；
    难且"真瓶颈"(超长 / 多步可拆 / 重推理)：才升级到多智能体组队(org，~15×贵，故保守)。
    合并了 economy/cascade/harness/org 的取舍。（"动手执行/工具"由前端按是否动手任务分派 exec。）"""
    c = classify(_prompt(messages))
    if _context_followup(messages):
        model = pick_model(router, "premium") or pick_model(router, "cheap")
        resp, receipt = await _ask_with_receipt(
            router, model, messages, role="auto.context_followup.answer"
        )
        resp["_route"] = _mode_route(
            "auto", receipt, [receipt], tier="context_followup", classify=c
        )
        return resp
    if c["difficulty"] == "easy":
        resp = await run_economy(router, messages)
        route = resp.get("_route") or {}
        resp["_route"] = {**route, "mode": "auto", "tier": "easy", "classify": c}
        return resp
    # 难：默认单模型做厚；只有真瓶颈才组队（点4 边界，保守，宁可不组省钱）
    bottleneck = c.get("length", 0) > 4000 or _multistep(_prompt(messages))
    if bottleneck:
        resp = await run_org(router, messages)
        rt = resp.get("_route") or {}
        resp["_route"] = {**rt, "mode": "auto", "tier": "org", "classify": c}
        return resp
    resp = await run_harness(router, messages)
    r = resp.get("_route") or {}
    resp["_route"] = {**r, "mode": "auto", "tier": "hard", "classify": c}
    return resp


def _provider_of(router: Any, model: str) -> str | None:
    for r in router.routes_info():
        if r["model"] == model:
            return r.get("provider")
    return None


def _cross_vendor_premium(router: Any, planner_model: str) -> str:
    """保留给 Trinity/旧编排路径的宽松选将适配器。

    新的 org/deep 互审不使用这个宽松回退；唯一票权真值入口是 ReviewGate。
    """
    planner_provider = _provider_of(router, planner_model)
    pool = [
        row
        for row in router.routes_info()
        if row.get("tier") == "premium" and not row.get("flagship")
    ]
    different = [row for row in pool if row.get("provider") != planner_provider]
    selected = sorted(different or pool, key=lambda row: rank_sort_key(row.get("rank")))
    return (
        str(selected[0]["model"])
        if selected
        else (pick_model(router, "premium") or planner_model)
    )


async def _org_review(
    router: Any,
    gate: ReviewGate,
    *,
    plan: str,
    output: str,
    label: str,
    role: str,
    wall_deadline: float | None = None,
) -> tuple[str, ReviewDecision | None, str]:
    """Request one review and bind its vote to the actual served identity."""
    requested = gate.select_reviewer() or ""
    if not requested:
        return "", None, "FAIL:无法证明存在与全部实际 lineage 异源的审核官"
    review_messages = [{
        "role": "user",
        "content": (
            f"规格：\n{plan}\n\n{label}：\n{output}\n\n"
            "你是独立审核官。请独立严格评分是否达标，先简述依据；"
            "最后一行必须且只能是 PASS，或 FAIL。"
        ),
    }]
    with bind_model_review_call(
        reviewed_output_sha256=reviewed_output_sha256(output),
        business_role=role,
    ):
        observed_call = await _ask_observed(
            router,
            requested,
            review_messages,
            role=role,
            wall_deadline=wall_deadline,
        )
        response, served, invocation_route = observed_call
        provider_provenance = getattr(observed_call, "provenance", None)
    expected_request_sha256 = canonical_provider_request_sha256(
        ChatCompletionRequest(
            model=served,
            messages=review_messages,
        ).model_dump(exclude_none=True)
    )
    observation = review_observation(
        router,
        requested_model=requested,
        served_model=served,
        route=invocation_route,
        response=response,
        verdict=_text(response),
        reviewed_output=output,
        provider_provenance=provider_provenance,
        expected_provider_request_sha256=expected_request_sha256,
    )
    decision = gate.evaluate(observation, reviewed_output=output)
    verdict = (
        observation.verdict
        if decision.qualified
        else f"FAIL:审核票作废（{decision.reason}）"
    )
    return requested, decision, verdict


async def run_org(
    router: Any,
    messages: list[dict[str, Any]],
    *,
    wall_deadline: float | None = None,
) -> dict[str, Any]:
    """多智能体组织（困难任务·P4）：规划官(强)→执行员(便宜·可重试)→审核官(强·跨厂独立)→升级。

    每步有验证闸（审核官独立评分），错误卡在闸口；执行员失败 2 轮 → 升级规划官亲自执行，
    强模型不会"一直等"。组队成本高(~15×)，故只作显式/困难触发，不在 auto 里默认拉起。
    """
    prompt = _prompt(messages)
    gate = ReviewGate(router)
    planner_requested = pick_model(router, "premium") or pick_model(router, "cheap")
    plan_response, planner, _planner_route = await _ask_observed(
        router,
        planner_requested,
        [{"role": "user", "content":
          f"为完成任务，列一份清晰执行规格（要点 + 验收标准），不要作答：\n{prompt}"}],
        role="org.plan",
        wall_deadline=wall_deadline,
    )
    gate.add_author(
        planner,
        role="planner",
        initiator=True,
        requested_model=planner_requested,
        route=_planner_route,
        response=plan_response,
    )
    plan = _text(plan_response)
    executor_requested = pick_model(router, "cheap") or planner
    critique = ""
    last_executor = ""
    last_decision: ReviewDecision | None = None

    for rnd in range(2):
        guide = f"执行规格：\n{plan}" + (
            f"\n\n上一版的问题（针对性改正）：\n{critique}" if critique else ""
        )
        draft, last_executor, _executor_route = await _ask_observed(
            router,
            executor_requested,
            [{"role": "system", "content": guide}, *messages],
            role=f"org.execute.round_{rnd + 1}",
            wall_deadline=wall_deadline,
        )
        gate.add_author(
            last_executor,
            role=f"executor_round_{rnd + 1}",
            requested_model=executor_requested,
            route=_executor_route,
            response=draft,
        )
        initial_requested, initial_decision, verdict = await _org_review(
            router,
            gate,
            plan=plan,
            output=_text(draft),
            label="执行员产出",
            role=f"org.review.draft.round_{rnd + 1}",
            wall_deadline=wall_deadline,
        )
        last_decision = initial_decision

        if initial_decision and initial_decision.reviewed:
            # 发起者只接收合格互审；审核反馈被总结吸收后也进入 lineage，且自身零票。
            initial_reviewer = initial_decision.observation.served_model
            gate.add_contributor(
                initial_decision.observation,
                role="initial_review_feedback",
            )
            review_summary = gate.summary_for_initiator()
            summary_prompt = (
                f"原始任务：\n{prompt}\n\n执行规格：\n{plan}\n\n"
                f"执行员草稿：\n{_text(draft)}\n\n"
                f"合格互审意见：\n{review_summary['qualified_reviews']}\n\n"
                "你是发起者，只负责基于草稿和上述合格互审意见形成最终总结；"
                "不得给自己投票，不得引入无依据的新事实。"
            )
            initiator_model = gate.initiator.model if gate.initiator else planner
            final, final_model, _summary_route = await _ask_observed(
                router,
                initiator_model,
                [{"role": "user", "content": summary_prompt}],
                role=f"org.summary.round_{rnd + 1}",
                wall_deadline=wall_deadline,
            )
            summary_accepted = gate.add_initiator_summary(
                final_model,
                role="initiator_summary",
                requested_model=initiator_model,
                route=_summary_route,
                response=final,
            )
            if not summary_accepted:
                draft_receipt = route_receipt(
                    requested_model=executor_requested,
                    actual_model=last_executor,
                    route=_executor_route,
                    response=draft,
                )
                draft["_route"] = {
                    "mode": "org",
                    **draft_receipt,
                    **gate.route_metadata(None, reviewed_output=_text(draft)),
                    "planner": planner,
                    "executor": last_executor,
                    "summary_model_requested": initiator_model,
                    "summary_model": final_model or None,
                    "final_model": last_executor,
                    "initial_reviewer": initial_reviewer,
                    "initial_reviewer_requested": initial_requested,
                    "final_reviewer_requested": None,
                    "rounds": rnd + 1,
                    "escalated": False,
                    "draft_reviewed": True,
                    "post_summary_review_required": True,
                    "post_summary_review_error": (
                        "initiator_summary_actual_mismatch"
                    ),
                    "review_reason": "initiator_summary_actual_mismatch",
                    "review_unavailable_reason": (
                        "initiator_summary_actual_mismatch"
                    ),
                    "reviewer_decision_vote_weight": 0,
                    "reviewer_vote_weight": 0,
                    "reviewed": False,
                    "verified": False,
                    "machine_verified": False,
                }
                return draft
            final_requested, final_decision, _final_verdict = await _org_review(
                router,
                gate,
                plan=plan,
                output=_text(final),
                label="发起者最终总结",
                role=f"org.review.summary.round_{rnd + 1}",
                wall_deadline=wall_deadline,
            )
            last_decision = final_decision
            reviewed = bool(final_decision and final_decision.reviewed)
            summary_receipt = route_receipt(
                requested_model=initiator_model,
                actual_model=final_model,
                route=_summary_route,
                response=final,
            )
            final["_route"] = {
                "mode": "org",
                **summary_receipt,
                **gate.route_metadata(
                    final_decision,
                    reviewed_output=_text(final),
                ),
                "planner": planner,
                "executor": last_executor,
                "summary_model": final_model,
                "final_model": final_model,
                "initial_reviewer": initial_reviewer,
                "initial_reviewer_requested": initial_requested,
                "final_reviewer_requested": final_requested,
                "rounds": rnd + 1,
                "escalated": False,
                "reviewed": reviewed,
                "verified": False,
                "machine_verified": False,
            }
            return final

        if initial_decision and initial_decision.qualified:
            gate.add_contributor(
                initial_decision.observation,
                role=f"review_feedback_round_{rnd + 1}",
            )
            critique = initial_decision.observation.verdict
        else:
            critique = verdict

    # 两轮草稿未过：发起者拿到的仍只有合格 review，形成升级总结后再独立终审。
    review_summary = gate.summary_for_initiator()
    summary_requested = gate.initiator.model if gate.initiator else planner
    final, final_model, _final_route = await _ask_observed(
        router,
        summary_requested,
        [{"role": "user", "content":
          f"执行规格：\n{plan}\n\n合格互审：\n{review_summary['qualified_reviews']}\n\n"
          f"请作为发起者形成最终总结。\n\n原始任务：\n{prompt}"}],
        role="org.summary.escalated",
        wall_deadline=wall_deadline,
    )
    summary_accepted = gate.add_initiator_summary(
        final_model,
        role="initiator_escalated_summary",
        requested_model=summary_requested,
        route=_final_route,
        response=final,
    )
    if not summary_accepted:
        draft_receipt = route_receipt(
            requested_model=executor_requested,
            actual_model=last_executor,
            route=_executor_route,
            response=draft,
        )
        draft["_route"] = {
            "mode": "org",
            **draft_receipt,
            **gate.route_metadata(None, reviewed_output=_text(draft)),
            "planner": planner,
            "executor": last_executor,
            "summary_model_requested": summary_requested,
            "summary_model": final_model or None,
            "final_model": last_executor,
            "final_reviewer_requested": None,
            "rounds": 2,
            "escalated": True,
            "draft_reviewed": bool(last_decision and last_decision.reviewed),
            "post_summary_review_required": True,
            "post_summary_review_error": "initiator_summary_actual_mismatch",
            "review_reason": "initiator_summary_actual_mismatch",
            "review_unavailable_reason": "initiator_summary_actual_mismatch",
            "reviewer_decision_vote_weight": 0,
            "reviewer_vote_weight": 0,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
        }
        return draft
    final_requested, final_decision, _final_verdict = await _org_review(
        router,
        gate,
        plan=plan,
        output=_text(final),
        label="升级后的最终总结",
        role="org.review.summary.escalated",
        wall_deadline=wall_deadline,
    )
    last_decision = final_decision
    reviewed = bool(last_decision and last_decision.reviewed)
    final_receipt = route_receipt(
        requested_model=summary_requested,
        actual_model=final_model,
        route=_final_route,
        response=final,
    )
    final["_route"] = {
        "mode": "org",
        **final_receipt,
        **gate.route_metadata(
            last_decision,
            reviewed_output=_text(final),
        ),
        "planner": planner,
        "executor": last_executor,
        "final_model": final_model,
        "final_reviewer_requested": final_requested,
        "rounds": 2,
        "escalated": True,
        "reviewed": reviewed,
        "verified": False,
        "machine_verified": False,
    }
    return final


SINGLE_ANSWER_MODES = {
    "auto": run_auto,        # 自动智能（默认）
    "org": run_org,          # 多智能体组织（困难/显式）
    "smart": run_smart,
    "cascade": run_cascade,
    "economy": run_economy,
    "best": run_best,
    "harness": run_harness,
}
