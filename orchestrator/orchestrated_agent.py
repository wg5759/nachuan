"""编排型 super-agent：按复杂度选模型 → 规划 → 带工具执行 → 跨厂强模型验证 → 不过升级重跑。

在已硬化的 `run_tool_agent`（执行步）之上套一层编排，把"复杂动手任务只在单个便宜模型上跑扁平循环"
升级为「规划 / 验证 / 升级」的闭环——复杂任务丝滑度从 0 拉起来。

设计要点（全部版本无关，不写死任何型号名）：
- 简单任务走**快路径**：0 额外 LLM 调用，直接 run_tool_agent，省钱。
- 复杂任务：强 tool_capable premium 模型规划→执行→跨厂 premium 独立验证；
  验证不过 / 执行停滞(stall/max_steps) → 执行模型升级一档、带评语改进 plan 重跑，最多 2 轮。
- 模型一律按 tier + rank/flagship + tool_capable **动态**选（复用 modes.py 的 pick_model 等 helper）。

对外只加不改：复用（import）modes / tool_agent / classify / failover 的既有 helper，
不改动 modes 里 run_auto/org/harness 的任何行为（chat 模式一个字不动）。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from gateway import quota_state
from gateway.catalog import preset_meta, rank_sort_key
from gateway.failover import chat_with_fallback
from gateway.provider_call_ledger import (
    bind_provider_call_scope,
    current_provider_call_context,
)
from gateway.route_attestation import (
    bind_agent_author_receipt,
    bind_model_review_call,
    canonical_provider_request_sha256,
    verify_agent_author_receipt,
)
from gateway.schemas import ChatCompletionRequest
from orchestrator import coordinator, scoreboard, task_state
from orchestrator.classify import classify
from orchestrator.modes import (
    _cross_vendor_premium,
    pick_model,
)
from orchestrator.review_gate import (
    ReviewDecision,
    ReviewGate,
    ReviewObservation,
    review_observation,
    reviewed_output_sha256,
)
from orchestrator.tool_agent import new_wall_deadline, run_tool_agent
from orchestrator.workflows.common import route_receipt, unserved_route_receipt
from orchestrator.workspace_guard import resolve_workspace

# 执行返回这些 stopped_reason 表示"执行本身出了问题"，即使验证放行也应触发升级重跑。
_STOP_BAD = {"stall", "max_steps", "wall_cap"}
# 编排升级封顶轮数（首跑之外最多再重跑这么多次）。省钱硬闸。
_MAX_ROUNDS = 2
# 判"复杂到值得铺编排"的长度阈值（字符）。与 classify 的难度判定叠加取或。
_LONG_TASK_CHARS = 1500

# ── F3 TRINITY 轮转常量 ──
# Fugu 的 K=5：点将→演一角色 最多轮转这么多次；每轮 verifier ACCEPT 即终止。
_TRINITY_MAX_TURNS = 5
# transcript 里每条产出摘要的截断长度（喂点将官的裸文本，省 token 又够路由判断）。
_TRINITY_DIGEST = 800
# 同一 worker 模型连续「干砸」(stall/max_steps 或被 verifier REJECT) 到此次数 →
# 在 transcript 里加一行提示，让点将官自然升级到更强模型。
_TRINITY_WORKER_FAIL_HINT = 2
# TRINITY 整体墙钟预算（秒）：超过即带部分成果优雅收尾——绝不无限转（机主实测 139 分钟的总闸）。
_TRINITY_WALL_SEC = 1200.0


@dataclass(frozen=True, slots=True)
class _ObservedModelResponse:
    text: str
    served_model: str
    route: Any
    response: dict[str, Any]
    provenance: dict[str, Any] | None = None

    def __iter__(self):  # noqa: ANN204 - preserve legacy four-value unpacking
        yield self.text
        yield self.served_model
        yield self.route
        yield self.response
# A review vote must cover the exact returned reply.  We therefore reject an
# oversized reply instead of silently reviewing only a prefix and blessing the
# unobserved suffix.
_MAX_REVIEW_REPLY_CHARS = 12_000

# 多步/可拆分粗判（借 modes.run_org 的思路）：命中即视为复杂，铺规划+验证。
_MULTISTEP = re.compile(
    r"\n\s*[1-9一二三四五]\s*[.、)]|步骤|分别|并行|多个|依次|拆解|清单|逐一|然后|接着|最后",
    re.I,
)

# 「要动手/用工具」哨兵（路由第3步·第0层）：粗判这活是不是要真去操作（浏览器/文件/命令/购物…）。
# 这类**别丢给最便宜的模型**（agnes-flash 磨半天），该上够强的 tool_capable 模型 + 走编排。
# 注意：这只用于**模型档位路由**，不是判 exec-vs-chat（那已定死：动手→exec）。命中=偏复杂。
_TOOL_HEAVY = re.compile(
    r"打开|浏览器|网页|网站|上网|搜索|搜一下|查一下|查询|下载|上传|文件夹|目录|运行|执行|命令|"
    r"爬虫|抓取|登录|填表|填写|点击|下单|购买|价格|多少钱|截图|保存到|读取文件|操作|自动化|"
    r"browser|website|download|upload|click|login|scrape|crawl|screenshot|automate|"
    r"淘宝|京东|拼多多|亚马逊|taobao|amazon|github|"
    # 生视频/生图是真动手活（要调工具、要传对参数）——别判"简单"丢给最弱模型磨蹭
    # （机主实测：「做1分钟视频」被 agnes-flash 快路径拖 1m28s 还没派出任务）
    r"视频|生图|画一?[张个]|做[张个]?图|生成图|video|animate",
    re.I,
)


def _needs_tools(task: str) -> bool:
    """粗判这活要不要动手/用工具（→ 别用最便宜模型，上够强的）。命中关键词或带本机路径即是。"""
    t = task or ""
    if _TOOL_HEAVY.search(t):
        return True
    if re.search(r"[A-Za-z]:\\|/(home|Users|mnt|var|etc)/", t):  # 本机路径 → 明显要读写文件
        return True
    return False


def _tool_capable(model: str) -> bool:
    """该模型能否稳定 function-calling（编排里"带工具执行/审核"择模型时据此过滤）。

    经 catalog.preset_meta 查预设登记；未登记的自定义/拉取模型默认 True（乐观放行）。
    """
    return bool(preset_meta(model).get("tool_capable", True))


def _tier_of(router: Any, model: str) -> str:
    """查模型档位（cheap/free/premium/…）；查不到返回 ""。供先快后升判"是不是真便宜档"。"""
    for r in router.routes_info():
        if r.get("model") == model:
            return str(r.get("tier") or "")
    return ""


def _rank_of(router: Any, model: str) -> tuple[int, int]:
    for r in router.routes_info():
        if r["model"] == model:
            return rank_sort_key(r.get("rank"))
    return rank_sort_key(None)


def _pick_tool_capable(router: Any, tier: str, *, allow_flagship: bool = False) -> Optional[str]:
    """按档位选一个 **tool_capable** 模型：先在该档位的 tool_capable 子集里按 flagship/rank 排优，
    子集为空再退回 pick_model（宁可给个不确定能调工具的，也不至于选不出模型卡死）。

    版本无关：只依据 tier + rank/flagship + tool_capable，绝不写死型号名。
    """
    infos = router.routes_info()
    if not infos:
        return None
    cheap_tiers = ("cheap", "free")
    if tier == "cheap":
        cands = [r for r in infos if r["model"] != "echo" and r["tier"] in cheap_tiers]
    elif tier == "premium":
        cands = [
            r for r in infos
            if r["tier"] == "premium" and (allow_flagship or not r.get("flagship"))
        ]
    else:
        cands = [r for r in infos if r["model"] != "echo"]
    capable = [r for r in cands if _tool_capable(r["model"])]
    if not capable:
        # 该档位没有确定能 function-calling 的 → 返回 None 让调用方**降档**再选。
        # 绝不能在这兜底 pick_model：机主 premium 档全是 CLI 后端(claude/codex, tool_capable=False)，
        # 兜底会把执行员又选回 claude → 180s CLI 超时灾难重演（机主实测：修了 catalog 仍旧空转）。
        return None
    # 额度感知（路由第2步）：冷却中的沉底——选还有额度的 tool_capable 模型顶上。
    capable = sorted(capable, key=lambda r: (
        0 if quota_state.available(r["model"]) else 1,
        0 if r.get("flagship") else 1,
        rank_sort_key(r.get("rank")),
    ))
    return capable[0]["model"]


def _escalate_model(router: Any, current: str) -> str:
    """把执行模型升级到"更强"的 tool_capable 模型。返回原模型=已无更强可换。

    真升级（机主实测「升级环是死代码」根修）：旧实现只在 premium∩tool_capable 池里找——
    而机主配置下 premium 全是 CLI（tool_capable=False）→ 池恒空 → 永远原地 → 升级从不发生。
    改为**按能力序**跨档找更强者：先同档内 rank 更小，再更高档任意 tool_capable，最后放行 flagship。
    tier 强弱以 _TIER_RANK 定序（premium>cheap>free），不写死型号名。
    """
    _TIER_RANK = {"premium": 3, "cheap": 2, "free": 1}

    def _cap(r: dict[str, Any]) -> tuple[int, int, int, int]:
        """能力键（越大越强）：档位、王牌、显式排名、排名数值。"""
        unranked, rank = rank_sort_key(r.get("rank"))
        return (
            _TIER_RANK.get(r.get("tier") or "", 0),
            1 if r.get("flagship") else 0,
            -unranked,
            -rank,
        )

    info = router.routes_info()
    cur = next((r for r in info if r["model"] == current), None)
    cur_cap = _cap(cur) if cur else (0, 0, -1, 0)
    # 候选=所有 tool_capable 且严格比当前更强的模型（跨档，不再局限 premium）。
    pool = [
        r for r in info
        if (
            r["model"] != "echo"
            and _tool_capable(r["model"])
            and r["model"] != current
            and _cap(r) > cur_cap
        )
    ]
    if not pool:
        return current  # 已是最强 tool_capable → 无更强可换（编排层据此停止无谓重跑）
    # 选“恰好比当前强一点”的最小步进（升一档就够，不一步跳顶，省钱又稳）。
    pool.sort(key=_cap)
    return pool[0]["model"]


def _is_complex(task: str, c: dict[str, Any]) -> bool:
    """是否复杂到值得铺编排（规划+验证）：难度 hard、或超长、或多步可拆——任一即是。"""
    return (
        c.get("difficulty") == "hard"
        or c.get("length", 0) > _LONG_TASK_CHARS
        or bool(_MULTISTEP.search(task or ""))
    )


def _tool_log_digest(tool_log: list[str], limit: int = 1600) -> str:
    """把执行的 tool_log 压成给审核官/重规划看的摘要（保头尾、限长，省 token）。"""
    if not tool_log:
        return "(无工具调用)"
    if len(tool_log) <= 12:
        body = "\n".join(tool_log)
    else:
        body = "\n".join(tool_log[:6] + ["…（省略中间若干步）…"] + tool_log[-6:])
    return body[:limit]


def _actual_author_models(result: dict[str, Any]) -> list[str]:
    """Read actual served author identities without laundering production unknowns.

    ``run_tool_agent`` always emits ``actual_model`` and ``actual_models``.  ``None``
    means no model call authored output, while ``""`` means a call returned without a
    verifiable identity.  Only old test doubles that omit both fields may fall back to
    the backward-compatible display ``model`` field.
    """
    observed: list[str] = []
    if "actual_models" in result:
        raw_models = result.get("actual_models")
        if raw_models is None:
            raw_models = []
        elif not isinstance(raw_models, (list, tuple)):
            # A malformed production truth field is itself unverifiable identity.
            raw_models = [""]
        for raw_model in raw_models:
            if raw_model is None:
                continue
            model = str(raw_model or "").strip()
            if model not in observed:
                observed.append(model)
        if "actual_model" in result and result.get("actual_model") is not None:
            final_model = str(result.get("actual_model") or "").strip()
            if final_model not in observed:
                observed.append(final_model)
        return observed
    if "actual_model" in result:
        actual_model = result.get("actual_model")
        return [] if actual_model is None else [str(actual_model or "").strip()]
    # Legacy compatibility is deliberately presence-based: production unknowns must
    # never be replaced by the requested/display model.
    return [str(result.get("model") or "").strip()]


def _record_result_authors(
    review_gate: ReviewGate,
    result: dict[str, Any],
    *,
    role: str,
) -> str | None:
    """Add every actual model hop from receipts; strings alone never grant identity."""
    actual_models = _actual_author_models(result)
    raw_receipts = result.get("author_receipts")
    receipts = raw_receipts if isinstance(raw_receipts, list) else []
    receipted_models: set[str] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict):
            review_gate.add_author("", role=role, receipt=None)
            continue
        actual_model = str(receipt.get("actual_model") or "").strip()
        receipted_models.add(actual_model)
        review_gate.add_author(
            actual_model,
            role=role,
            receipt=receipt,
            initiator=review_gate.initiator is None,
        )
    for actual_model in actual_models:
        if actual_model not in receipted_models:
            review_gate.add_author(
                actual_model,
                role=role,
                initiator=review_gate.initiator is None,
            )
    for actual_model in reversed(actual_models):
        if actual_model:
            return actual_model
    return "" if actual_models else None


def _final_result_receipt(
    result: dict[str, Any],
    *,
    requested_model: str | None,
) -> dict[str, Any]:
    """Return immutable evidence for the model that authored the final reply."""

    reply = str(result.get("reply") or "")
    existing = result.get("final_route_receipt")
    if isinstance(existing, dict) and verify_agent_author_receipt(
        existing,
        reply=reply,
    ):
        return dict(existing)
    actual_value = result.get("actual_model") if "actual_model" in result else None
    if actual_value is None:
        return unserved_route_receipt(
            requested_model=requested_model,
            reason="no_final_model_call",
        )
    actual = str(actual_value or "").strip()
    receipts = result.get("author_receipts")
    if isinstance(receipts, list):
        for receipt in reversed(receipts):
            if not isinstance(receipt, dict):
                continue
            if str(receipt.get("actual_model") or "").strip() == actual:
                try:
                    return bind_agent_author_receipt(receipt, reply=reply)
                except ValueError:
                    continue
    missing = route_receipt(
        requested_model=requested_model,
        actual_model=actual,
        route=None,
        response=None,
    )
    missing["model_identity_error"] = (
        "served_identity_unknown" if not actual else "missing_final_call_receipt"
    )
    from gateway.route_attestation import seal_route_receipt

    return seal_route_receipt(missing)


def _bind_final_result_identity(
    result: dict[str, Any],
    *,
    requested_model: str | None,
) -> dict[str, Any]:
    receipt = _final_result_receipt(result, requested_model=requested_model)
    result["model"] = receipt.get("actual_model")
    result["final_route_receipt"] = receipt
    return receipt


# 规划/验证类单跳 LLM 调用的硬超时（秒）。CLI 系模型撞限额可能长挂——单跳超时按失败处理，
# 走既有降级路径，绝不让一跳把整个编排拖死（机主实测 139 分钟转圈的直接解药之一）。
_LLM_HOP_TIMEOUT = 240.0


def _wall_expired(deadline: float) -> bool:
    return time.monotonic() >= deadline


async def _await_with_wall(
    factory: Callable[[], Awaitable[Any]],
    deadline: float,
    *,
    stage_cap: float = _LLM_HOP_TIMEOUT,
) -> Any:
    """Start one stage only while the shared request budget is live."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise asyncio.TimeoutError("shared wall deadline expired")
    return await asyncio.wait_for(factory(), timeout=min(stage_cap, remaining))


async def _llm_observed_response(
    router: Any,
    model: str,
    prompt: str,
) -> tuple[str, str, Any, dict[str, Any]]:
    """Keep the response metadata required to verify the served model."""
    req = ChatCompletionRequest(model=model, messages=[{"role": "user", "content": prompt}])  # type: ignore[arg-type]
    provider_role = current_provider_call_context().role or "orchestrated.llm"
    with bind_provider_call_scope(role=provider_role):
        call_result = await asyncio.wait_for(
            chat_with_fallback(router, req), timeout=_LLM_HOP_TIMEOUT
        )
    res, served, route = call_result
    text = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
    return _ObservedModelResponse(
        text,
        str(served or ""),
        route,
        res,
        getattr(call_result, "provenance", None),
    )


async def _llm_observed(router: Any, model: str, prompt: str) -> tuple[str, str, Any]:
    """Compatibility view for non-voting calls; voting paths keep the response."""

    text, served, route, _response = await _llm_observed_response(router, model, prompt)
    return text, served, route


async def _llm_text(router: Any, model: str, prompt: str) -> str:
    """兼容旧调用方的纯文本适配器；需要票权/lineage 时必须用 `_llm_observed`。"""
    text, _served, _route = await _llm_observed(router, model, prompt)
    return text


async def _make_plan(
    router: Any,
    model: str,
    task: str,
    critique: str = "",
    *,
    review_gate: ReviewGate | None = None,
    role: str = "planner",
) -> str:
    """让强模型给 3-6 步简短 TODO（要点 + 验收标准），风格参照 modes.run_org 的规划提示。

    带 critique（上一轮审核评语）时要求针对性改进计划。只列计划、不作答。
    """
    prompt = (
        "为完成下面这个需要动手的任务，列一份 3-6 步的简短执行计划（每步：要点 + 可验证的验收标准），"
        "只列计划、不要现在就动手作答，也不要写代码：\n"
        f"任务：{task}"
    )
    if critique:
        prompt += (
            "\n\n上一轮执行未达标，审核评语如下，请据此改进计划（更具体、补上遗漏、修正方向）：\n"
            f"{critique}"
        )
    try:
        with bind_provider_call_scope(role=f"orchestrated.plan.{role}"[:256]):
            plan_text, served, call_route, response = await _llm_observed_response(
                router, model, prompt
            )
        if review_gate is not None:
            review_gate.add_author(
                served,
                role=role,
                initiator=review_gate.initiator is None,
                requested_model=model,
                route=call_route,
                response=response,
            )
        plan = plan_text.strip()
    except asyncio.TimeoutError:  # 单跳超时 → 用兜底计划继续，不拖死编排
        plan = ""
    return plan or "1. 理解任务并拆解步骤\n2. 逐步动手执行\n3. 自检结果是否满足要求"


async def _verify(
    router: Any,
    reviewer: str,
    task: str,
    plan: str,
    result: dict[str, Any],
) -> ReviewObservation:
    """跨厂强模型依据"验收标准 + 执行结果(reply + tool_log 摘要)"独立判是否达标。

    返回携带 requested/actual identity 的 ReviewObservation；仍可兼容二元解包。
    """
    reply = str(result.get("reply") or "")
    if len(reply) > _MAX_REVIEW_REPLY_CHARS:
        return review_observation(
            router,
            requested_model=reviewer,
            served_model="",
            verdict=(
                "FAIL:待审最终回复超过安全审核上限，未调用审核模型；"
                "请先形成不超过 12000 字符的最终总结"
            ),
            passed=False,
        )
    digest = _tool_log_digest(result.get("tool_log") or [])
    prompt = (
        "你是独立审核官（与执行方不同厂），请严格、客观地判断下面这次动手执行是否达标。\n\n"
        f"原始任务：\n{task}\n\n"
        f"执行计划与验收标准：\n{plan}\n\n"
        f"执行结果（最终回复）：\n{reply}\n\n"
        f"执行过程（工具调用摘要）：\n{digest}\n\n"
        "只依据以上信息判断：是否真的完成了任务、满足验收标准？"
        "先用一两句说明理由，最后单独一行给结论——达标写 PASS，未达标写 FAIL:<最关键的缺口>。"
    )
    try:
        provider_role = current_provider_call_context().role or "orchestrated.review"
        with bind_model_review_call(
            reviewed_output_sha256=reviewed_output_sha256(reply),
            business_role=provider_role,
        ):
            with bind_provider_call_scope(role=provider_role):
                observed_call = await _llm_observed_response(router, reviewer, prompt)
                verdict, served, invocation_route, response = observed_call
            provider_provenance = getattr(observed_call, "provenance", None)
        expected_request_sha256 = canonical_provider_request_sha256(
            ChatCompletionRequest(
                model=served,
                messages=[{"role": "user", "content": prompt}],
            ).model_dump(exclude_none=True)
        )
    except asyncio.TimeoutError:
        # 审核超时**必须算未通过**——空判词会被 _verdict_pass 当"无失败词"放行，绝不能默认通过。
        return review_observation(
            router,
            requested_model=reviewer,
            served_model="",
            verdict="审核调用超时(240s)，按未通过处理",
            passed=False,
        )
    return review_observation(
        router,
        requested_model=reviewer,
        served_model=served,
        route=invocation_route,
        response=response,
        verdict=verdict,
        reviewed_output=reply,
        provider_provenance=provider_provenance,
        expected_provider_request_sha256=expected_request_sha256,
    )


def _coerce_review_observation(
    router: Any,
    requested_reviewer: str,
    raw: Any,
) -> ReviewObservation:
    """Normalize review seams; legacy tuples carry no served identity and get zero vote."""
    if isinstance(raw, ReviewObservation):
        return raw
    verdict = ""
    passed = False
    if isinstance(raw, tuple) and len(raw) >= 2:
        passed, verdict = bool(raw[0]), str(raw[1] or "")
    return review_observation(
        router,
        requested_model=requested_reviewer,
        served_model="",
        verdict=verdict or "审核结果缺少实际服务身份",
        passed=passed,
    )


async def _review_with_gate(
    router: Any,
    gate: ReviewGate,
    reviewer: str | None,
    task: str,
    plan: str,
    result: dict[str, Any],
) -> tuple[ReviewDecision | None, str]:
    """Run one review and let the centralized gate assign (or deny) its vote."""
    if not reviewer:
        return None, "无法证明存在与全部实际作者异源的审核模型"
    raw = await _verify(router, reviewer, task, plan, result)
    observation = _coerce_review_observation(router, reviewer, raw)
    decision = gate.evaluate(
        observation,
        reviewed_output=str(result.get("reply") or ""),
    )
    verdict = observation.verdict if decision.qualified else f"审核票作废：{decision.reason}"
    return decision, verdict


def _qualified_review_context(gate: ReviewGate) -> str:
    """Serialize only qualified review evidence for the initiator.

    Reviewer prose is bounded per observation so one hostile/buggy provider
    cannot inflate the post-review summary prompt without limit.  Identity and
    vote fields remain explicit; unqualified reviews never enter this view.
    """

    rows: list[dict[str, Any]] = []
    for raw in gate.summary_for_initiator().get("qualified_reviews") or []:
        if not isinstance(raw, dict):
            continue
        rows.append({
            "served_model": raw.get("served_model"),
            "model_family": raw.get("model_family"),
            "independence_domain": raw.get("independence_domain"),
            "passed": bool(raw.get("passed")),
            "vote_weight": int(raw.get("vote_weight", 0) or 0),
            "verdict": str(raw.get("verdict") or "")[:4000],
        })
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":"))


async def _summarize_then_final_review(
    router: Any,
    gate: ReviewGate,
    initial_decision: ReviewDecision,
    *,
    task: str,
    plan: str,
    draft_result: dict[str, Any],
    role_prefix: str,
    wall_deadline: float,
    on_event: Optional[Callable[[dict], Awaitable[None]]] = None,
) -> tuple[dict[str, Any], ReviewDecision | None, dict[str, Any]]:
    """Turn an accepted draft into an initiator summary, then review it anew.

    The first reviewer is absorbed into lineage before the initiator sees its
    feedback.  Consequently ``select_reviewer`` can only choose a *different*
    strong family/domain for the exact final summary.  If any identity or
    capacity is unavailable, the summary may still be returned as progress but
    it never inherits the draft's PASS.
    """

    meta: dict[str, Any] = {
        "draft_reviewed": bool(initial_decision.reviewed),
        "initial_reviewer": initial_decision.observation.served_model,
        "initial_reviewer_requested": initial_decision.observation.requested_model,
        "summary_model_requested": None,
        "summary_model": None,
        "final_reviewer_requested": None,
        "post_summary_review_required": True,
        "post_summary_review_error": None,
    }
    if not initial_decision.reviewed or not initial_decision.qualified:
        meta["post_summary_review_error"] = "initial_review_not_qualified_pass"
        return dict(draft_result), None, meta

    if not gate.add_contributor(
        initial_decision.observation,
        role=f"{role_prefix}.initial_review_feedback",
    ):
        meta["post_summary_review_error"] = "initial_reviewer_lineage_rejected"
        return dict(draft_result), None, meta

    initiator = gate.initiator
    if initiator is None:
        meta["post_summary_review_error"] = "initiator_identity_unknown"
        return dict(draft_result), None, meta

    summary_requested = initiator.model
    meta["summary_model_requested"] = summary_requested
    draft_reply = str(draft_result.get("reply") or "")
    summary_prompt = (
        f"原始任务：\n{task}\n\n"
        f"执行规格/上下文：\n{plan}\n\n"
        f"当前草稿：\n{draft_reply}\n\n"
        f"合格的外部互审结果（结构化，只能使用这些互审意见）：\n"
        f"{_qualified_review_context(gate)}\n\n"
        "你是本任务的发起者。请接收其他模型的合格互审结果，在保留重要限制、"
        "不歪曲反对意见、不引入无依据新事实的前提下，形成可直接交付的最终总结。"
        "你不得审核自己、不得给自己投票，也不要输出 PASS/FAIL 投票。"
    )
    try:
        with bind_provider_call_scope(role=f"{role_prefix}.initiator_summary"[:256]):
            summary_text, summary_actual, summary_route, summary_response = await _await_with_wall(
                lambda: _llm_observed_response(router, summary_requested, summary_prompt),
                wall_deadline,
            )
    except asyncio.TimeoutError:
        meta["post_summary_review_error"] = "initiator_summary_timeout"
        return dict(draft_result), None, meta

    summary_text = str(summary_text or "").strip()
    meta["summary_model"] = summary_actual or None
    if not summary_text:
        meta["post_summary_review_error"] = "initiator_summary_empty"
        return dict(draft_result), None, meta

    summary_receipt = route_receipt(
        requested_model=summary_requested,
        actual_model=summary_actual or None,
        route=summary_route,
        response=summary_response,
    )
    summary_accepted = gate.add_initiator_summary(
        summary_actual,
        role=f"{role_prefix}.initiator_summary",
        requested_model=summary_requested,
        receipt=summary_receipt,
    )
    if not summary_accepted:
        meta["post_summary_review_error"] = (
            "initiator_summary_actual_mismatch"
            if summary_actual != summary_requested
            else "initiator_summary_authority_invalid"
        )
        return dict(draft_result), None, meta
    try:
        final_summary_receipt = bind_agent_author_receipt(
            summary_receipt,
            reply=summary_text,
        )
    except ValueError:
        final_summary_receipt = summary_receipt
    summary_result = dict(draft_result)
    summary_result["reply"] = summary_text
    summary_result["model"] = summary_actual or None
    summary_result["actual_model"] = summary_actual or None
    if "final_author_models" in summary_result:
        summary_result["final_author_models"] = [summary_actual] if summary_actual else []
    if "output_kind" in summary_result:
        summary_result["output_kind"] = "initiator_summary"
    actual_models = list(summary_result.get("actual_models") or [])
    if summary_actual and summary_actual not in actual_models:
        actual_models.append(summary_actual)
    summary_result["actual_models"] = actual_models
    author_receipts = [
        dict(row) for row in (summary_result.get("author_receipts") or [])
        if isinstance(row, dict)
    ]
    author_receipts.append(summary_receipt)
    summary_result["author_receipts"] = author_receipts
    summary_result["final_route_receipt"] = final_summary_receipt
    await _emit(on_event, {
        "type": "summary",
        "stage": "post_review",
        "model": summary_actual or None,
        "requested_model": summary_requested,
        "initiator_vote_weight": 0,
    })

    if len(summary_text) > _MAX_REVIEW_REPLY_CHARS:
        meta["post_summary_review_error"] = "reviewed_output_too_large"
        return summary_result, None, meta

    final_reviewer = gate.select_reviewer()
    meta["final_reviewer_requested"] = final_reviewer
    if not final_reviewer:
        meta["post_summary_review_error"] = "no_strong_independent_final_reviewer"
        return summary_result, None, meta

    try:
        with bind_provider_call_scope(role=f"{role_prefix}.final_review"[:256]):
            final_decision, final_verdict = await _await_with_wall(
                lambda: _review_with_gate(
                    router,
                    gate,
                    final_reviewer,
                    task,
                    plan,
                    summary_result,
                ),
                wall_deadline,
            )
    except asyncio.TimeoutError:
        meta["post_summary_review_error"] = "final_review_timeout"
        return summary_result, None, meta

    if not final_decision:
        meta["post_summary_review_error"] = "final_review_unavailable"
    elif not final_decision.reviewed:
        meta["post_summary_review_error"] = final_decision.reason
    await _emit(on_event, {
        "type": "verify",
        "stage": "post_summary_final",
        "reviewer": final_decision.observation.served_model if final_decision else None,
        "reviewer_requested": final_reviewer,
        "reviewer_vote_weight": final_decision.vote_weight if final_decision else 0,
        "reviewed": bool(final_decision and final_decision.reviewed),
        "verified": False,
        "verdict": str(final_verdict or "")[:600],
    })
    return summary_result, final_decision, meta


def _survey_workdir(workdir: str, limit: int = 40) -> str:
    """轻量勘察工作区顶层结构（给 init 规划接地，别盲规划）。失败→""。"""
    try:
        import os
        entries = sorted(os.listdir(workdir))[:limit]
        rows = [("[目录] " if os.path.isdir(os.path.join(workdir, e)) else "[文件] ") + e for e in entries]
        return "\n".join(rows)
    except Exception:  # noqa: BLE001
        return ""


async def _harness_init(
    router: Any,
    model: str,
    workdir: str,
    task: str,
    *,
    review_gate: ReviewGate | None = None,
) -> str:
    """长任务 harness 的 init 阶段（Anthropic 铁律④：init/coding 分离）：勘察工作区→接地规划→
    落盘任务状态(目标+checklist)。返回规划文本（供注入 coding 阶段的上下文）。"""
    survey = _survey_workdir(workdir)
    plan_task = task if not survey else f"{task}\n\n【工作目录 {workdir} 现有内容】\n{survey}"
    plan = await _make_plan(
        router,
        model,
        plan_task,
        review_gate=review_gate,
        role="harness_planner",
    )
    try:
        task_state.start_task(workdir, task, plan)  # 落盘目标+步骤清单；不落可执行命令
    except Exception:  # noqa: BLE001 状态落盘失败不挡任务
        pass
    return plan


def _harness_persist(harness: bool, workdir: str, task: str, result: dict[str, Any], resuming: bool) -> None:
    """长任务 harness 落盘：把本轮结果记进 workdir 的 .纳川/（新任务先落目标+计划，续跑只追进展）。

    全吞异常——状态落盘是"外部记忆"锦上添花，绝不能因它挡任务或抛错。
    """
    if not harness or not workdir:
        return
    try:
        st = task_state.load(workdir)
        # 新任务（无状态 / 旧任务已完成或与本次不相关）→ 用本次目标+计划开一份新的。
        if not resuming and (st is None or not task_state.looks_like_continuation(task, st)):
            task_state.start_task(workdir, task, str(result.get("plan") or ""))
        note = str(result.get("reply") or "")[:200]
        task_state.record_progress(workdir, note, completed=bool(result.get("verified")))
        # 符号化短期记忆（借鉴腾讯 TencentDB Agent Memory）：把本轮**全量工具日志卸载**到
        # .纳川/refs/<node_id>.md，画布上只留一个轻量节点——续跑时注入画布（省 token），
        # 要复盘本步细节按 node_id 下钻。best-effort，失败绝不挡任务。
        try:
            from orchestrator import symbolic_memory

            tl = result.get("tool_log") or []
            detail = (
                "【计划】\n" + str(result.get("plan") or "(无)")
                + "\n\n【本轮全量工具日志】\n" + "\n".join(str(x) for x in tl)
            )
            symbolic_memory.add_node(
                workdir, note or "本轮进展", detail,
                kind="done" if result.get("verified") else "step",
            )
        except Exception:  # noqa: BLE001 符号画布是锦上添花
            pass
    except Exception:  # noqa: BLE001
        return


async def _emit(on_event: Optional[Callable[[dict], Awaitable[None]]], event: dict) -> None:
    """推进度事件（给将来 SSE 用）。on_event 为 None 不推；异常吞掉，绝不因推事件失败而中断编排。"""
    if on_event is None:
        return
    try:
        await on_event(event)
    except Exception:  # noqa: BLE001
        pass


def apply_outcome(result: dict[str, Any], verified: Optional[bool]) -> str:
    """把验证状态收口为诚实的终态；未过验收的结果绝不标成 completed。"""
    has_progress = bool(
        (result.get("reply") or "").strip()
        or int(result.get("steps", 0) or 0) > 0
        or result.get("tool_log")
        or result.get("file_changes")
        or result.get("media")
        or result.get("pending_videos")
    )
    # Every stopped_reason is an explicit incomplete/abnormal terminal state.  It
    # dominates both an absent verifier and even a contradictory positive flag;
    # otherwise wall-cap/stall/capability-denial summaries can masquerade as done.
    declared_stopped_outcome = result.get("outcome")
    if result.get("stopped_reason"):
        if declared_stopped_outcome in {"partial", "failed", "blocked"}:
            outcome = str(declared_stopped_outcome)
        else:
            outcome = "partial" if has_progress else "failed"
    elif verified is True:
        outcome = "completed"
    elif verified is None:
        outcome = "completed_unverified"
    else:
        outcome = "partial" if has_progress else "failed"
    result["outcome"] = outcome
    result["blocked"] = outcome == "blocked"
    route = result.get("_route")
    if isinstance(route, dict):
        route["outcome"] = outcome
    return outcome


# ══════════════════════════════ F3 TRINITY 三角色轮转 ══════════════════════════════
# Fugu 核心机制③：每一轮由「点将官」(coordinator.pick_next，永不答题) 给池中模型派
# thinker(出思路) / worker(动手) / verifier(审核) 之一；喂点将官的是 **raw transcript**
# （`role: content\n` 裸文本，不走 chat template——Fugu 发现这对路由准确率关键）；verifier
# ACCEPT 即终止收工，上限 K=5 轮。点将失败(None) 由规则兜底（首轮 worker，之后 verifier），
# 保证没有点将官也能走完「干活→验收」；现有 plan→execute→verify 流保留为最终 fallback。


def _digest(text: str, limit: int = _TRINITY_DIGEST) -> str:
    """把一段产出压成 transcript 里的摘要（去多余空白 + 截断），省点将官/审核官的 token。"""
    s = re.sub(r"\n{3,}", "\n\n", (text or "").strip())
    return s[:limit] if len(s) > limit else s


def _accumulate(total: dict[str, Any], result: dict[str, Any]) -> None:
    """把一次 worker(run_tool_agent) 的产出累积进总结果：file_changes/media 追加，usage 相加，
    并把最近一次的 reply/tool_log/model/steps 记为「当前累计结果」（供 verifier 审、最终返回）。
    """
    incoming_reply = result.get("reply")
    total["reply"] = incoming_reply or total.get("reply") or ""
    if incoming_reply:
        # ``model`` is the actual author of this current reply.  A deterministic
        # fallback intentionally overwrites an earlier model with None.
        final_actual = result.get("actual_model") if "actual_model" in result else None
        total["model"] = final_actual
        total["actual_model"] = final_actual
    total.setdefault("actual_models", [])
    for actual in result.get("actual_models") or []:
        if actual not in total["actual_models"]:
            total["actual_models"].append(actual)
    total.setdefault("author_receipts", [])
    total["author_receipts"].extend(result.get("author_receipts") or [])
    if result.get("stopped_reason"):
        total["stopped_reason"] = result["stopped_reason"]
    total["steps"] = int(total.get("steps", 0) or 0) + int(result.get("steps", 0) or 0)
    total.setdefault("tool_log", [])
    total["tool_log"].extend(result.get("tool_log") or [])
    total.setdefault("file_changes", [])
    total["file_changes"].extend(result.get("file_changes") or [])
    total.setdefault("media", [])
    total["media"].extend(result.get("media") or [])
    total.setdefault("pending_videos", [])
    total["pending_videos"].extend(result.get("pending_videos") or [])
    u = result.get("usage") or {}
    acc = total.setdefault("usage", {})
    for k, v in u.items():
        acc[k] = int(acc.get(k, 0) or 0) + int(v or 0)


def _record_worker(model: str, task_kind: str, win: bool) -> None:
    """给本轮之前干活的 worker 模型记一场战绩（沿用批1钩子风格：全吞异常，记分牌坏了不挡任务）。"""
    try:
        scoreboard.record(model, task_kind, win)
    except Exception:  # noqa: BLE001
        pass


async def run_trinity_agent(
    router: Any,
    task: str,
    *,
    workdir: str,
    max_steps: int = 50,  # 天花板抬高：靠"给出最终答案"自然停+停滞检测兜底，让长任务干到完成
    history: Optional[list[dict]] = None,
    allow: Optional[set[str]] = None,
    on_event: Optional[Callable[[dict], Awaitable[None]]] = None,
    first_cast: Optional[dict[str, Any]] = None,
    preload_context: bool = True,
    wall_deadline: Optional[float] = None,  # 墙钟预算：与外层编排共享，worker 轮转不重置
    review_gate: ReviewGate | None = None,
) -> dict[str, Any]:
    """TRINITY 三角色轮转（Fugu「舰队」打法的心脏）：点将→演角色→验收，最多 K 轮。

    返回 dict 与 run_orchestrated_agent 同构（reply/steps/model/usage/tool_log/file_changes/
    media + trinity 元信息 turns/cast_log/verified）。任何点将失败一律规则兜底，绝不挡任务。
    """
    workdir = str(resolve_workspace(workdir))
    c = classify(task)
    task_kind = c.get("kind") or "general"

    # raw transcript：Fugu 关键——喂点将官的是裸文本（role: content\n），不是 chat template。
    transcript = f"user: {task}\n"
    cast_log: list[dict[str, Any]] = []      # 每轮点将记录（给返回 & 调试）
    total: dict[str, Any] = {}                # 累计结果（worker 产出汇总到这）
    review_gate = review_gate or ReviewGate(router)
    final_review: ReviewDecision | None = None
    post_review_meta: dict[str, Any] = {}
    reviewed = False
    last_worker: Optional[str] = None         # 最近一次干活的 worker（供 verifier 结论记账 & 护栏）
    worker_fail: dict[str, int] = {}          # 每个 worker 连续「干砸」计数（护栏：连败→提示升级）
    budget_per_worker = max(4, max_steps)     # 每次 worker 的步数预算（复用外部 max_steps）
    wall_t0 = time.monotonic()                # 整体墙钟（机主实测 139 分钟转圈的总闸）
    _wall = wall_deadline if wall_deadline is not None else new_wall_deadline()  # 硬预算（422 分钟失控根修）

    for k in range(_TRINITY_MAX_TURNS):
        turn = k + 1
        if _wall_expired(_wall) or time.monotonic() - wall_t0 > _TRINITY_WALL_SEC:
            transcript += "(整体耗时超预算，带现有成果收尾)\n"
            break  # 墙钟超限 → 优雅收尾（下方返回带部分成果），绝不无限转

        # ── 点将（worker 那轮需要动手 → need_tools=True 让点将官优先点可调工具的）──
        need_tools = True  # 保守：多数轮可能要动手；thinker/verifier 用不到工具也无妨
        if k == 0 and first_cast is not None:
            # 免双重点将：入口探针已点过一次，首轮直接用探针结果（省一次 LLM 调用 + 几十秒）。
            cast = first_cast if first_cast.get("model") else None
        else:
            try:
                with bind_provider_call_scope(
                    role=f"orchestrated.trinity.coordinator.turn_{k + 1}"
                ):
                    cast = await _await_with_wall(
                        lambda: coordinator.pick_next(
                            router,
                            transcript,
                            task_kind=task_kind,
                            need_tools=need_tools,
                        ),
                        _wall,
                    )
            except asyncio.TimeoutError:
                if _wall_expired(_wall):
                    break
                cast = None

        # ── 点将失败(None) 的规则兜底：第 1 轮兜底 worker，之后兜底 verifier ──
        # （保证没有点将官也能走完「干活→验收」；第 1 轮就没结果可验，必须先 worker。）
        fallback = cast is None
        if fallback:
            if last_worker is None:
                bmodel = (_pick_tool_capable(router, "premium") or _pick_tool_capable(router, "cheap")
                          or pick_model(router, "cheap"))  # 全空终极兜底，保证有模型可跑
                cast = {"model": bmodel, "role": "worker", "instruction": ""}
            else:
                vmodel = _cross_vendor_premium(router, last_worker)
                cast = {"model": vmodel, "role": "verifier", "instruction": ""}

        model = cast.get("model")
        role = cast.get("role")
        instruction = cast.get("instruction") or ""
        if not model:
            break  # 连兜底都选不出模型（空池）→ 优雅收尾
        cast_rec = {"turn": turn, "model": model, "role": role,
                    "instruction": instruction, "fallback": fallback}
        if cast.get("by"):  # 战绩短路（by=record）：让 SSE 时间线看到「这轮是按战绩直选，非点将官」
            cast_rec["by"] = cast["by"]
        cast_log.append(cast_rec)
        await _emit(on_event, {"type": "cast", **cast_rec})

        # ══════════════ thinker：纯文本出思路/拆解（不动工具，省额度）══════════════
        if role == "thinker":
            prompt = (
                f"任务：{task}\n\n"
                f"当前进展（对话记录）：\n{transcript}\n\n"
                + (f"你的分工指令：{instruction}\n\n" if instruction else "")
                + "请作为思考者，只用纯文字给出解决思路 / 关键拆解 / 应注意的要点，不要动手、不要写最终答案。"
            )
            try:
                with bind_provider_call_scope(
                    role=f"orchestrated.trinity.thinker.turn_{turn}"
                ):
                    think, actual_thinker, think_route, think_response = await _await_with_wall(
                        lambda: _llm_observed_response(router, model, prompt), _wall
                    )
            except asyncio.TimeoutError:  # 该跳超时 → 记录并跳过这轮，让点将官换招
                transcript += f"thinker({model}): (调用超时240s，跳过)\n"
                if _wall_expired(_wall):
                    break
                continue
            review_gate.add_author(
                actual_thinker,
                role=f"thinker_turn_{turn}",
                initiator=review_gate.initiator is None,
                requested_model=model,
                route=think_route,
                response=think_response,
            )
            cast_rec["actual_model"] = actual_thinker
            digest = _digest(think)
            transcript += f"thinker({actual_thinker or 'unknown'}): {digest}\n"
            await _emit(on_event, {
                "type": "think", "turn": turn, "model": actual_thinker or model,
                "requested_model": model, "text": digest,
            })
            continue

        # ══════════════ verifier：独立审核当前累计结果是否达标 ══════════════
        if role == "verifier":
            if not total:
                # 还没有任何干活产出可审 → 这轮无意义，改提示点将官先派 worker，避免空转。
                transcript += "verifier: (尚无产出可审，请先派 worker 动手)\n"
                continue
            # 点将只是建议；票权必须相对全部实际作者/供应商重新选，身份未知则不调用。
            requested_reviewer = review_gate.select_reviewer()
            cast_rec["requested_reviewer"] = requested_reviewer
            plan_ctx = _digest(transcript, 1200)  # 用 transcript 当「计划/上下文」喂审核官
            try:
                with bind_provider_call_scope(
                    role=f"orchestrated.trinity.review.turn_{turn}"
                ):
                    decision, verdict = await _await_with_wall(
                        lambda: _review_with_gate(
                            router,
                            review_gate,
                            requested_reviewer,
                            task,
                            plan_ctx,
                            total,
                        ),
                        _wall,
                    )
            except asyncio.TimeoutError:
                if _wall_expired(_wall):
                    break
                decision, verdict = None, "审核调用超时，按未通过处理"
            ok = bool(decision and decision.reviewed)
            final_review = decision
            digest = _digest(verdict, 600)
            actual_reviewer = (
                decision.observation.served_model if decision else None
            )
            await _emit(on_event, {
                "type": "verify", "turn": turn, "reviewer": actual_reviewer,
                "reviewer_requested": requested_reviewer,
                "reviewer_vote_weight": decision.vote_weight if decision else 0,
                "reviewed": ok, "verified": False, "verdict": digest,
            })
            # 记账：本轮结论算到「最近一次干活的 worker」头上（win/loss）。
            if last_worker:
                _record_worker(last_worker, task_kind, ok)
            if ok:
                transcript += f"verifier({actual_reviewer}): ACCEPT — {digest}\n"
                # Draft PASS is not transferable: the initiator now consumes the
                # qualified review, authors a new summary with zero vote, and a
                # second independent reviewer must approve that exact summary.
                total, final_review, post_review_meta = await _summarize_then_final_review(
                    router,
                    review_gate,
                    decision,
                    task=task,
                    plan=plan_ctx,
                    draft_result=total,
                    role_prefix=f"orchestrated.trinity.turn_{turn}",
                    wall_deadline=_wall,
                    on_event=on_event,
                )
                reviewed = bool(final_review and final_review.reviewed)
                break
            # 只有身份合格的 REJECT 才能进入 transcript 影响后续作者；一旦吸收就纳入 lineage。
            if decision and decision.qualified:
                review_gate.add_contributor(
                    decision.observation,
                    role=f"review_feedback_turn_{turn}",
                )
                transcript += f"verifier({actual_reviewer}): REJECT — {digest}\n"
            else:
                transcript += f"verifier: REJECT — {digest}\n"
            if last_worker:
                worker_fail[last_worker] = worker_fail.get(last_worker, 0) + 1
                if worker_fail[last_worker] >= _TRINITY_WORKER_FAIL_HINT:
                    transcript += "提示：换更强模型\n"
            continue

        # ══════════════ worker：带工具动手执行（复用硬化的 run_tool_agent）══════════════
        # role 非 thinker/verifier 一律按 worker 处理（点将官若给了奇怪角色也稳）。
        wtask = task if not instruction else f"{task}\n\n【本步分工指令】{instruction}"
        with bind_provider_call_scope(
            role=f"orchestrated.trinity.worker.turn_{turn}"
        ):
            wresult = await run_tool_agent(
                router, model, wtask,
                workdir=workdir, max_steps=budget_per_worker, history=history, allow=allow,
                preload_context=preload_context,
                on_event=on_event,  # 实时逐步流式：worker 每调一个工具就即时推，不再等整轮干完批量推
                wall_deadline=_wall,  # 共享墙钟：轮转/换将不续命
            )
        _accumulate(total, wresult)
        actual_worker = _record_result_authors(
            review_gate,
            wresult,
            role=f"worker_turn_{turn}",
        )
        last_worker = actual_worker or None
        cast_rec["actual_model"] = actual_worker or None
        stopped = wresult.get("stopped_reason")
        wdigest = _digest(
            (wresult.get("reply") or "") + "\n工具摘要：" + _tool_log_digest(wresult.get("tool_log") or [], 400)
        )
        transcript += f"worker({actual_worker or 'unknown'}): {wdigest}\n"
        await _emit(on_event, {
            "type": "work", "turn": turn, "model": actual_worker or model,
            "requested_model": model,
            "stopped_reason": stopped, "text": wdigest,
        })
        # 护栏：worker 执行本身停滞/爆步（stall/max_steps）也算一次「干砸」，累计连败→提示升级。
        if stopped in _STOP_BAD:
            worker_key = actual_worker or model
            worker_fail[worker_key] = worker_fail.get(worker_key, 0) + 1
            if worker_fail[worker_key] >= _TRINITY_WORKER_FAIL_HINT:
                transcript += "提示：换更强模型\n"

    # ── K 用尽或提前 break：优雅收尾，返回尽力而为结果 ──
    if not total:
        # 一次 worker 都没成功跑过（极端兜底：连 worker 模型都选不出）→ 退回既有编排流。
        return await run_orchestrated_agent(
            router, task, workdir=workdir, max_steps=max_steps,
            history=history, allow=allow, on_event=on_event, trinity=False,
            wall_deadline=_wall,
        )

    result = dict(total)
    result.setdefault("usage", {})
    result["usage"] = {k: v for k, v in result["usage"].items() if v}
    result["plan"] = None
    result["rounds"] = len(cast_log)
    result["reviewed"] = bool(reviewed)
    result["verified"] = False
    result["machine_verified"] = False
    result["verification_level"] = "model_review_only" if reviewed else "none"
    result["escalated"] = False
    result["mode"] = "trinity"
    result["turns"] = len(cast_log)
    result["cast_log"] = cast_log
    final_receipt = _bind_final_result_identity(result, requested_model=None)
    result["_route"] = {
        "mode": "trinity", "task_kind": task_kind,
        **final_receipt,
        "turns": len(cast_log), "reviewed": bool(reviewed),
        "verified": False, "machine_verified": False,
        "final_model": result.get("model"),
        "final_route_receipt": final_receipt,
        **review_gate.route_metadata(
            final_review,
            reviewed_output=str(result.get("reply") or ""),
        ),
        **post_review_meta,
    }
    outcome = apply_outcome(result, None if reviewed else False)
    await _emit(on_event, {
        "type": "done", "mode": "trinity", "reviewed": bool(reviewed),
        "verified": False, "machine_verified": False,
        "turns": len(cast_log), "model": result.get("model"), "outcome": outcome,
    })
    return result


def _trinity_enabled(trinity: bool) -> bool:
    """TRINITY 总开关：参数 trinity 为主；环境变量 NACHUAN_TRINITY=0/false/off 可全局强制关闭。

    （给运维一个不改代码的急停阀；默认开——Fugu 打法是升级后的主路径。）
    """
    if not trinity:
        return False
    env = (os.getenv("NACHUAN_TRINITY") or "").strip().lower()
    if env in {"0", "false", "off", "no"}:
        return False
    return True


async def run_orchestrated_agent(
    router: Any,
    task: str,
    *,
    workdir: str,
    model: Optional[str] = None,
    max_steps: int = 50,  # 天花板抬高：靠"给出最终答案"自然停+停滞检测兜底，让长任务干到完成
    history: Optional[list[dict]] = None,
    allow: Optional[set[str]] = None,
    on_event: Optional[Callable[[dict], Awaitable[None]]] = None,
    trinity: bool = True,
    preload_context: bool = True,
    fast_first: bool = True,
    harness: bool = False,
    wall_deadline: Optional[float] = None,
) -> dict[str, Any]:
    """编排型 super-agent：路由 → (复杂则) TRINITY 舰队轮转 / 退回 规划→执行→跨厂验证→升级重跑。

    参数与 run_tool_agent 对齐；额外：
    - model：显式指定执行模型则尊重之（跳过自动路由；显式点模型时不走 TRINITY，尊重用户选择）。
    - trinity：复杂任务是否试走 F3 TRINITY 三角色轮转（默认 True）；点将官首轮不可用（None）时
      **自动退回**下方既有 plan→execute→verify 流（现有行为完整保留为 fallback，逻辑一字未改）。
    - on_event：async 事件回调，推 route/cast/think/work/plan/step/verify/replan/escalate/done 事件。

    返回：以最终一次 run_tool_agent 的 dict 为基础（保留 reply/steps/model/usage/tool_log/
    file_changes/media 等键，app.py/前端依赖），叠加 plan / rounds / verified / escalated / _route。
    """
    # 整个编排（快路径/快档探路/TRINITY/规划-执行-验证-升级重跑）共享**一个**墙钟预算——
    # 升级重跑不续命，否则"每轮重跑都重置预算"会让总闸形同虚设（422 分钟失控根修）。
    _wall = wall_deadline if wall_deadline is not None else new_wall_deadline()
    workdir = str(resolve_workspace(workdir))
    c = classify(task)

    # ── 长任务 harness 续跑判定（必须在复杂度门之前）：workdir 里有未完成任务、本次是续跑指令
    # （哪怕"继续"这种短指令）→ 强制走编排流并注入上次进度，绝不让它被判"简单"走快路径跳过 harness。
    _resuming = False
    _resume_ctx = ""
    if harness and workdir:
        try:
            _st = task_state.load(workdir)
            if task_state.looks_like_continuation(task, _st):
                _resume_ctx = task_state.resume_context(workdir)
                _resuming = bool(_resume_ctx)
        except Exception:  # noqa: BLE001
            pass

    # ── ① 路由：显式 model 优先；否则按复杂度选 tool_capable 模型 ──
    forced = bool(model)
    # 续跑 / harness 长任务（显式项目文件夹）一律按复杂走完整编排流——要 init 勘察规划、要真跑
    # 验证、要落盘进度，绝不让它被判"简单"抄近道跳过 harness（机主实测:短指令/短任务会被误判）。
    # 路由第3步·哨兵：要动手/用工具的活（浏览器/文件/命令/购物…）判为复杂——选够强模型 + 走编排,
    # 不再被判"简单"丢给 agnes-flash 走无升级的快路径（机主实测「打开淘宝」被丢给弱模型又慢又差的根修）。
    needs_tools = _needs_tools(task)
    complex_task = _is_complex(task, c) or needs_tools or _resuming or (harness and bool(workdir))
    if forced:
        exec_model = model  # type: ignore[assignment]
    elif complex_task:
        # premium 档在机主配置下全是 CLI 后端(不能当执行员) → 自然降到 cheap 档的国产强模型
        #（DeepSeek/MiniMax/GLM/Kimi）；全空再终极兜底 pick_model 保证能跑。
        exec_model = (_pick_tool_capable(router, "premium") or _pick_tool_capable(router, "cheap")
                      or pick_model(router, "premium"))
    else:
        exec_model = (_pick_tool_capable(router, "cheap") or _pick_tool_capable(router, "premium")
                      or pick_model(router, "cheap"))
    route_info = {
        "difficulty": c.get("difficulty"),
        "length": c.get("length"),
        "complex": complex_task,
        "forced_model": forced,
        "requested_model": exec_model,
        "scheduled_model": exec_model,
        "tool_capable": _tool_capable(exec_model) if exec_model else None,
    }
    await _emit(on_event, {"type": "route", **route_info, "model": exec_model})
    review_gate = ReviewGate(router)

    # ── 快路径：简单任务（且未显式点复杂模型）→ 直接执行，0 额外 LLM 调用，省钱 ──
    if not complex_task:
        with bind_provider_call_scope(role="orchestrated.fast_path"):
            result = await run_tool_agent(
                router, exec_model, task,
                workdir=workdir, max_steps=max_steps, allow=allow, history=history,
                preload_context=preload_context,
                on_event=on_event,  # 实时逐步流式
                wall_deadline=_wall,
            )
        result["plan"] = None
        result["rounds"] = 1
        result["verified"] = None  # 快路径不验证
        result["escalated"] = False
        final_receipt = _bind_final_result_identity(
            result,
            requested_model=exec_model,
        )
        result["_route"] = {
            **route_info,
            **final_receipt,
            "final_model": result.get("model"),
            "final_route_receipt": final_receipt,
            "fast_path": True,
        }
        outcome = apply_outcome(result, None)
        await _emit(on_event, {
            "type": "done", "verified": None, "escalated": False, "rounds": 1,
            "model": result.get("model"), "outcome": outcome,
        })
        return result

    # ── 先快后升（机主实测根修）："分析下这个文件"这类活被 classify 误判 hard → 走规划路
    # 43s 无产出。正确哲学不是猜"这题难不难"，而是**先让便宜模型直接上手**（小预算 10 步），
    # 干成了立刻返回（5-15s 出活）；停滞/空手才升编排（TRINITY/规划，那里有验证与升级）。
    # 便宜模型 10 步的成本可忽略，换来的是"简单活永远秒回"。显式点名模型时不插这层（尊重用户）。
    # #1(互审·真高)：只在**真 cheap/free 档**跑快档——退化配置(池里只有 premium/echo)时
    # _pick_tool_capable 会回退到 premium，那就别用它当"便宜探路"(2× 成本还没验证)，直接跳过快档进编排。
    # harness 长任务不走 fast_first 快赢（那会跳过 init 规划/落盘/真跑验证——长任务要的是可续可验，
    # 不是秒回）；纯动手快活才 fast_first。
    # 要动手/用工具的活跳过"便宜 fast-first 探路"——别让 agnes-flash 先磨 10 步再升级,
    # 直接用上面选好的够强模型走编排（快且稳）。纯"可能简单"的活才 fast_first 省钱探路。
    if fast_first and not forced and not (harness and workdir) and not needs_tools:
        quick_model = _pick_tool_capable(router, "cheap")
        if quick_model and _tier_of(router, quick_model) not in ("cheap", "free"):
            quick_model = None  # 回退到了非便宜档 → 不值得当快档探路
        if quick_model:
            # #5(互审·契约)：role 标 fast、去掉空串 instruction，与点将官的 worker/thinker/verifier 区分。
            await _emit(on_event, {"type": "cast", "turn": 0, "model": quick_model,
                                   "role": "fast", "by": "fast_first"})
            try:
                with bind_provider_call_scope(role="orchestrated.fast_first"):
                    quick = await run_tool_agent(
                        router, quick_model, task,
                        workdir=workdir, max_steps=min(10, max_steps), allow=allow,
                        history=history,
                        preload_context=False,  # #4(互审)：快档就是要快，绝不预读 KB/工作区吃 1-3s
                        on_event=on_event,  # 实时逐步流式
                        wall_deadline=_wall,
                    )
            except Exception:  # noqa: BLE001 #2(互审·真中)：快档硬异常≠编排死，吞掉升编排
                quick = {
                    "reply": "",
                    "stopped_reason": "error",
                    "tool_log": ["(快档异常：内部详情已隐藏，已升级编排)"],
                }
            q_reply = (quick.get("reply") or "").strip()
            if q_reply and quick.get("stopped_reason") not in _STOP_BAD and quick.get("stopped_reason") != "error":
                quick["plan"] = None
                quick["rounds"] = 1
                quick["verified"] = None  # 先快后升的快档不验证（要深验证选 ultra）
                quick["escalated"] = False
                final_receipt = _bind_final_result_identity(
                    quick,
                    requested_model=quick_model,
                )
                quick["_route"] = {
                    **route_info,
                    **final_receipt,
                    "final_model": quick.get("model"),
                    "final_route_receipt": final_receipt,
                    "fast_first": True,
                }
                outcome = apply_outcome(quick, None)
                await _emit(on_event, {
                    "type": "done", "verified": None, "escalated": False, "rounds": 1,
                    "model": quick.get("model"), "outcome": outcome,
                })
                return quick
            # 便宜模型没干成 → 升编排（它的尝试已在上面实时逐步推过了，不再批量重推）。
            # #3(互审·契约)：带 stage 字段，让前端能区分"快档→编排"这一跳与后续编排内升级。
            await _emit(on_event, {"type": "escalate", "round": 0, "stage": "fast_to_orchestrate",
                                   "reason": "fast_first_failed", "from": quick_model, "to": "编排"})

    # ── 长任务 harness（Anthropic 铁律）：续跑→注入上次进度；新长任务→init 阶段(勘察+接地规划+落盘)。
    # 纯聊天不开启（harness=False，不污染 home）。
    if _resuming and _resume_ctx:
        history = [{"role": "system", "content": _resume_ctx}] + list(history or [])
        await _emit(on_event, {"type": "resume", "note": "接续 workdir 里未完成的长任务"})
    elif harness and workdir and not forced:
        # init/coding 分离：先勘察工作区、接地规划、落盘 checklist+验证命令，再进 coding 执行。
        try:
            _init_model = _pick_tool_capable(router, "premium") or exec_model
            _init_plan = await _await_with_wall(
                lambda: _harness_init(
                    router,
                    _init_model,
                    workdir,
                    task,
                    review_gate=review_gate,
                ),
                _wall,
            )
            if _init_plan:
                history = [{"role": "system", "content":
                            "【本次长任务的执行计划（已落盘为 checklist，按它一步步做、每步做完自检）】\n"
                            + _init_plan}] + list(history or [])
                await _emit(on_event, {"type": "init", "note": "已勘察工作区并规划落盘", "plan": _init_plan})
        except Exception:  # noqa: BLE001 init 失败退回普通流程，不挡任务
            pass

    # ── F3 TRINITY 入口（仅复杂 + 未显式点模型 + 开关开）：先探一次点将官是否可用 ──
    # 首轮能点将 → 走舰队轮转；点将官不可用(None) → 落回下方既有 plan→execute→verify 流
    # （现有行为完整保留为 fallback，一字未改）。探针本身用 cheap 模型，开销可忽略。
    if _trinity_enabled(trinity) and not forced:
        task_kind = c.get("kind") or "general"
        # 首轮点将短路（F 批6①）：该 task_kind 攒够战绩且有胜率冠军 → 0 LLM 调用直选冠军当 probe，
        # 跳过点将官 LLM 调用（省几十秒 + 一次调用）。**只用于首轮**：轮转中仍由点将官依进展决策。
        # 未命中（场次不够/胜率不高/异常）才走原 pick_next 探针。
        # 路由第3步·根修：要动手的活（needs_tools）直接用上面按复杂度选好的**强模型**开局，
        # 跳过点将官——点将官按 task_kind="chat" 的战绩会点到 agnes-flash（机主实测舰队路还是弱模型的真因）。
        # 轮转中点将官仍会依进展调整；这里只保证"开局就上够强的"。纯闲聊(非动手)才让点将官正常点。
        # first_cast 必须是 dict（run_trinity_agent 会 first_cast.get("model")），格式对齐点将官返回。
        probe = (
            {"model": exec_model, "role": "worker", "instruction": "", "by": "needs_tools"}
            if (needs_tools and exec_model)
            else None
        )
        if probe is None:
            try:
                probe = coordinator.pick_by_record(router, task_kind, need_tools=True)
            except Exception:  # noqa: BLE001 战绩短路失败一律当未命中，退回点将官探针
                probe = None
        # 神经点将（批8③，训练先验）：战绩未命中 → 试训练好的线性头按题选（~1s，零配额）。
        # 组件不在/backbone 不可用/置信不足 → None，静默跳过退回 LLM 点将。import 在函数内 try/except
        # 包住：models/coordinator 缺失或 transformers 未装（打包版 excludes）时，这一层等于不存在。
        if probe is None:
            try:
                from orchestrator import neural_coordinator

                probe = neural_coordinator.pick_neural(
                    router, f"user: {task}\n", task_kind=task_kind, need_tools=True
                )
            except Exception:  # noqa: BLE001 神经点将不可用一律当未命中，退回 LLM 点将
                probe = None
        if probe is None:
            try:
                with bind_provider_call_scope(role="orchestrated.coordinator.probe"):
                    probe = await _await_with_wall(
                        lambda: coordinator.pick_next(
                            router,
                            f"user: {task}\n",
                            task_kind=task_kind,
                            need_tools=True,
                        ),
                        _wall,
                    )
            except Exception:  # noqa: BLE001 探针失败一律当点将官不可用，退回既有流
                probe = None
        if probe is not None:
            _res = await run_trinity_agent(
                router, task, workdir=workdir, max_steps=max_steps,
                history=history, allow=allow, on_event=on_event,
                first_cast=probe, preload_context=preload_context,  # 探针结果直用，免双重点将
                wall_deadline=_wall,
                review_gate=review_gate,
            )
            _harness_persist(harness, workdir, task, _res, _resuming)
            return _res

    # ── ② 规划（仅复杂）──
    try:
        plan = await _await_with_wall(
            lambda: _make_plan(
                router,
                exec_model,
                task,
                review_gate=review_gate,
                role="planner_round_1",
            ),
            _wall,
        )
    except asyncio.TimeoutError:
        plan = "1. 理解任务并拆解步骤\n2. 逐步动手执行\n3. 自检结果是否满足要求"
    await _emit(on_event, {"type": "plan", "round": 1, "model": exec_model, "plan": plan})

    result: dict[str, Any] = {}
    model_review_pass = False
    final_review: ReviewDecision | None = None
    post_review_meta: dict[str, Any] = {}
    final_exec_ok = False
    # 工作区测试/构建会执行仓库代码，等价于任意代码执行。网关与审批密钥仍在同一
    # Windows 用户边界内时，绝不能为了“自动验收”在宿主进程账户下运行它们。
    # 这里只探测并提示应跑什么，不执行；接入独立低权限 worker 后再恢复机器证据。
    evidence_cmd = task_state.detect_verify_cmd(workdir) if harness and workdir else ""
    escalated = False
    rounds = 0

    # ── ③ 执行 → ④ 验证 → ⑤ 重规划/升级（有界，最多 _MAX_ROUNDS 轮重跑）──
    for rnd in range(_MAX_ROUNDS + 1):  # 第 0 轮=首跑，之后最多 _MAX_ROUNDS 轮升级重跑
        rounds = rnd + 1
        # ③ 执行：把计划注入 history（作为系统级脚手架），让执行模型带工具干活
        exec_history = list(history or [])
        exec_history.append({
            "role": "system",
            "content": (
                "以下是本次任务的执行计划与验收标准，请严格按它一步步动手完成，"
                "每步做完对照验收标准自检；不要只做规划，要真正用工具执行：\n" + plan
            ),
        })
        with bind_provider_call_scope(role=f"orchestrated.execute.round_{rounds}"):
            result = await run_tool_agent(
                router, exec_model, task,
                workdir=workdir, max_steps=max_steps, allow=allow, history=exec_history,
                preload_context=preload_context,
                on_event=on_event,  # 实时逐步流式
                wall_deadline=_wall,  # 升级重跑共享同一预算，不续命
            )
        actual_executor = _record_result_authors(
            review_gate,
            result,
            role=f"executor_round_{rounds}",
        )

        stopped = result.get("stopped_reason")
        if stopped == "wall_cap" or _wall_expired(_wall):
            model_review_pass = False
            verdict = "共享墙钟预算已耗尽，跳过审核与重规划"
            await _emit(on_event, {
                "type": "verify",
                "round": rounds,
                "reviewer": None,
                "verified": False,
                "exec_stopped_reason": stopped or "wall_cap",
                "verdict": verdict,
                "skipped": "wall_deadline",
            })
            break

        # ④ 验证：基于全部 actual author lineage 选独立 reviewer；无资格者直接关闸。
        reviewer = review_gate.select_reviewer()
        try:
            with bind_provider_call_scope(role=f"orchestrated.review.round_{rounds}"):
                decision, verdict = await _await_with_wall(
                    lambda: _review_with_gate(
                        router,
                        review_gate,
                        reviewer,
                        task,
                        plan,
                        result,
                    ),
                    _wall,
                )
        except asyncio.TimeoutError:
            decision, verdict = None, "审核调用超过共享墙钟预算，按未通过处理"
        final_review = decision
        model_review_pass = bool(decision and decision.reviewed)
        exec_ok = stopped not in _STOP_BAD  # 执行本身没停滞/爆步
        final_exec_ok = exec_ok
        # 跨模型审查不是机器执行证据。检测到测试/构建入口时，只记录待验证命令，
        # 不信任工作区状态文件，也不在持密钥的宿主账户下运行仓库代码。
        cmd_note = ""
        if evidence_cmd:
            cmd_note = f"（待隔离执行器验证 `{evidence_cmd}`；宿主自动执行已关闭）"
            await _emit(on_event, {
                "type": "verify_run", "round": rounds, "cmd": evidence_cmd,
                "passed": None, "skipped": "isolated_worker_unavailable",
            })
        await _emit(on_event, {
            "type": "verify", "round": rounds,
            "reviewer": decision.observation.served_model if decision else None,
            "reviewer_requested": reviewer,
            "reviewer_vote_weight": decision.vote_weight if decision else 0,
            "reviewed": model_review_pass, "verified": False,
            "exec_stopped_reason": stopped, "verdict": (verdict + cmd_note)[:600],
        })

        # ── F6 记账钩子（最小侵入，全吞异常）：把本轮验证结论 + 停滞记入战绩记分牌。
        # task_kind 取函数开头 classify 的 kind（chat/code/reason/long）；记分牌坏了绝不能挡编排。
        try:
            from orchestrator import scoreboard
            task_kind = c.get("kind") or "general"
            scoreboard.record(actual_executor or exec_model, task_kind, model_review_pass and exec_ok)
            if stopped == "stall":  # 执行停滞额外记一次 loss（这轮没干顺）
                scoreboard.record(actual_executor or exec_model, task_kind, False)
        except Exception:  # noqa: BLE001
            pass

        if model_review_pass and exec_ok and decision is not None:
            # The executor draft passed, but the initiator's new summary is a
            # different artifact.  It receives a fresh, second independent vote.
            result, final_review, post_review_meta = await _summarize_then_final_review(
                router,
                review_gate,
                decision,
                task=task,
                plan=plan,
                draft_result=result,
                role_prefix=f"orchestrated.fallback.round_{rounds}",
                wall_deadline=_wall,
                on_event=on_event,
            )
            model_review_pass = bool(final_review and final_review.reviewed)
            break

        if rnd >= _MAX_ROUNDS:
            break  # 轮次用尽 → 返回尽力而为结果（下方标 verified=False）

        # ⑤ 升级执行模型 + 带评语改进计划，重跑（这是"升级"，不是原地重试）
        # An explicit model is user authority, not an initial routing hint.  A
        # missing/failed independent review may lower confidence, but it must
        # never silently replace that model with another executor.
        if forced:
            break
        stronger = _escalate_model(router, exec_model)
        if stronger == exec_model:
            break  # 已无更强的 tool_capable 模型可换 → 不做无谓重跑，返回尽力而为结果
        escalated = True
        reason = "verify_failed" if not model_review_pass else f"exec_{stopped}"
        await _emit(on_event, {
            "type": "escalate", "round": rounds, "reason": reason,
            "from": exec_model, "to": stronger,
        })
        exec_model = stronger
        if decision and decision.qualified and not decision.reviewed:
            # 只有合格 reviewer 的反馈能进入下一轮计划；被吸收后它也是 lineage contributor。
            review_gate.add_contributor(
                decision.observation,
                role=f"review_feedback_round_{rounds}",
            )
            replan_critique = decision.observation.verdict
        else:
            replan_critique = (
                f"审核未形成有效票：{verdict}"
                if not model_review_pass
                else f"审核通过但执行状态异常：{stopped}"
            )
        try:
            plan = await _await_with_wall(
                lambda: _make_plan(
                    router,
                    exec_model,
                    task,
                    critique=replan_critique,
                    review_gate=review_gate,
                    role=f"planner_round_{rounds + 1}",
                ),
                _wall,
            )
        except asyncio.TimeoutError:
            break
        await _emit(on_event, {"type": "replan", "round": rounds + 1, "model": exec_model, "plan": plan})

    # ── 返回：以最终一次执行的 dict 为基础，叠加编排元信息 ──
    result["plan"] = plan
    result["rounds"] = rounds
    reviewed = bool(model_review_pass and final_exec_ok)
    machine_verified = False
    result["reviewed"] = reviewed
    result["verified"] = machine_verified
    result["machine_verified"] = False
    result["verification_level"] = "model_review_only" if reviewed else "none"
    if evidence_cmd:
        result["verification_required"] = evidence_cmd
    result["escalated"] = escalated
    final_receipt = _bind_final_result_identity(
        result,
        requested_model=(post_review_meta.get("summary_model_requested") or exec_model),
    )
    result["_route"] = {
        **route_info,
        **final_receipt,
        **review_gate.route_metadata(
            final_review,
            reviewed_output=str(result.get("reply") or ""),
        ),
        "fast_path": False,
        "final_model": result.get("model"),
        "final_route_receipt": final_receipt,
        "verified": machine_verified,
        "reviewed": reviewed,
        "machine_verified": False,
        "verification_level": result["verification_level"],
        "escalated": escalated,
        "rounds": rounds,
        **post_review_meta,
    }
    outcome = apply_outcome(result, None if reviewed else False)
    await _emit(on_event, {
        "type": "done", "verified": machine_verified, "reviewed": reviewed,
        "verification_level": result["verification_level"], "escalated": escalated,
        "rounds": rounds, "model": result.get("model"), "outcome": outcome,
    })
    _harness_persist(harness, workdir, task, result, _resuming)
    return result
