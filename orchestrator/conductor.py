"""F4 Conductor-lite 工作流 DAG（Fugu「fugu-ultra」深编排档）。

Fugu 核心机制④：强模型一次产出 **三平行列表**——`model_id[1:T]`（每步派谁）/
`subtasks[1:T]`（每步做什么，含给该 worker 的定制指令）/`access_list[1:T]`（每步能看到哪些
前序输出的下标；可见性必须是拓扑序、禁前向引用）。引擎按拓扑执行，互不依赖的节点可并行。

本文件两个入口：
- `plan_workflow(...)`：让强模型（premium，缺省经 `modes.pick_model`）产出并**校验** DAG；
  校验不过带违规说明重试 1 次，再不过返回 None（调用方退化）。
- `run_conductor_agent(...)`：拿 DAG → 按拓扑层执行（显式只读同层并发≤2，可写同层串行）→
  跨厂终审（复用 `orchestrated_agent._verify`）→ 不过带评语重规划 ≤1 轮 → 合成末层 → 记账。
  拿不到 DAG（planner 挂）**原样退化**为 `orchestrated_agent.run_trinity_agent`（不自造退化逻辑）。

降级第一：所有失败路径优雅退化——planner 挂→TRINITY；单节点挂→该节点产出记「(节点失败:…)」
继续，绝不炸整个 DAG。省额度：并发≤2、重规划≤1、合成仅末层多节点才做。版本无关：只依据
tier/rank/flagship/tool_capable/战绩这些**数据**选模型，绝不写死型号名。
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Optional

from gateway.failover import chat_with_fallback
from gateway.catalog import rank_sort_key
from gateway.provider_call_ledger import bind_provider_call_scope
from gateway.route_attestation import bind_agent_author_receipt
from gateway.schemas import ChatCompletionRequest
from orchestrator import coordinator, orchestrated_agent, scoreboard
from orchestrator.classify import classify
from orchestrator.modes import pick_model
from orchestrator.review_gate import ReviewDecision, ReviewGate
from orchestrator.tool_agent import new_wall_deadline, run_tool_agent
from orchestrator.workflows.common import route_receipt
from orchestrator.workspace_guard import resolve_workspace

# DAG 规模硬闸：T 步数上限（照抄 Fugu 的 T≤6，省配额 + 好收敛）。
_MAX_STEPS_T = 6
# 喂给后继节点的每条「前序产出」截断长度（省 token，够后继理解即可）。
_CTX_PER_PRED = 1500
# 终审不过后的重规划封顶轮数（首次规划之外最多再规划这么多次）。省钱硬闸。
_MAX_REPLAN = 1
# 每节点 run_tool_agent 的步数下限（哪怕 T 很大，也给每步至少这么多步喘息）。
_MIN_NODE_STEPS = 4
# 只有显式收窄到这些无副作用工具时，同层节点才可安全共享 workdir 并行。
# allow=None 才代表调用方未限制（全部工具）；显式空集代表零工具/advisory。
_READ_ONLY_PARALLEL_TOOLS = frozenset({
    "list_dir",
    "read_file",
    "list_models",
    "ask_model",
    "list_skills",
    "load_skill",
    "web_read",
    "kb_query",
    "translate",
})


def _shared_workdir_parallel_safe(allow: Optional[set[str]]) -> bool:
    """显式只读 capability 才允许同层共享工作区并发；未知能力一律 fail closed。"""
    return bool(allow) and set(allow).issubset(_READ_ONLY_PARALLEL_TOOLS)


# ───────────────────────────── plan_workflow ─────────────────────────────


def _validate_dag(obj: Any, snapshot: list[dict[str, Any]]) -> tuple[Optional[dict[str, Any]], str]:
    """校验并规整三平行列表 DAG。

    返回 (规整后的 dag | None, 违规说明)。违规说明非空即校验未过（供带说明重试）。
    规则：
    - obj 是 dict，含 model_id / subtasks / access_list 三个**等长**列表，长度 T∈[1, _MAX_STEPS_T]；
    - access_list[i] 是下标列表，每个下标 j 满足 0 ≤ j < i（**拓扑序**，禁前向/自引用）；
    - model_id[i] 必须在池内；不在→用池内同档近似替代（借 coordinator 的 tool_capable 替代思路），
      池空则判违规。

    校验只「修得动就修」（池外模型替代、access 去重排序），结构性错误（不等长/前向引用/越界）
    一律判违规交由重试——不擅自猜测模型意图。
    """
    if not isinstance(obj, dict):
        return None, "输出不是 JSON 对象"
    model_id = obj.get("model_id")
    subtasks = obj.get("subtasks")
    access_list = obj.get("access_list")
    if not (isinstance(model_id, list) and isinstance(subtasks, list) and isinstance(access_list, list)):
        return None, "model_id / subtasks / access_list 必须都是列表"
    T = len(model_id)
    if not (len(subtasks) == T and len(access_list) == T):
        return None, (
            f"三个列表长度必须相等：model_id={len(model_id)}、subtasks={len(subtasks)}、"
            f"access_list={len(access_list)}"
        )
    if T < 1 or T > _MAX_STEPS_T:
        return None, f"步数 T={T} 超出允许范围 [1, {_MAX_STEPS_T}]"

    by_id = {e["model"]: e for e in snapshot}
    ids = list(by_id.keys())

    norm_models: list[str] = []
    norm_subtasks: list[str] = []
    norm_access: list[list[int]] = []
    for i in range(T):
        # ── model_id[i]：不在池内 → 同档近似替代（tool_capable 优先） ──
        m = model_id[i]
        if not isinstance(m, str) or m.strip() not in by_id:
            alt = _nearest_in_pool(snapshot, m if isinstance(m, str) else None)
            if alt is None:
                return None, f"第{i}步模型『{m}』不在池内，且池内无可替代模型"
            m = alt
        else:
            m = m.strip()
        norm_models.append(m)

        # ── subtasks[i]：转字符串（模型偶尔给 dict/None，宽容处理，不判违规） ──
        st = subtasks[i]
        norm_subtasks.append(str(st).strip() if st is not None else "")

        # ── access_list[i]：必须是下标列表且严格 < i（拓扑序） ──
        acc = access_list[i]
        if not isinstance(acc, list):
            return None, f"第{i}步 access_list 不是下标列表"
        cleaned: list[int] = []
        for j in acc:
            if not isinstance(j, int) or isinstance(j, bool):
                return None, f"第{i}步 access_list 含非整数下标『{j}』"
            if j < 0 or j >= i:
                return None, f"第{i}步引用了下标 {j}（必须 0≤下标<{i}，禁前向/自引用）"
            if j not in cleaned:
                cleaned.append(j)
        norm_access.append(sorted(cleaned))

    if ids and not norm_models:  # 理论到不了（T≥1），保险
        return None, "空计划"
    return {"model_id": norm_models, "subtasks": norm_subtasks, "access_list": norm_access}, ""


def _nearest_in_pool(snapshot: list[dict[str, Any]], want_model: Optional[str]) -> Optional[str]:
    """池外/幻觉模型的同档近似替代（借 coordinator._substitute_tool_capable 的 tool_capable 思路）。

    偏好：tool_capable 优先（DAG 节点多要动手）→ 同想要模型档位优先 → flagship → rank 小。
    池内没有任何模型时返回 None。want_model 仅用于「猜它想要的档位」（取不到就无所谓）。
    """
    if not snapshot:
        return None
    want_tier = None
    # want_model 不在池里（本来就是替代场景），拿不到 tier；退而用「有 tool_capable 就好」。
    capable = [e for e in snapshot if e.get("tool_capable", True)]
    pool = capable or list(snapshot)
    pool = sorted(
        pool,
        key=lambda e: (
            0 if (want_tier and e.get("tier") == want_tier) else 1,
            0 if e.get("flagship") else 1,
            rank_sort_key(e.get("rank")),
        ),
    )
    return pool[0]["model"]


def _plan_prompt(task: str, pool_txt: str, board: str, critique: str = "") -> str:
    """产出三平行列表 DAG 的规划提示词（照抄 Fugu 表示法 + 硬规则说明）。"""
    parts = [
        "你是一支模型舰队的总调度（Conductor）。请把下面这个复杂任务拆成一张**工作流 DAG**："
        "为每一步指定 由哪个模型来做、这一步做什么、这一步能看到哪些前序步骤的产出。"
        "你【绝不】自己作答，只输出这张调度计划。",
        "",
        "【可用模型池】(id · 档位 · 技能[· 胜率][· 王牌/无工具])：",
        pool_txt or "(空)",
    ]
    if board:
        parts += ["", board]
    parts += [
        "",
        f"【任务】：\n{task}",
        "",
        "只输出一个 JSON 对象，含三个**等长**的平行列表：",
        '{"model_id": ["<第0步模型id>", "<第1步模型id>", ...], '
        '"subtasks": ["<给第0步模型的定制指令>", "<给第1步模型的定制指令>", ...], '
        '"access_list": [[], [0], [0,1], ...]}',
        "",
        "硬规则（必须全部满足，否则计划作废）：",
        f"1. 步数 T ≤ {_MAX_STEPS_T}；三个列表长度必须完全相等。",
        "2. access_list[i] 是「第 i 步能看到的前序步骤下标」列表，每个下标必须严格小于 i"
        "（拓扑序，禁前向引用、禁引用自己）；第 0 步只能是 []。",
        "3. model_id 里的每个 id 必须取自上面的模型池（照抄池中 id，不要杜撰）。",
        "4. subtasks[i] 是给该模型的**定制指令**——它看不到全局任务，也看不到未被 access_list 授权的"
        "其它步骤，所以指令必须自含（把该步需要的背景、目标、产出要求都写清楚）。",
        "5. 互不依赖的只读步骤可被引擎并行；有写/命令等副作用能力时会为保护共享工作区串行执行。",
        "6. 用模经济学：读文件/摘要/翻译/格式化这类简单子步一律派 cheap/free 档模型（快且省）；"
        "只有真正难的推理/合成步才派 premium；标『王牌』的一律不派。",
    ]
    if critique:
        parts += [
            "",
            "【上一版计划被判无效，原因如下，请据此修正后重新输出完整 JSON】：",
            critique,
        ]
    return "\n".join(parts)


async def plan_workflow(
    router: Any,
    task: str,
    *,
    planner: str | None = None,
    task_kind: str = "general",
    wall_deadline: float | None = None,
    review_gate: ReviewGate | None = None,
    provider_role_prefix: str = "conductor.plan",
) -> dict[str, Any] | None:
    """让强模型产出并校验一张工作流 DAG（Fugu 三平行列表）。

    返回校验通过并规整后的 `{"model_id":[...], "subtasks":[...], "access_list":[[...],...]}`，
    或 **None**（planner 选不出 / 池空 / 两次校验都不过 / 任何异常——由调用方退化到 TRINITY）。

    planner 缺省用强模型（`pick_model(router,"premium")`，没有则 cheap）；解析借
    `coordinator._extract_json_obj`（容忍模型在 JSON 前后废话）；校验见 `_validate_dag`：
    三列表等长、T∈[1,6]、access_list 拓扑序、model_id 全在池内（池外→同档近似替代）。
    校验不过→带违规说明重试 1 次；再不过→None。
    """
    try:
        snapshot = coordinator.pool_snapshot(router, task_kind)
        if not snapshot:
            return None
        model = planner or pick_model(router, "premium") or pick_model(router, "cheap")
        if not model:
            return None

        pool_txt = coordinator.pool_text(snapshot)
        board = scoreboard.summary_line([e["model"] for e in snapshot], task_kind)

        critique = ""
        for _attempt in range(2):  # 首次 + 带违规说明重试 1 次
            prompt = _plan_prompt(task, pool_txt, board, critique)
            req = ChatCompletionRequest(  # type: ignore[call-arg]
                model=model,
                messages=[{"role": "user", "content": prompt}],
            )
            # 单跳硬超时（同 orchestrated_agent._LLM_HOP_TIMEOUT 策略）：超时抛出→外层吞→退化 TRINITY。
            with bind_provider_call_scope(
                role=f"{provider_role_prefix}.attempt_{_attempt + 1}"[:256]
            ):
                if wall_deadline is None:
                    res, served, call_route = await asyncio.wait_for(
                        chat_with_fallback(router, req), timeout=240.0
                    )
                else:
                    res, served, call_route = await orchestrated_agent._await_with_wall(
                        lambda: chat_with_fallback(router, req), wall_deadline
                    )
            if review_gate is not None:
                review_gate.add_author(
                    str(served or ""),
                    role=f"workflow_planner_attempt_{_attempt + 1}",
                    initiator=review_gate.initiator is None,
                    requested_model=model,
                    route=call_route,
                    response=res,
                )
            content = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
            obj = coordinator._extract_json_obj(content)
            dag, why = _validate_dag(obj, snapshot)
            if dag is not None:
                return dag
            critique = why or "计划格式不合法，请严格按三平行列表 JSON 重新输出。"
        return None  # 两次都不过 → 退化
    except Exception:  # noqa: BLE001 规划失败绝不能挡任务，退化到 TRINITY
        return None


# ─────────────────────────── run_conductor_agent ───────────────────────────


def _topo_layers(access_list: list[list[int]]) -> list[list[int]]:
    """把 DAG 按「依赖已全部完成」分层（Kahn 分层）：同层节点互不依赖 → 可并行。

    access_list 已由 `_validate_dag` 保证拓扑序（下标只引用更小的），故必可完整分层；
    保险起见对残余（理论不该有）也兜底成末层，绝不丢节点。
    """
    T = len(access_list)
    done: set[int] = set()
    layers: list[list[int]] = []
    remaining = set(range(T))
    while remaining:
        layer = [i for i in sorted(remaining) if all(j in done for j in access_list[i])]
        if not layer:  # 理论到不了（拓扑序保证），兜底：剩下的全塞末层，防死循环
            layer = sorted(remaining)
        layers.append(layer)
        done.update(layer)
        remaining.difference_update(layer)
    return layers


def _node_context(access: list[int], digests: dict[int, str], models: list[str]) -> str:
    """按 access_list 拼该节点可见的前序产出（每条截断 ~1500 字，标注来源步与模型）。

    无前序（access 为空）返回 ""（该节点是起点，只看自己的定制指令）。
    """
    if not access:
        return ""
    blocks: list[str] = []
    for j in access:
        d = (digests.get(j) or "").strip()
        if not d:
            continue
        blocks.append(f"【前序产出 #{j}（{models[j] if j < len(models) else '?'}）】\n{d[:_CTX_PER_PRED]}")
    return "\n\n".join(blocks)


def _digest_node(result: dict[str, Any]) -> str:
    """把一个节点的执行产出压成给后继/终审看的摘要（reply + 工具摘要，截断省 token）。"""
    reply = (result.get("reply") or "").strip()
    tools = orchestrated_agent._tool_log_digest(result.get("tool_log") or [], 400)
    body = reply
    if tools and tools != "(无工具调用)":
        body = f"{reply}\n工具摘要：{tools}"
    return orchestrated_agent._digest(body, _CTX_PER_PRED)


def _record(model: str, task_kind: str, win: bool) -> None:
    """给某模型记一场战绩（沿用全吞异常风格：记分牌坏了绝不挡编排）。"""
    try:
        scoreboard.record(model, task_kind, win)
    except Exception:  # noqa: BLE001
        pass


async def _run_node(
    router: Any,
    idx: int,
    model: str,
    subtask: str,
    context: str,
    *,
    workdir: str,
    node_steps: int,
    history: Optional[list[dict]],
    allow: Optional[set[str]],
    sem: asyncio.Semaphore,
    on_event: Optional[Callable[[dict], Awaitable[None]]],
    preload_context: bool = True,
    wall_deadline: Optional[float] = None,  # 整个 DAG 共享的墙钟预算
    provider_role: str = "conductor.execute.node",
) -> dict[str, Any]:
    """执行单个 DAG 节点：定制指令 + 前序上下文 → run_tool_agent。并发受 sem 限（≤2）。

    节点自身异常绝不炸整个 DAG——捕获后返回一个「(节点失败:…)」占位产出，让后继与终审继续。
    """
    async with sem:
        await orchestrated_agent._emit(
            on_event, {"type": "node", "index": idx, "model": model, "status": "start"}
        )
        node_task = subtask or "（无定制指令，请根据下方前序产出与工作区推进本步）"
        if context:
            node_task = f"{node_task}\n\n可参考的前序步骤产出：\n{context}"
        try:
            with bind_provider_call_scope(role=provider_role):
                result = await run_tool_agent(
                    router, model, node_task,
                    workdir=workdir, max_steps=node_steps, history=history, allow=allow,
                    preload_context=preload_context,
                    wall_deadline=wall_deadline,
                )
        except Exception:  # noqa: BLE001 单节点失败不炸 DAG
            result = {
                "reply": "节点执行失败；内部详情已隐藏，编排将按失败状态继续收口。",
                "steps": 0,
                "model": "nachuan-engine", "requested_model": model,
                "actual_model": None, "actual_models": [],
                "usage": {}, "tool_log": [], "file_changes": [], "media": [],
                "stopped_reason": "error",
                "outcome": "failed", "blocked": False,
                "reviewed": False, "verified": False, "machine_verified": False,
                "_author_models": [],
                "_author_receipts": [],
                "_author_model": None,  # deterministic system placeholder, not model output
            }
        else:
            # Field-presence semantics are centralized with the other orchestrators:
            # production None means no author, empty means unknown (poison the gate),
            # and only a legacy test double missing both fields may use display `model`.
            author_models = orchestrated_agent._actual_author_models(result)
            result["_author_models"] = author_models
            result["_author_receipts"] = list(result.get("author_receipts") or [])
            result["_author_model"] = next(
                (author for author in reversed(author_models) if author),
                "" if author_models else None,
            )
        result.setdefault("requested_model", model)
        result.setdefault("model", result.get("actual_model"))
        digest = _digest_node(result)
        await orchestrated_agent._emit(
            on_event,
            {"type": "node", "index": idx, "model": model, "status": "done", "digest": digest[:600]},
        )
        return result


async def _synthesize(
    router: Any,
    planner: str,
    task: str,
    tail_results: list[dict[str, Any]],
    models: list[str],
    *,
    wall_deadline: float | None = None,
    review_gate: ReviewGate | None = None,
    provider_role: str = "conductor.synthesis",
) -> dict[str, Any]:
    """末层多节点时，用 planner 把它们的产出合成一段最终答案（1 次 LLM 调用）。

    合成失败/空 → 退回拼接各末层 reply（绝不因合成失败而丢结果）。
    """
    joined = "\n\n".join(
        f"【产出 {i + 1}（{r.get('model', '?')}）】\n{(r.get('reply') or '').strip()[:_CTX_PER_PRED]}"
        for i, r in enumerate(tail_results)
    )
    prompt = (
        "下面是若干并行子任务各自的产出，请把它们**整合成一段**面向用户的完整最终答案"
        "（去重、衔接、补全过渡，不要罗列成分点也不要提到『子任务』字样）：\n\n"
        f"原始任务：{task}\n\n{joined}"
    )
    try:
        with bind_provider_call_scope(role=provider_role):
            if wall_deadline is None:
                text, served, call_route, response = await orchestrated_agent._llm_observed_response(
                    router, planner, prompt
                )
            else:
                text, served, call_route, response = await orchestrated_agent._await_with_wall(
                    lambda: orchestrated_agent._llm_observed_response(router, planner, prompt),
                    wall_deadline,
                )
        text = (text or "").strip()
        if text:
            receipt = route_receipt(
                requested_model=planner,
                actual_model=served,
                route=call_route,
                response=response,
            )
            final_receipt = bind_agent_author_receipt(receipt, reply=text)
            if review_gate is not None:
                review_gate.add_author(
                    served,
                    role="dag_synthesizer",
                    receipt=receipt,
                )
            return {
                "reply": text,
                "model": served,
                "actual_model": served,
                "actual_models": [served],
                "final_author_models": [served],
                "final_route_receipt": final_receipt,
                "usage": dict(response.get("usage") or {}),
                "output_kind": "model_synthesis",
            }
    except Exception:  # noqa: BLE001 合成失败 → 退回拼接
        pass
    final_authors = [
        str(result.get("_author_model") or "")
        for result in tail_results
        if result.get("_author_model")
    ]
    return {
        "reply": "\n\n".join(
            (r.get("reply") or "").strip() for r in tail_results if r.get("reply")
        ),
        "model": None,
        "actual_model": None,
        "actual_models": [],
        "final_author_models": final_authors,
        "final_route_receipt": None,
        "usage": {},
        "output_kind": "deterministic_tail_merge",
    }


async def _execute_dag(
    router: Any,
    task: str,
    dag: dict[str, Any],
    *,
    workdir: str,
    max_steps: int,
    history: Optional[list[dict]],
    allow: Optional[set[str]],
    planner: str,
    task_kind: str,
    on_event: Optional[Callable[[dict], Awaitable[None]]],
    preload_context: bool = True,
    wall_deadline: Optional[float] = None,  # 整个 DAG 共享的墙钟预算（层/节点不重置）
    review_gate: ReviewGate | None = None,
    round_no: int = 1,
) -> tuple[dict[str, Any], list[str]]:
    """按拓扑层执行整张 DAG，返回 (累计结果 total, 末层节点模型列表)。

    - 分层执行：显式只读工具集同层 `asyncio.gather` 并发≤2；可写/未知能力同层串行；
    - 每节点上下文 = access_list 指向的前序节点产出（各截断 ~1500 字）；
    - history 仅首层带（后续层靠前序摘要传递上下文，不重复灌历史）；
    - 每节点步数预算 = max(4, max_steps // T)；
    - 末层多节点 → 用 planner 合成一段主答案，否则末层单节点 reply 即主答案。
    """
    models: list[str] = dag["model_id"]
    subtasks: list[str] = dag["subtasks"]
    access_list: list[list[int]] = dag["access_list"]
    T = len(models)
    node_steps = max(_MIN_NODE_STEPS, max_steps // max(1, T))
    sem = asyncio.Semaphore(2)

    layers = _topo_layers(access_list)
    digests: dict[int, str] = {}
    results: dict[int, dict[str, Any]] = {}
    total: dict[str, Any] = {}
    last_completed_layer: list[int] = []

    for layer_no, layer in enumerate(layers):
        if wall_deadline is not None and orchestrated_agent._wall_expired(wall_deadline):
            break
        coros = [
            _run_node(
                router, idx, models[idx], subtasks[idx],
                _node_context(access_list[idx], digests, models),
                workdir=workdir, node_steps=node_steps,
                history=(history if layer_no == 0 else None),  # 历史仅首层带
                allow=allow, sem=sem, on_event=on_event, preload_context=preload_context,
                wall_deadline=wall_deadline,
                provider_role=f"conductor.execute.round_{round_no}.node_{idx + 1}",
            )
            for idx in layer
        ]
        if _shared_workdir_parallel_safe(allow):
            layer_results = await asyncio.gather(*coros)
        else:
            # 同层节点共享 workdir；任何写/命令/浏览器副作用能力都串行，避免静默覆盖。
            layer_results = [await coro for coro in coros]
        for idx, res in zip(layer, layer_results):
            results[idx] = res
            digests[idx] = _digest_node(res)
            if review_gate is not None:
                orchestrated_agent._record_result_authors(
                    review_gate,
                    res,
                    role=f"dag_node_{idx}",
                )
        last_completed_layer = list(layer)

    # 按下标顺序把各节点产出累积进 total（file_changes/media 追加、usage 相加）。
    for idx in range(T):
        r = results.get(idx)
        if r:
            orchestrated_agent._accumulate(total, r)

    tail = last_completed_layer
    # Return actual served tail identities, never the DAG's requested model ids.
    tail_models = [
        str(results[i].get("_author_model") or "")
        for i in tail
        if results[i].get("_author_model")
    ]
    if len(tail) > 1:
        # 末层多节点 → 合成一段主答案（覆盖 _accumulate 落下的「最后一个节点 reply」）。
        synthesis = await _synthesize(
            router,
            planner,
            task,
            [results[i] for i in tail],
            models,
            wall_deadline=wall_deadline,
            review_gate=review_gate,
            provider_role=f"conductor.synthesis.round_{round_no}",
        )
        total.update(
            {
                key: synthesis[key]
                for key in (
                    "reply",
                    "model",
                    "actual_model",
                    "actual_models",
                    "final_author_models",
                    "final_route_receipt",
                    "output_kind",
                )
            }
        )
        usage = total.setdefault("usage", {})
        for key, value in (synthesis.get("usage") or {}).items():
            usage[key] = int(usage.get(key, 0) or 0) + int(value or 0)
        synthesis_model = str(synthesis.get("actual_model") or "").strip()
        if synthesis_model and synthesis_model not in tail_models:
            tail_models.append(synthesis_model)
    elif len(tail) == 1:
        tail_result = results[tail[0]]
        final_model = str(tail_result.get("_author_model") or "").strip() or None
        final_receipt = tail_result.get("final_route_receipt")
        if not isinstance(final_receipt, dict):
            final_receipt = None
        total.update(
            {
                "reply": tail_result.get("reply") or total.get("reply") or "",
                "model": final_model,
                "actual_model": final_model,
                "actual_models": [final_model] if final_model else [],
                "final_author_models": list(tail_models),
                "final_route_receipt": final_receipt,
                "output_kind": "tail_model" if final_model else "system_placeholder",
            }
        )
    else:
        total.update(
            {
                "model": None,
                "actual_model": None,
                "actual_models": [],
                "final_author_models": [],
                "final_route_receipt": None,
                "output_kind": "no_output",
            }
        )

    return total, tail_models


async def run_conductor_agent(
    router: Any,
    task: str,
    *,
    workdir: str,
    max_steps: int = 50,  # 天花板抬高：靠"给出最终答案"自然停+停滞检测兜底，让长任务干到完成
    history: Optional[list[dict]] = None,
    allow: Optional[set[str]] = None,
    on_event: Optional[Callable[[dict], Awaitable[None]]] = None,
    preload_context: bool = True,
) -> dict[str, Any]:
    """Conductor-lite：规划工作流 DAG → 分层并行执行 → 跨厂终审 → 不过重规划(≤1) → 合成末层。

    - `plan_workflow` 拿不到 DAG（planner 挂）→ **原样退化** `run_trinity_agent`（不自造退化）。
    - 有 DAG：按拓扑层执行（显式只读同层并发≤2，可写同层串行），末层产出为主答案；
    - 终审复用 `orchestrated_agent._verify`（跨厂 premium 审核官）判「任务 + 各节点产出汇总」达标；
      不过 → 带评语重新 `plan_workflow` 一次（≤1 轮），再不过 → 尽力而为返回。
    - 记账：终审 PASS → 全部参与模型记 win；FAIL → 末层模型记 loss（全吞异常）。

    返回 dict 与 `run_trinity_agent` 同构（reply/steps/model/usage/tool_log/file_changes/media
    全累积）+ `mode:"conductor"`、`dag`（最终采用的三列表）、`verified`、`rounds`。
    """
    _wall = new_wall_deadline()  # 整个 conductor（规划/DAG各层/重规划）共享一个墙钟预算
    workdir = str(resolve_workspace(workdir))
    c = classify(task)
    task_kind = c.get("kind") or "general"
    review_gate = ReviewGate(router)

    planner = pick_model(router, "premium") or pick_model(router, "cheap")
    dag = await plan_workflow(
        router,
        task,
        planner=planner,
        task_kind=task_kind,
        wall_deadline=_wall,
        review_gate=review_gate,
        provider_role_prefix="conductor.plan.round_1",
    )

    # ── 退化：拿不到 DAG → 原样转发 TRINITY（不自造退化逻辑） ──
    if dag is None:
        await orchestrated_agent._emit(on_event, {"type": "replan", "reason": "no_dag_fallback_trinity"})
        return await orchestrated_agent.run_trinity_agent(
            router, task, workdir=workdir, max_steps=max_steps,
            history=history, allow=allow, on_event=on_event,
            preload_context=preload_context,
            wall_deadline=_wall,
        )

    reviewed = False
    final_review: ReviewDecision | None = None
    post_review_meta: dict[str, Any] = {}
    rounds = 0
    total: dict[str, Any] = {}
    tail_models: list[str] = []

    for rnd in range(_MAX_REPLAN + 1):  # 第 0 轮=首次 DAG，之后最多 _MAX_REPLAN 轮重规划
        rounds = rnd + 1
        await orchestrated_agent._emit(on_event, {"type": "dag", "round": rounds, "plan": dag})

        total, tail_models = await _execute_dag(
            router, task, dag,
            workdir=workdir, max_steps=max_steps, history=history, allow=allow,
            planner=planner or (dag["model_id"][-1] if dag["model_id"] else ""), task_kind=task_kind,
            on_event=on_event, preload_context=preload_context,
            wall_deadline=_wall,  # 重规划轮共享预算，不续命
            review_gate=review_gate,
            round_no=rounds,
        )

        # ── 终审：相对全部实际规划/节点/合成作者选独立 reviewer ──
        reviewer = review_gate.select_reviewer()
        # 用整份 total（含合成后的 reply + 累计 tool_log）喂审核官；plan 用 DAG 文本当验收上下文。
        plan_ctx = _dag_text(dag)
        wall_stopped = (
            total.get("stopped_reason") == "wall_cap"
            or orchestrated_agent._wall_expired(_wall)
        )
        reviewable_output = bool(
            total.get("output_kind")
            in {"tail_model", "model_synthesis", "deterministic_tail_merge"}
            and total.get("final_author_models")
        )
        if not reviewable_output:
            decision, verdict = None, "没有可归属到实际模型作者的最终产出，禁止模型审核放行"
        elif wall_stopped:
            decision, verdict = None, "共享墙钟预算已耗尽，跳过终审与重规划"
        else:
            try:
                with bind_provider_call_scope(role=f"conductor.review.round_{rounds}"):
                    decision, verdict = await orchestrated_agent._await_with_wall(
                        lambda: orchestrated_agent._review_with_gate(
                            router,
                            review_gate,
                            reviewer,
                            task,
                            plan_ctx,
                            total,
                        ),
                        _wall,
                    )
            except asyncio.TimeoutError:
                decision, verdict = None, "终审超过共享墙钟预算，按未通过处理"
        final_review = decision
        draft_reviewed = bool(decision and decision.reviewed)
        reviewed = draft_reviewed
        await orchestrated_agent._emit(on_event, {
            "type": "verify", "round": rounds,
            "reviewer": decision.observation.served_model if decision else None,
            "reviewer_requested": reviewer,
            "reviewer_vote_weight": decision.vote_weight if decision else 0,
            "reviewed": reviewed, "verified": False,
            "verdict": (verdict or "")[:600],
        })

        if draft_reviewed and decision is not None:
            # A PASS covers the current DAG output only.  Once the initiator
            # consumes that feedback and authors a summary, a different strong
            # family/domain must review the new artifact before it can be marked
            # reviewed.
            total, final_review, post_review_meta = (
                await orchestrated_agent._summarize_then_final_review(
                    router,
                    review_gate,
                    decision,
                    task=task,
                    plan=plan_ctx,
                    draft_result=total,
                    role_prefix=f"conductor.round_{rounds}",
                    wall_deadline=_wall,
                    on_event=on_event,
                )
            )
            reviewed = bool(final_review and final_review.reviewed)
            decision = final_review

        # ── 记账：PASS → 全部参与模型 win；FAIL → 末层模型 loss ──
        if reviewed:
            for m in review_gate.contributor_models:
                _record(m, task_kind, True)
        else:
            for m in tail_models:
                _record(m, task_kind, False)

        if draft_reviewed:
            # Whether the second review passes or fails, do not inherit the
            # first PASS and do not silently re-enter a different DAG loop.
            break
        if wall_stopped:
            break
        if rnd >= _MAX_REPLAN:
            break  # 重规划轮次用尽 → 尽力而为返回

        # ── 带评语重规划一次（整体不过 → 重新出一张 DAG，保持简单：不做局部重跑） ──
        if decision and decision.qualified:
            review_gate.add_contributor(
                decision.observation,
                role=f"review_feedback_round_{rounds}",
            )
            replan_feedback = decision.observation.verdict
        else:
            replan_feedback = verdict
        await orchestrated_agent._emit(on_event, {"type": "replan", "round": rounds + 1, "reason": "verify_failed"})
        new_dag = await plan_workflow(
            router, f"{task}\n\n【上一版工作流未通过终审，评语】：\n{(replan_feedback or '')[:800]}",
            planner=planner, task_kind=task_kind, wall_deadline=_wall,
            review_gate=review_gate,
            provider_role_prefix=f"conductor.plan.round_{rounds + 1}",
        )
        if new_dag is None:
            break  # 重规划失败 → 保留本轮结果，尽力而为返回
        dag = new_dag

    # ── 组装返回（与 run_trinity_agent 同构 + conductor 元信息） ──
    result = dict(total)
    result.setdefault("reply", "")
    result.setdefault("steps", 0)
    result.setdefault("tool_log", [])
    result.setdefault("file_changes", [])
    result.setdefault("media", [])
    result.setdefault("pending_videos", [])  # #6：生视频异步任务，回前端轮询到成片自动贴回
    result.setdefault("usage", {})
    result["usage"] = {k: v for k, v in (result.get("usage") or {}).items() if v}
    result["model"] = result.get("model")
    result["plan"] = None
    result["dag"] = dag
    result["rounds"] = rounds
    result["reviewed"] = bool(reviewed)
    result["verified"] = False
    result["machine_verified"] = False
    result["verification_level"] = "model_review_only" if reviewed else "none"
    result["escalated"] = False
    result["mode"] = "conductor"
    result["_route"] = {
        "mode": "conductor", "task_kind": task_kind,
        **review_gate.route_metadata(
            final_review,
            reviewed_output=str(result.get("reply") or ""),
        ),
        "steps_T": len(dag.get("model_id") or []),
        "rounds": rounds, "reviewed": bool(reviewed),
        "verified": False, "machine_verified": False,
        "final_model": result.get("model"),
        "final_author_models": list(result.get("final_author_models") or []),
        "final_route_receipt": result.get("final_route_receipt"),
        "final_output_kind": result.get("output_kind"),
        **post_review_meta,
    }
    if not result.get("final_author_models"):
        result["_route"]["review_unavailable_reason"] = "no_model_authored_output"
    outcome = orchestrated_agent.apply_outcome(result, None if reviewed else False)
    await orchestrated_agent._emit(on_event, {
        "type": "done", "mode": "conductor", "reviewed": bool(reviewed),
        "verified": False, "machine_verified": False,
        "rounds": rounds, "model": result.get("model"), "outcome": outcome,
    })
    return result


def _dag_text(dag: dict[str, Any]) -> str:
    """把 DAG 三列表压成给审核官/日志看的可读文本（每步一行：#i 模型 ← [依赖] : 指令摘要）。"""
    models = dag.get("model_id") or []
    subtasks = dag.get("subtasks") or []
    access = dag.get("access_list") or []
    lines: list[str] = []
    for i in range(len(models)):
        dep = access[i] if i < len(access) else []
        instr = (subtasks[i] if i < len(subtasks) else "") or ""
        lines.append(f"#{i} {models[i]} ← 依赖{dep or '无'} : {instr[:120]}")
    return "\n".join(lines) or "(空 DAG)"
