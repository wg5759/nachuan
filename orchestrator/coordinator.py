"""点将官（Coordinator）—— Fugu「对内是一支被小协调器点将的模型舰队」的调度中枢。

本文件分两期落地：
- **批次 1（当前）**：只做 `pool_snapshot()` / `pool_text()` —— 实时「池子快照」，即 Fugu 的
  k-of-n 可换池：每次点将都用当前在线模型 + 能力画像(F1) + 历史战绩(F6) 的实时视图，
  新模型接入即刻可被点。这是后续「点将官」路由的地基。
- **批次 2（后续）**：在此文件加 `pick_next(...)`（永不答题的点将决策），消费本文件的快照。

版本无关：快照只依据 tier / rank / flagship / skills / tool_capable / 战绩这些**数据**，
绝不写死型号名做逻辑判断。
"""

from __future__ import annotations

import json
import re
from typing import Any

from gateway.catalog import preset, preset_meta, rank_sort_key
from gateway.failover import chat_with_fallback
from gateway.provider_call_ledger import (
    bind_provider_call_scope,
    current_provider_call_context,
)
from gateway.schemas import ChatCompletionRequest
from orchestrator import modes, scoreboard

# 点将官只认这三种角色（Fugu TRINITY）；其它一律判无效 → 返回 None 让调用方兜底。
_VALID_ROLES = {"thinker", "worker", "verifier"}


def _is_local_provider(provider: str | None) -> bool:
    """该 provider 是否本地模型（Ollama/LM Studio 一类）。

    版本无关：不写死型号名，改查 catalog 预设的 `region`——预设里 region=='local' 的厂商
    （ollama/lmstudio）即本地。查不到预设（自定义连接）时保守判非本地（不误标）。
    异常一律吞掉当非本地（标注只是锦上添花，绝不能拖垮快照）。
    """
    if not provider:
        return False
    try:
        p = preset(provider)
        return bool(p and p.get("region") == "local")
    except Exception:  # noqa: BLE001 preset 查询出错当非本地，不炸快照
        return False


def pool_snapshot(router: Any, task_kind: str = "general") -> list[dict[str, Any]]:
    """当前在线模型池的实时快照（供点将官/编排提示词消费）。

    遍历 `router.routes_info()`，过滤 modality=chat 且非 echo（echo 仅联通性兜底、不点将）；
    每个模型输出 `{model, tier, rank, flagship, tool_capable, skills, win_rate}`：
    - skills / tool_capable / modality 经 `catalog.preset_meta`（未登记默认 []/True/chat）；
    - win_rate 经 F6 记分牌，**无记录则不带该键**（区分「没打过」与「胜率 0」）。

    任何一模型解析出错都跳过它，绝不让快照整体失败。
    """
    infos = router.routes_info()
    snapshot: list[dict[str, Any]] = []
    for r in infos or []:
        try:
            model = r.get("model")
            if not model or model == "echo":
                continue
            meta = preset_meta(model)
            modality = r.get("modality", meta.get("modality", "chat"))
            if modality != "chat":
                continue  # 生图/生视频等非对话模态不进点将池
            entry: dict[str, Any] = {
                "model": model,
                "tier": r.get("tier"),
                "rank": r.get("rank", 0),
                "flagship": bool(r.get("flagship", False)),
                "tool_capable": bool(
                    r.get("tool_capable", meta.get("tool_capable", True))
                ),
                "skills": list(r.get("skills") or meta.get("skills") or []),
            }
            # 本地模型标注（F 批6④）：provider region=='local' → 标 local=True，让点将官提示词
            # 里能看到「· 本地」（工具能力/稳定性未知）。只做标注、不改选择逻辑——战绩会自己教它。
            if _is_local_provider(r.get("provider")):
                entry["local"] = True
            wr = scoreboard.win_rate(model, task_kind)
            if wr is not None:
                entry["win_rate"] = wr
            snapshot.append(entry)
        except Exception:  # noqa: BLE001 单模型异常不拖垮整份快照
            continue
    return snapshot


def pool_text(snapshot: list[dict[str, Any]]) -> str:
    """把快照压成给 LLM 提示词的紧凑多行文本（每模型一行：id·档位·技能·[战绩]）。

    形如：
        premium-reviewer · premium · code/reasoning/long/zh · 胜率80%
        glm · cheap · zh/code
    空池返回 ""。
    """
    lines: list[str] = []
    for e in snapshot or []:
        model = e.get("model", "?")
        tier = e.get("tier") or "?"
        skills = "/".join(e.get("skills") or []) or "-"
        flag = " · 王牌" if e.get("flagship") else ""
        tools = "" if e.get("tool_capable", True) else " · 无工具"
        local = " · 本地" if e.get("local") else ""
        parts = [f"{model} · {tier} · {skills}"]
        if "win_rate" in e:
            parts.append(f"胜率{round(e['win_rate'] * 100)}%")
        line = " · ".join(parts) + flag + tools + local
        lines.append(line)
    return "\n".join(lines)


# ───────────────────────── 首轮点将短路（0 LLM 调用，F 批6①） ─────────────────────────
# Fugu 的路由本质是「什么题给什么模型」——一旦某 task_kind 攒够战绩且有明显冠军，首轮无需再花
# 一次点将官 LLM 调用去问「派谁」，直接按历史胜率派冠军当 worker。只用于**首轮**（轮转中仍由
# 点将官依当前进展决策）；场次不够/胜率不高/无冠军 → 返回 None，老老实实走点将官（不硬选）。

# 战绩短路的胜率门槛：低于此值不信任战绩、退回点将官（避免小样本噪声或平庸模型被硬选）。
_RECORD_MIN_WIN_RATE = 0.6


def pick_by_record(
    router: Any,
    task_kind: str,
    *,
    need_tools: bool = False,
    min_games: int = 3,
) -> dict[str, Any] | None:
    """首轮点将短路：按历史战绩直选该 task_kind 的胜率冠军当 worker（0 次 LLM 调用）。

    命中条件（全满足才短路，否则 None 退回点将官）：
    - 在**非王牌(flagship)** 候选里挑（自动路由不烧王牌，与点将官王牌闸同策）；
    - need_tools=True 时只在 tool_capable 候选里挑（要动手就得能调工具）；
    - 该 task_kind 场次（wins+losses）≥ min_games 且胜率 ≥ _RECORD_MIN_WIN_RATE；
    - 胜率并列取 rank 小者（更强）。

    命中返回 `{"model", "role":"worker", "instruction":"", "by":"record"}`；不命中/异常 → None
    （战绩短路是加速优化，坏了绝不能挡任务，一律优雅降级走点将官）。
    """
    try:
        snapshot = pool_snapshot(router, task_kind)
        if not snapshot:
            return None
        cands = [e for e in snapshot if not e.get("flagship")]
        if need_tools:
            cands = [e for e in cands if e.get("tool_capable", True)]
        if not cands:
            return None

        best: dict[str, Any] | None = None
        best_rate = -1.0
        for e in cands:
            rec = scoreboard.stats(e.get("model"), task_kind)
            if rec is None:
                continue
            wins, losses = rec
            total = wins + losses
            if total < min_games:
                continue  # 场次不够，不信任
            rate = wins / total if total > 0 else 0.0
            if rate < _RECORD_MIN_WIN_RATE:
                continue  # 胜率不达门槛，不硬选
            # 胜率高者胜；并列取 rank 小者（更强）。
            if rate > best_rate or (
                rate == best_rate
                and best is not None
                and rank_sort_key(e.get("rank")) < rank_sort_key(best.get("rank"))
            ):
                best = e
                best_rate = rate

        if best is None:
            return None
        return {"model": best["model"], "role": "worker", "instruction": "", "by": "record"}
    except Exception:  # noqa: BLE001 战绩短路失败绝不挡任务，退回点将官
        return None


# ─────────────────────────── F2 点将官（Coordinator，永不答题） ───────────────────────────
# Fugu 核心机制②：0.6B 小协调器只输出「派谁 + 演什么角色 + 给它一句定制指令」，
# **绝不生成给用户的答案**——答案永远来自被点将的前沿模型。这里用便宜/免费模型（pick_model
# "cheap"）经 failover 做这一步决策；解析/校验任一失败即返回 None，由 TRINITY 循环规则兜底。

_JSON_OBJ = re.compile(r"\{.*?\}", re.S)  # 从话痨回复里抽第一个 {...}（非贪婪 + 跨行）


def _extract_json_obj(text: str) -> dict[str, Any] | None:
    """从模型回复里抽出第一个能 json.loads 成 dict 的 {...}（容忍模型在 JSON 前后废话）。

    优先整体解析；失败则用正则从头逐个候选块试 loads，取第一个成功的对象。全失败→None。
    """
    s = (text or "").strip()
    if not s:
        return None
    # 去掉 ```json ... ``` 围栏（模型爱包代码块）。
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", s).strip()
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
    except Exception:  # noqa: BLE001 整体不是纯 JSON，转正则抽取
        pass
    for m in _JSON_OBJ.finditer(s):
        try:
            obj = json.loads(m.group(0))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _substitute_non_flagship(
    snapshot: list[dict[str, Any]], picked: dict[str, Any], *, need_tools: bool
) -> dict[str, Any]:
    """点将点到王牌(flagship)时的确定性降档：换同档最强的非王牌（本项目经济学：自动路由不烧王牌，
    王牌只归"最强模式/升级路径"显式动用）。池里没有非王牌可换时保留原选（不至于无模型可用）。
    不指望提示词拦住——LLM 看见"王牌"标签反而爱点它，必须代码兜底。"""
    pool = [e for e in snapshot if not e.get("flagship")]
    if need_tools:
        pool = [e for e in pool if e.get("tool_capable", True)] or pool
    if not pool:
        return picked
    want_tier = picked.get("tier")
    pool.sort(
        key=lambda e: (
            0 if e.get("tier") == want_tier else 1,
            rank_sort_key(e.get("rank")),
        )
    )
    return pool[0]


def _substitute_tool_capable(snapshot: list[dict[str, Any]], picked: dict[str, Any]) -> str | None:
    """need_tools=True 但所点模型不能 function-calling 时，在快照内改选一个 tool_capable 近似替代。

    偏好：同 tier 优先，其次 flagship，再按 rank（越小越强）。快照里没有任何 tool_capable
    模型时返回 None（由调用方兜底），绝不硬塞一个不能动手的。
    """
    want_tier = picked.get("tier")
    capable = [e for e in snapshot if e.get("tool_capable", True)]
    if not capable:
        return None
    capable.sort(
        key=lambda e: (
            0 if e.get("tier") == want_tier else 1,   # 同档优先
            0 if e.get("flagship") else 1,             # 王牌次之
            rank_sort_key(e.get("rank")),               # 再按 rank
        )
    )
    return capable[0]["model"]


async def pick_next(
    router: Any,
    transcript: str,
    *,
    task_kind: str = "general",
    need_tools: bool = False,
) -> dict[str, Any] | None:
    """点将官：给定当前 raw transcript，用便宜模型决策下一步派谁、演什么角色、给什么指令。

    返回 `{"model": <池中id>, "role": "thinker|worker|verifier", "instruction": <一句定制指令>}`，
    或 **None**（任何异常/超时/解析失败/校验不过——点将失败绝不能挡任务，由调用方规则兜底）。

    关键设计（照抄 Fugu）：
    - **决策模型用 cheap**（`modes.pick_model(router,"cheap")`），经 `chat_with_fallback` 调用；
      **其输出永不作为答案给用户**，只产调度决策。
    - 提示词喂 **raw transcript**（`role: content\n` 裸文本，调用方传入）+ 池子快照 + 战绩行，
      Fugu 发现裸文本比 chat template 路由更准。
    - 校验：model 必须在快照里；role 必须合法；need_tools=True 时若所点模型不可调工具，
      在快照内改选 tool_capable 近似替代（同 tier 优先）。
    """
    try:
        snapshot = pool_snapshot(router, task_kind)
        if not snapshot:
            return None  # 空池无从点将
        decider = modes.pick_model(router, "cheap")
        if not decider:
            return None

        board = scoreboard.summary_line([e["model"] for e in snapshot], task_kind)
        prompt_parts = [
            "你是一支模型舰队的调度器（点将官）。你的唯一职责是决定下一步派哪个模型、"
            "让它扮演什么角色、给它一句定制指令。你【绝不】自己回答用户的任务，只输出调度决策。",
            "",
            "【可用模型池】(id · 档位 · 技能[· 胜率][· 王牌/无工具])：",
            pool_text(snapshot),
        ]
        if board:
            prompt_parts += ["", board]
        prompt_parts += [
            "",
            "【当前对话进展（原始裸文本 transcript）】：",
            (transcript or "(空)")[:6000],
            "",
            "角色含义：thinker=纯思考出思路/拆解（不动工具）；worker=带工具动手执行；"
            "verifier=独立审核当前结果是否达标。",
            "复杂/陌生任务建议第一手先派 thinker 出思路——**思路质量决定全局，thinker 要点"
            "premium 档的强模型（非王牌）**；出好思路后，照着清晰思路执行的 worker 可以点 cheap 档省钱；"
            "已有清晰思路或简单直做的才直接 worker。",
            "标『王牌』的模型成本极高，一律不要点它（升级到王牌由系统另行决定）。",
            (
                "本步需要动手（可能要用工具），请优先点一个能调用工具（未标『无工具』）的模型。"
                if need_tools
                else "根据进展判断本步最该做什么，选最合适的模型与角色。"
            ),
            "",
            '只输出一行 JSON，格式：{"model":"<池中id>","role":"thinker|worker|verifier",'
            '"instruction":"<给该模型的一句定制指令>"}，不要输出任何其它内容。',
        ]
        prompt = "\n".join(prompt_parts)

        req = ChatCompletionRequest(  # type: ignore[call-arg]
            model=decider,
            messages=[{"role": "user", "content": prompt}],
        )
        provider_role = current_provider_call_context().role or "coordinator.pick_next"
        with bind_provider_call_scope(role=provider_role):
            res, _served, _route = await chat_with_fallback(router, req)
        content = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""

        obj = _extract_json_obj(content)
        if not obj:
            return None

        model = obj.get("model")
        role = obj.get("role")
        instruction = obj.get("instruction") or ""
        if not isinstance(model, str) or not isinstance(role, str):
            return None
        role = role.strip().lower()
        if role not in _VALID_ROLES:
            return None

        by_id = {e["model"]: e for e in snapshot}
        picked = by_id.get(model.strip())
        if picked is None:
            return None  # 点了池外/幻觉模型 → 不信任，兜底
        model = model.strip()

        # 王牌闸（确定性）：点将点到 flagship → 换同档最强非王牌（自动路由不烧王牌）。
        if picked.get("flagship"):
            picked = _substitute_non_flagship(snapshot, picked, need_tools=need_tools)
            model = picked["model"]

        # need_tools：所点模型不可调工具 → 快照内改选近似替代（同 tier 优先）。
        if need_tools and not picked.get("tool_capable", True):
            alt = _substitute_tool_capable(snapshot, picked)
            if alt is None:
                return None  # 池里没有能动手的 → 兜底
            model = alt

        return {
            "model": model,
            "role": role,
            "instruction": str(instruction).strip(),
        }
    except Exception:  # noqa: BLE001 点将失败绝不能挡任务
        return None
