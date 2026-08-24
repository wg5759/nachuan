"""F2 点将官 pick_next：正常解析 / 话痨容忍 / 无效模型拒绝 / need_tools 替换 / 异常→None。

版本无关手法（照抄 test_coordinator_snapshot）：假 router 只实现 routes_info；用 monkeypatch
掌控每个假模型的 modality/skills/tool_capable（不碰真 catalog）与战绩（不碰真 sqlite），并
monkeypatch coordinator 模块内引用的 chat_with_fallback，让点将官按脚本回话。
"""

from __future__ import annotations

import orchestrator.coordinator as co
import orchestrator.scoreboard as sb

# 版本无关假池：便宜可调工具 / 强可调工具 / 强不可调工具 三种；echo 与生图应被快照过滤掉。
_ROUTES = [
    {"model": "echo", "provider": "e", "tier": "free", "rank": 0, "flagship": False},
    {"model": "cheapA", "provider": "vX", "tier": "cheap", "rank": 3, "flagship": False},
    {"model": "premC", "provider": "vY", "tier": "premium", "rank": 2, "flagship": False},
    {"model": "flagD", "provider": "vZ", "tier": "premium", "rank": 0, "flagship": True},
    {"model": "imgE", "provider": "vI", "tier": "free", "rank": 0, "flagship": False},
]

_META = {
    "cheapA": {"modality": "chat", "skills": ["zh"], "tool_capable": True},
    "premC": {"modality": "chat", "skills": ["code"], "tool_capable": True},
    "flagD": {"modality": "chat", "skills": ["long"], "tool_capable": False},  # 不能调工具
    "imgE": {"modality": "image", "skills": [], "tool_capable": True},
}


class _Router:
    def __init__(self, routes=None):
        self._routes = _ROUTES if routes is None else routes

    def routes_info(self):
        return [dict(r) for r in self._routes]


def _patch(monkeypatch, reply: str, *, capture=None):
    """掌控快照来源（preset_meta/win_rate）+ 让点将官 LLM 按脚本回 `reply`。

    capture 传入 list 时，记录点将官实际用的决策模型 id（验证它用 cheap 档）。
    """
    def fake_meta(model_id):
        m = _META.get(model_id, {})
        return {
            "rank": 0, "flagship": False,
            "tool_capable": m.get("tool_capable", True),
            "skills": list(m.get("skills") or []),
            "modality": m.get("modality", "chat"),
        }

    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)
    monkeypatch.setattr(sb, "summary_line", lambda models, kind: "")

    async def fake_chat(router, req):
        if capture is not None:
            capture.append(req.model)
        return ({"choices": [{"message": {"content": reply}}]}, req.model, None)

    monkeypatch.setattr(co, "chat_with_fallback", fake_chat)


# ────────────────────────────── 正常解析 ──────────────────────────────
async def test_pick_next_parses_valid_decision(monkeypatch):
    """干净的一行 JSON → 原样解析出 model/role/instruction；决策用便宜模型。"""
    used: list[str] = []
    _patch(
        monkeypatch,
        '{"model":"premC","role":"thinker","instruction":"先拆解任务再列步骤"}',
        capture=used,
    )
    d = await co.pick_next(_Router(), "user: 帮我写个爬虫\n", task_kind="code")
    assert d == {"model": "premC", "role": "thinker", "instruction": "先拆解任务再列步骤"}
    # 点将官用 cheap 档模型做决策（便宜/免费），不烧强模型
    assert used == ["cheapA"]


async def test_pick_next_role_case_insensitive(monkeypatch):
    """role 大小写/空格容忍：THINKER / Worker 等归一化为小写合法角色。"""
    _patch(monkeypatch, '{"model": "cheapA", "role": "WORKER", "instruction": "动手"}')
    d = await co.pick_next(_Router(), "t", need_tools=True)
    assert d is not None and d["role"] == "worker" and d["model"] == "cheapA"


# ────────────────────────────── 话痨容忍 ──────────────────────────────
async def test_pick_next_tolerates_chatty_model(monkeypatch):
    """模型在 JSON 前后废话 / 包 ```json 围栏 → 仍能抽出第一个 {...}。"""
    reply = (
        "好的，我来分析一下当前进展。综合来看，应该让 premC 出思路。\n"
        "```json\n"
        '{"model": "premC", "role": "thinker", "instruction": "梳理架构"}\n'
        "```\n"
        "希望这个安排合理。"
    )
    _patch(monkeypatch, reply)
    d = await co.pick_next(_Router(), "transcript...")
    assert d is not None
    assert d["model"] == "premC" and d["role"] == "thinker" and d["instruction"] == "梳理架构"


async def test_pick_next_picks_first_valid_json_when_multiple(monkeypatch):
    """回复里有多个 {...} 片段 → 取第一个能解析成对象的。"""
    reply = '闲聊 {不是json} 再来 {"model":"cheapA","role":"verifier","instruction":"审核"} 结束'
    _patch(monkeypatch, reply)
    d = await co.pick_next(_Router(), "x")
    assert d is not None and d["model"] == "cheapA" and d["role"] == "verifier"


# ────────────────────────────── 无效模型 / 无效角色拒绝 ──────────────────────────────
async def test_pick_next_rejects_model_not_in_pool(monkeypatch):
    """点了池外/幻觉模型（如被过滤的 echo、或压根不存在的名字）→ 返回 None。"""
    _patch(monkeypatch, '{"model":"gpt-9-imaginary","role":"worker","instruction":"go"}')
    assert await co.pick_next(_Router(), "x") is None


async def test_pick_next_rejects_filtered_model(monkeypatch):
    """点了 echo（联通兜底，已被快照过滤）→ 不在快照里 → None。"""
    _patch(monkeypatch, '{"model":"echo","role":"worker","instruction":"go"}')
    assert await co.pick_next(_Router(), "x") is None


async def test_pick_next_rejects_invalid_role(monkeypatch):
    """role 不在 thinker/worker/verifier → None。"""
    _patch(monkeypatch, '{"model":"premC","role":"boss","instruction":"go"}')
    assert await co.pick_next(_Router(), "x") is None


async def test_pick_next_none_on_unparseable(monkeypatch):
    """回复里根本没有 JSON 对象 → None。"""
    _patch(monkeypatch, "我觉得应该让最强的模型上，但我不确定该用哪个。")
    assert await co.pick_next(_Router(), "x") is None


# ────────────────────────────── need_tools 替换 ──────────────────────────────
async def test_pick_next_substitutes_when_need_tools_and_picked_lacks_tools(monkeypatch):
    """need_tools=True 但点了不可调工具的 flagD → 快照内改选 tool_capable 替代（同 tier 优先）。"""
    _patch(monkeypatch, '{"model":"flagD","role":"worker","instruction":"动手做"}')
    d = await co.pick_next(_Router(), "x", need_tools=True)
    assert d is not None
    assert d["role"] == "worker"
    # flagD 不可调工具 → 同为 premium 的 premC 是最优替代（同 tier + 可调工具）
    assert d["model"] == "premC"


async def test_pick_next_keeps_incapable_model_when_tools_not_needed(monkeypatch):
    """need_tools=False 时点了不可调工具的模型（thinker 纯文本无需工具）→ 保留不替换。

    注：原用 flagD 验证，但王牌闸现在会先换掉 flagship——改用「去王牌标的同池」验证
    同一语义（need_tools=False 不做 tool_capable 替换）。"""
    routes = [dict(r, flagship=False) for r in _ROUTES]  # 同池但全部非王牌（不触发王牌闸）
    _patch(monkeypatch, '{"model":"flagD","role":"thinker","instruction":"想一想"}')
    d = await co.pick_next(_Router(routes), "x", need_tools=False)
    assert d is not None and d["model"] == "flagD" and d["role"] == "thinker"


async def test_pick_next_none_when_need_tools_but_no_capable_in_pool(monkeypatch):
    """need_tools=True 且快照里没有任何可调工具模型 → None（不硬塞不能动手的）。"""
    routes = [
        {"model": "flagD", "provider": "vZ", "tier": "premium", "rank": 0, "flagship": True},
    ]
    _patch(monkeypatch, '{"model":"flagD","role":"worker","instruction":"go"}')
    assert await co.pick_next(_Router(routes), "x", need_tools=True) is None


# ────────────────────────────── 异常 → None ──────────────────────────────
async def test_pick_next_none_on_llm_exception(monkeypatch):
    """决策 LLM 调用抛异常 → 吞掉返回 None（点将失败绝不挡任务）。"""
    def fake_meta(model_id):
        m = _META.get(model_id, {})
        return {"rank": 0, "flagship": False,
                "tool_capable": m.get("tool_capable", True),
                "skills": [], "modality": m.get("modality", "chat")}

    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)

    async def boom(router, req):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(co, "chat_with_fallback", boom)
    assert await co.pick_next(_Router(), "x") is None


async def test_pick_next_none_on_empty_pool(monkeypatch):
    """空池（无任何可点将模型）→ None，且不发起 LLM 调用。"""
    called = {"n": 0}

    async def fake_chat(router, req):
        called["n"] += 1
        return ({"choices": [{"message": {"content": "{}"}}]}, req.model, None)

    monkeypatch.setattr(co, "preset_meta", lambda m: {"modality": "chat", "skills": [], "tool_capable": True})
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)
    monkeypatch.setattr(co, "chat_with_fallback", fake_chat)

    assert await co.pick_next(_Router([]), "x") is None
    assert called["n"] == 0  # 空池直接返回，不浪费一次 LLM 调用


async def test_flagship_pick_swapped_to_non_flagship(monkeypatch):
    """王牌闸：点将官点了 flagship → 确定性换成同档最强非王牌（自动路由不烧王牌）。"""
    reply = '{"model":"flagD","role":"worker","instruction":"上"}'
    _patch(monkeypatch, reply)
    out = await co.pick_next(_Router(), "user: 干活\n", need_tools=True)
    assert out is not None
    assert out["model"] == "premC"  # premium 非王牌里最强（rank 2），而不是王牌 flagD
    assert out["role"] == "worker"


# ════════════════════ 首轮点将短路 pick_by_record（0 LLM 调用，批6①）════════════════════
def _patch_record(monkeypatch, stats: dict[str, tuple[int, int]]):
    """掌控 pool_snapshot 的 preset_meta + 战绩 stats（模块级），不碰真 catalog/sqlite/LLM。

    stats: {model: (wins, losses)}。win_rate 一律 None（短路只看 stats 的场次/胜率）。
    并断言全程不发 LLM 调用（打桩 chat_with_fallback，命中即测试失败）。
    """
    def fake_meta(model_id):
        m = _META.get(model_id, {})
        return {"rank": 0, "flagship": False,
                "tool_capable": m.get("tool_capable", True),
                "skills": list(m.get("skills") or []),
                "modality": m.get("modality", "chat")}

    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)
    monkeypatch.setattr(sb, "stats", lambda model, kind: stats.get(model))

    async def no_llm(router, req):  # 短路是 0 LLM 调用，若被调到即为错
        raise AssertionError("pick_by_record 不应发起任何 LLM 调用")

    monkeypatch.setattr(co, "chat_with_fallback", no_llm)


def test_pick_by_record_hits_champion(monkeypatch):
    """够场次且胜率达标 → 直选胜率冠军当 worker，带 by=record，0 LLM 调用。"""
    # premC 8/2=80%，cheapA 3/3=50%；premC 是冠军。
    _patch_record(monkeypatch, {"premC": (8, 2), "cheapA": (3, 3)})
    out = co.pick_by_record(_Router(), "code", need_tools=True)
    assert out == {"model": "premC", "role": "worker", "instruction": "", "by": "record"}


def test_pick_by_record_none_when_not_enough_games(monkeypatch):
    """场次不够（< min_games）→ None，不硬选（退回点将官）。"""
    # premC 胜率高(100%)但只 2 场 < 默认 min_games=3。
    _patch_record(monkeypatch, {"premC": (2, 0)})
    assert co.pick_by_record(_Router(), "code", need_tools=True) is None


def test_pick_by_record_none_when_win_rate_low(monkeypatch):
    """够场次但胜率 < 0.6 → None（平庸模型不硬选）。"""
    _patch_record(monkeypatch, {"premC": (5, 5), "cheapA": (4, 6)})  # 50% / 40%
    assert co.pick_by_record(_Router(), "code", need_tools=True) is None


def test_pick_by_record_need_tools_filters_incapable(monkeypatch):
    """need_tools=True → 只在可调工具候选里选；不可调工具的冠军被排除。"""
    # flagD 战绩最好但 flagship+不可调工具（双重排除）；premC 可调工具且达标 → 选它。
    _patch_record(monkeypatch, {"flagD": (20, 0), "premC": (7, 1)})
    out = co.pick_by_record(_Router(), "code", need_tools=True)
    assert out is not None and out["model"] == "premC"


def test_pick_by_record_excludes_flagship(monkeypatch):
    """flagship 一律排除（自动路由不烧王牌），即便它战绩最好。"""
    # flagD(flagship) 战绩最好，但快照里 flagD tool_capable=False；改用非工具场景（need_tools=False）
    # 仍应排除王牌：给 flagD 顶级战绩，cheapA 达标 → 选 cheapA（非王牌）。
    _patch_record(monkeypatch, {"flagD": (30, 0), "cheapA": (8, 2)})
    out = co.pick_by_record(_Router(), "chat", need_tools=False)
    assert out is not None and out["model"] != "flagD" and out["model"] == "cheapA"


def test_pick_by_record_tie_break_by_rank(monkeypatch):
    """胜率并列 → 取 rank 小者（更强）。premC(rank2) 优于 cheapA(rank3)。"""
    _patch_record(monkeypatch, {"premC": (8, 2), "cheapA": (8, 2)})  # 都 80%
    out = co.pick_by_record(_Router(), "code", need_tools=True)
    assert out is not None and out["model"] == "premC"  # rank 2 < 3


def test_pick_by_record_none_on_empty_pool(monkeypatch):
    """空池 → None。"""
    _patch_record(monkeypatch, {})
    assert co.pick_by_record(_Router([]), "code") is None


def test_pick_by_record_none_when_no_records(monkeypatch):
    """池里有模型但都没战绩 → None（退回点将官）。"""
    _patch_record(monkeypatch, {})
    assert co.pick_by_record(_Router(), "code", need_tools=True) is None


def test_pick_by_record_survives_stats_exception(monkeypatch):
    """stats 抛异常 → 吞掉返回 None（短路失败绝不挡任务）。"""
    def fake_meta(model_id):
        m = _META.get(model_id, {})
        return {"rank": 0, "flagship": False,
                "tool_capable": m.get("tool_capable", True),
                "skills": [], "modality": m.get("modality", "chat")}

    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)

    def boom(model, kind):
        raise RuntimeError("scoreboard down")

    monkeypatch.setattr(sb, "stats", boom)
    assert co.pick_by_record(_Router(), "code", need_tools=True) is None
