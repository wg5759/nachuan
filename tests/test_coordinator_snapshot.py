"""点将官池子快照：过滤(排 echo / 排非 chat 模态) + 字段构造 + 战绩注入 + pool_text 格式。

版本无关手法（照抄 test_orchestrated_agent）：假 router 只实现 routes_info；用 monkeypatch
掌控每个假模型的 modality/skills/tool_capable（不碰真 catalog），及其战绩（不碰真 sqlite）。
"""

from __future__ import annotations

from orchestrator import coordinator as co
from orchestrator import scoreboard as sb

# 版本无关的假池：便宜/强/生图 三种模态与档位；echo 应被过滤掉。
_ROUTES = [
    {"model": "echo", "provider": "e", "tier": "free", "rank": 0, "flagship": False},
    {"model": "cheapA", "provider": "vX", "tier": "cheap", "rank": 3, "flagship": False},
    {"model": "premC", "provider": "vY", "tier": "premium", "rank": 2, "flagship": False},
    {"model": "flagD", "provider": "vZ", "tier": "premium", "rank": 0, "flagship": True},
    {"model": "imgE", "provider": "vI", "tier": "free", "rank": 0, "flagship": False},  # 生图，非 chat
]

# 每个假模型的画像（modality 决定是否进池；skills/tool_capable 进快照字段）。
_META = {
    "cheapA": {"modality": "chat", "skills": ["zh", "code"], "tool_capable": True},
    "premC": {"modality": "chat", "skills": ["code", "reasoning"], "tool_capable": True},
    "flagD": {"modality": "chat", "skills": ["code", "long"], "tool_capable": False},
    "imgE": {"modality": "image", "skills": [], "tool_capable": True},
}


class _Router:
    def __init__(self, routes=None):
        self._routes = _ROUTES if routes is None else routes

    def routes_info(self):
        return [dict(r) for r in self._routes]


def _patch(monkeypatch, win_rates=None):
    """掌控 preset_meta（模态/技能/工具）与 scoreboard.win_rate（战绩），不碰真 catalog/sqlite。"""
    def fake_meta(model_id):
        m = _META.get(model_id, {})
        return {
            "rank": 0, "flagship": False,
            "tool_capable": m.get("tool_capable", True),
            "skills": list(m.get("skills") or []),
            "modality": m.get("modality", "chat"),
        }

    wr = win_rates or {}
    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: wr.get(model))


def test_snapshot_filters_echo_and_non_chat(monkeypatch):
    """快照排除 echo 与非 chat 模态（生图），只留可点将的对话模型。"""
    _patch(monkeypatch)
    snap = co.pool_snapshot(_Router())
    models = {e["model"] for e in snap}
    assert "echo" not in models        # 联通兜底不点将
    assert "imgE" not in models        # 生图非对话模态被过滤
    assert models == {"cheapA", "premC", "flagD"}


def test_snapshot_fields_from_meta_and_routes(monkeypatch):
    """每条快照字段来源正确：tier/rank/flagship 取 routes，skills/tool_capable 取 preset_meta。"""
    _patch(monkeypatch)
    snap = co.pool_snapshot(_Router())
    by_id = {e["model"]: e for e in snap}

    c = by_id["cheapA"]
    assert c["tier"] == "cheap" and c["rank"] == 3 and c["flagship"] is False
    assert c["skills"] == ["zh", "code"] and c["tool_capable"] is True

    f = by_id["flagD"]
    assert f["flagship"] is True             # 来自 routes_info
    assert f["tool_capable"] is False        # 来自 preset_meta（该模型不可调工具）


def test_snapshot_winrate_present_only_when_recorded(monkeypatch):
    """有战绩才带 win_rate 键；无记录（None）则不带该键——区分『没打过』与『胜率 0』。"""
    _patch(monkeypatch, win_rates={"premC": 0.8, "cheapA": 0.0})  # flagD 无记录
    snap = co.pool_snapshot(_Router(), task_kind="code")
    by_id = {e["model"]: e for e in snap}

    assert by_id["premC"]["win_rate"] == 0.8
    assert by_id["cheapA"]["win_rate"] == 0.0  # 胜率 0 是真实数据，要带
    assert "win_rate" not in by_id["flagD"]    # 无记录 → 不带键


def test_pool_text_format(monkeypatch):
    """pool_text：每模型一行 id·档位·技能[·胜率][·王牌/无工具]；空池返回 ''。"""
    _patch(monkeypatch, win_rates={"premC": 0.8})
    snap = co.pool_snapshot(_Router(), task_kind="code")
    text = co.pool_text(snap)
    lines = text.splitlines()
    assert len(lines) == 3  # cheapA / premC / flagD

    joined = text
    assert "cheapA · cheap · zh/code" in joined
    assert "premC · premium · code/reasoning · 胜率80%" in joined
    assert "王牌" in joined       # flagD 是 flagship
    assert "无工具" in joined     # flagD tool_capable=False

    assert co.pool_text([]) == ""


def test_snapshot_empty_router(monkeypatch):
    """空 router（无任何路由）→ 空快照，不抛。"""
    _patch(monkeypatch)
    assert co.pool_snapshot(_Router([])) == []


def test_snapshot_survives_bad_scoreboard(monkeypatch):
    """记分牌读取抛异常时，单模型跳过不影响其余（快照绝不整体失败）。"""
    _patch(monkeypatch)

    def boom(model, kind):
        if model == "premC":
            raise RuntimeError("scoreboard down")
        return None

    monkeypatch.setattr(sb, "win_rate", boom)
    snap = co.pool_snapshot(_Router())
    models = {e["model"] for e in snap}
    # premC 那次 win_rate 抛错 → 该模型被跳过；其余仍在
    assert "premC" not in models
    assert {"cheapA", "flagD"} <= models


# ════════════════════ 本地模型标注（region=local → local=True，批6④）════════════════════
# 版本无关：靠 catalog 预设的 region 判本地（不写死型号名）。测试 monkeypatch co.preset
# 让某 provider 名映射到 region=='local'，验证快照打 local 标 + pool_text 尾巴带「· 本地」。

# 加一个「本地」provider 的模型（provider=locP，对应预设 region=local）。
_ROUTES_LOCAL = _ROUTES + [
    {"model": "localX", "provider": "locP", "tier": "cheap", "rank": 0, "flagship": False},
]
_META_LOCAL = dict(_META, localX={"modality": "chat", "skills": ["zh"], "tool_capable": False})


def _patch_local(monkeypatch, local_providers=("locP",)):
    """在 _patch 基础上，把 co.preset 换成：本地 provider 名 → {region:'local'}，其余 → None。"""
    def fake_meta(model_id):
        m = _META_LOCAL.get(model_id, {})
        return {"rank": 0, "flagship": False,
                "tool_capable": m.get("tool_capable", True),
                "skills": list(m.get("skills") or []),
                "modality": m.get("modality", "chat")}

    monkeypatch.setattr(co, "preset_meta", fake_meta)
    monkeypatch.setattr(sb, "win_rate", lambda model, kind: None)
    monkeypatch.setattr(
        co, "preset",
        lambda name: {"region": "local"} if name in local_providers else None,
    )


def test_snapshot_marks_local_by_region(monkeypatch):
    """provider 对应预设 region=='local' → 快照 entry 带 local=True；云端模型不带该键。"""
    _patch_local(monkeypatch)
    snap = co.pool_snapshot(_Router(_ROUTES_LOCAL))
    by_id = {e["model"]: e for e in snap}
    assert by_id["localX"].get("local") is True     # 本地模型被标注
    assert "local" not in by_id["cheapA"]           # 云端模型不带 local 键
    assert "local" not in by_id["premC"]


def test_pool_text_local_suffix(monkeypatch):
    """pool_text 里本地模型那行尾部带「· 本地」；云端行不带。"""
    _patch_local(monkeypatch)
    snap = co.pool_snapshot(_Router(_ROUTES_LOCAL))
    text = co.pool_text(snap)
    local_line = next(ln for ln in text.splitlines() if ln.startswith("localX"))
    assert "· 本地" in local_line
    cheap_line = next(ln for ln in text.splitlines() if ln.startswith("cheapA"))
    assert "本地" not in cheap_line


def test_snapshot_no_local_when_preset_missing(monkeypatch):
    """provider 查不到预设（自定义连接，preset 返回 None）→ 不误标本地。"""
    # 所有 provider 都不在本地名单 → preset 返回 None → 无 local 键。
    _patch_local(monkeypatch, local_providers=())
    snap = co.pool_snapshot(_Router(_ROUTES_LOCAL))
    by_id = {e["model"]: e for e in snap}
    assert "local" not in by_id["localX"]


def test_snapshot_local_survives_preset_exception(monkeypatch):
    """preset 查询抛异常 → 当非本地（不标 local），且不炸快照。"""
    _patch_local(monkeypatch)

    def boom(name):
        raise RuntimeError("catalog down")

    monkeypatch.setattr(co, "preset", boom)
    snap = co.pool_snapshot(_Router(_ROUTES_LOCAL))
    by_id = {e["model"]: e for e in snap}
    assert "localX" in by_id and "local" not in by_id["localX"]  # 未标注但仍进池
