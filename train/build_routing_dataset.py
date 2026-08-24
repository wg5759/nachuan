"""FUGU 三期批8① · 神经点将数据构造（照 OpenFugu TRINITY 复刻思路的离线 SFT 数据）。

产出 `data/routing_dataset.jsonl`：每行 `{"q":题,"kind":...,"model":...,"correct":0/1,"weight":1.0}`，
供 `train/train_coordinator.py` 训练一个「按题选模型」的线性头（冻结 Qwen3-0.6B 之上，~19.5K 参数）。

数据怎么来（真跑，会烧配额，故默认 `--dry-run` 只预览）：
- 内置中文评测集：task_kind **以 `orchestrator/classify.py` 实际输出的 kind 集合为准**
  （chat / code / reason / long——方案原写"6类"，但硬约束要求以 classify 真实输出为准，故 4 类），
  每类 ~12 道题，难度混合、中文为主。
- 候选模型 = 当前在线 chat 模型里**非 flagship** 的 cheap+premium（≤6 个，cheap 优先）——
  不起引擎，按 `gateway/router.py` 的正式构造方式直接创建 Router。
- 每题 × 每候选：经 `chat_with_fallback` 取答案；评分由**与答题模型不同厂的 cheap 裁判**判
  （"只回 CORRECT 或 WRONG"，解析容错）。每次调用 try/except，单题失败跳过。
- **断点续跑**：逐条 append jsonl；重跑跳过已有的 (题hash, model) 组合（配额贵，绝不重复烧）。
- 末尾融合 `orchestrator/scoreboard.dump_all()` 的真实战绩：按 (model, kind) 胜率转**伪样本**
  （weight 低于真评测，标 source=scoreboard），让线上实证与离线评测一起塑形。

**降级第一 / 省配额**：任何单点失败都跳过、不炸全局；`--dry-run` 一次上游都不调。
不写死任何型号名——候选/裁判全按 tier·flagship·provider 这些**数据**动态选。
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# 允许 `python train/build_routing_dataset.py` 直接跑（把仓库根加进 sys.path）。
_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_DATA_DIR = Path(os.getenv("DATA_DIR") or (_REPO / "data"))
_OUT_PATH = _DATA_DIR / "routing_dataset.jsonl"

# 战绩伪样本权重（远低于真评测的 1.0）：线上实证是弱先验，别盖过离线评测。
_SCOREBOARD_WEIGHT = 0.3
# 候选模型上限（cheap 优先塞满）——评测成本 = 题数 × 候选数 × (答题+裁判)，必须封顶。
_MAX_CANDIDATES = 6


# ──────────────────────────────────────────────────────────────────────────
# 内置中文评测集：kind 严格取自 classify.py 的输出集合（chat/code/reason/long）。
# 每类 ~12 道，难度混合、中文为主。题目就写在这里（可读、可审、可扩）。
# ──────────────────────────────────────────────────────────────────────────
EVAL_SETS: dict[str, list[str]] = {
    "chat": [
        "用一句话解释什么是机会成本。",
        "推荐三部适合周末放松看的电影，并各写一句推荐理由。",
        "帮我把这句话改得更礼貌：把报告今天发我。",
        "冬天皮肤干燥，有哪些日常保湿的小办法？",
        "用亲切的口吻写一段 30 字左右的生日祝福给同事。",
        "简单说说红茶和绿茶在制作工艺上的主要区别。",
        "给刚养猫的新手三条最重要的注意事项。",
        "把「山重水复疑无路，柳暗花明又一村」用大白话讲讲意思。",
        "我想周末去爬山，帮我列一个简短的随身物品清单。",
        "解释一下「内卷」这个词在日常语境里通常指什么。",
        "用轻松的语气写一句朋友圈文案，配一张海边日落的照片。",
        "早上起床总是很困，有什么快速清醒的小方法？",
    ],
    "code": [
        "写一个 Python 函数，判断一个字符串是否是回文，忽略大小写和空格。",
        "用 Python 实现快速排序，并加上简单注释。",
        "给定一个整数列表，写代码返回其中出现次数最多的元素。",
        "写一段 SQL：从 orders 表里查出每个用户的订单总金额，按金额降序。",
        "用 JavaScript 写一个防抖（debounce）函数。",
        "Python 里如何优雅地合并两个字典？给出两种写法。",
        "写一个递归函数计算第 n 个斐波那契数，并说明它的时间复杂度问题。",
        "用正则表达式匹配中国大陆的 11 位手机号，并写一个 Python 校验函数。",
        "实现一个 LRU 缓存类（Python），支持 get 和 put，容量固定。",
        "写一段 Python 代码读取一个 CSV 文件并统计某一列的平均值。",
        "用 Python 的 asyncio 写一个并发抓取多个 URL 的最小示例。",
        "给一个二叉树的节点定义，写代码做层序遍历（BFS）返回每层的值。",
    ],
    "reason": [
        "证明：任意三个连续整数的乘积一定能被 6 整除。",
        "一个笼子里有鸡和兔共 35 只，脚共 94 只，问鸡兔各几只？给出推导。",
        "分析：为什么快速排序平均是 O(n log n) 但最坏是 O(n²)？关键在哪。",
        "甲的年龄是乙的 3 倍，5 年后甲是乙的 2 倍，求两人现在各多少岁。",
        "有 8 个球，其中一个略重，用天平最少称几次能找出来？说明策略。",
        "论证：如果一个数的各位数字之和能被 3 整除，那么这个数能被 3 整除。",
        "三个开关控制另一个房间的一盏灯，只能进去一次，如何确定哪个开关？",
        "权衡：微服务架构相比单体，主要优势和代价分别是什么？分点分析。",
        "为什么在高并发下用乐观锁可能比悲观锁更好？也说说它的风险。",
        "一道逻辑题：说谎者永远说假话，老实人永远说真话。A 说“我们都是说谎者”，判断 A 和 B 各是什么。",
        "推导：等差数列前 n 项和公式，并说明推导思路。",
        "分析一个电商大促时数据库为什么容易成为瓶颈，可以从哪些方向优化。",
    ],
    "long": [
        "阅读以下要求并给出一份完整方案：为一个 50 人的中小团队设计一套代码评审规范，"
        "覆盖流程、工具、评审标准、冲突处理与度量指标，尽量具体可落地。",
        "写一篇约 600 字的短文，主题是“人工智能对未来教育的影响”，要有观点、论据和结尾。",
        "为一款面向老年人的健康管理 App 写一份产品需求概述，包含目标用户、核心功能、"
        "关键流程与三条差异化卖点，条理清晰。",
        "总结并对比敏捷开发中 Scrum 与 Kanban 的核心差异、适用场景与常见误区，成文一篇。",
        "为一次面向初学者的“Python 数据分析”两小时线上讲座，写一份详细的分段大纲与时间分配。",
        "写一份创业公司远程办公的协作制度草案，覆盖沟通、会议、文档、绩效与信息安全五个方面。",
        "以“城市共享单车的治理困境与对策”为题，写一篇结构完整、约 700 字的分析文章。",
        "为一个开源项目撰写贡献者指南（CONTRIBUTING）的完整正文，覆盖环境搭建、分支规范、"
        "提交规范、测试要求与评审流程。",
        "写一份把纸质档案数字化的项目实施方案，包含目标、范围、阶段划分、风险与验收标准。",
        "总结一份“新员工第一周入职指南”，从入职当天到第五天，逐日列出应完成的事项与资源。",
        "为一场关于“可持续时尚”的两天线下工作坊设计完整日程，含主题、环节形式与预期产出。",
        "写一篇约 600 字的科普文，向非技术读者解释“什么是大语言模型，它为什么有时会一本正经地胡说八道”。",
    ],
}


def _all_items() -> list[tuple[str, str]]:
    """展平成 [(kind, question), ...]，稳定顺序（便于断点续跑的确定性）。"""
    items: list[tuple[str, str]] = []
    for kind in sorted(EVAL_SETS):
        for q in EVAL_SETS[kind]:
            items.append((kind, q))
    return items


def _q_hash(q: str) -> str:
    """题目稳定短哈希（断点续跑的键之一：同题同模型不重复烧配额）。"""
    return hashlib.sha1(q.encode("utf-8")).hexdigest()[:12]


# ──────────────────────────────────────────────────────────────────────────
# Router / 候选 / 裁判（不起引擎，直接构 Router；全按数据动态选，不写死型号名）
# ──────────────────────────────────────────────────────────────────────────
def _build_router() -> Any:
    """按正式连接存储直接构 Router，不启动 HTTP 引擎。"""
    from gateway.config import get_settings
    from gateway.connections import ConnectionStore
    from gateway.router import Router

    settings = get_settings()
    store = ConnectionStore(Path(settings.usage_db_path).parent / "connections.json")
    return Router(store=store)


def _online_chat_models(router: Any) -> list[dict[str, Any]]:
    """当前在线 chat 模型（含 provider/tier/flagship/rank），echo 与非 chat 模态排除。"""
    from gateway.catalog import preset_meta

    out: list[dict[str, Any]] = []
    for r in router.routes_info() or []:
        model = r.get("model")
        if not model or model == "echo":
            continue
        if preset_meta(model).get("modality", "chat") != "chat":
            continue
        out.append({
            "model": model,
            "provider": r.get("provider"),
            "tier": r.get("tier"),
            "rank": r.get("rank") or 999,
            "flagship": bool(r.get("flagship")),
        })
    return out


def _pick_candidates(models: list[dict[str, Any]], limit: int = _MAX_CANDIDATES) -> list[dict[str, Any]]:
    """候选 = 非 flagship 的 cheap+premium，cheap 优先塞满，≤ limit 个。

    排序键：cheap 档优先(0) → premium(1)；同档按 rank 升序（更强的先入选）。
    """
    cheap_tiers = ("cheap", "free")
    cands = [m for m in models if not m["flagship"] and m["tier"] in (*cheap_tiers, "premium")]
    cands.sort(key=lambda m: (0 if m["tier"] in cheap_tiers else 1, m["rank"]))
    return cands[:limit]


def _pick_judge(
    answer_model: dict[str, Any], candidates: list[dict[str, Any]], all_models: list[dict[str, Any]]
) -> str | None:
    """给某道题的答题模型挑一个**不同厂的 cheap 裁判**（跨厂避免同源偏袒）。

    偏好：先在候选里找不同厂的 cheap；候选里没有，则退到全体在线 cheap 里找不同厂的；
    再没有就退到任意不同厂模型；实在全同厂 → None（该题此模型跳过评分）。
    """
    cheap_tiers = ("cheap", "free")
    ap = answer_model["provider"]

    def diff_cheap(pool: list[dict[str, Any]]) -> str | None:
        picks = [m for m in pool if m["provider"] != ap and m["tier"] in cheap_tiers]
        picks.sort(key=lambda m: m["rank"])
        return picks[0]["model"] if picks else None

    return (
        diff_cheap(candidates)
        or diff_cheap(all_models)
        or next((m["model"] for m in all_models if m["provider"] != ap), None)
    )


# ──────────────────────────────────────────────────────────────────────────
# 真跑：答题 + 评分（经 chat_with_fallback；每步 try/except，坏一点不炸全局）
# ──────────────────────────────────────────────────────────────────────────
async def _ask(
    router: Any,
    model: str,
    question: str,
    *,
    max_chars: int = 4000,
    role: str = "routing_dataset.answer",
) -> str | None:
    """让 model 回答 question，返回文本（异常/空 → None，由调用方跳过该样本）。"""
    from gateway.failover import chat_with_fallback
    from gateway.provider_call_ledger import bind_provider_call_scope
    from gateway.schemas import ChatCompletionRequest

    try:
        req = ChatCompletionRequest(  # type: ignore[call-arg]
            model=model, messages=[{"role": "user", "content": question}]
        )
        with bind_provider_call_scope(role=role):
            res, _served, _route = await chat_with_fallback(router, req)
        text = (res.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        text = text.strip()
        return text[:max_chars] if text else None
    except Exception:  # noqa: BLE001 单次答题失败跳过该样本，绝不炸全局
        return None


_CORRECT_TOKENS = ("CORRECT", "正确", "对")
_WRONG_TOKENS = ("WRONG", "错误", "错", "不对", "INCORRECT")


def _parse_verdict(text: str) -> int | None:
    """把裁判回复解析成 1(对)/0(错)/None(无法判定)。容错：认关键词、看整体倾向。"""
    if not text:
        return None
    up = text.strip().upper()
    # 优先看开头 token（裁判被要求"只回 CORRECT 或 WRONG"）。
    head = up[:16]
    if head.startswith("CORRECT") or head.startswith("正确"):
        return 1
    if head.startswith("WRONG") or head.startswith("INCORRECT") or head.startswith("错"):
        return 0
    has_c = any(t in up for t in ("CORRECT",)) or any(t in text for t in ("正确",))
    has_w = any(t in up for t in ("WRONG", "INCORRECT")) or any(t in text for t in ("错误", "不对"))
    if has_c and not has_w:
        return 1
    if has_w and not has_c:
        return 0
    return None  # 模糊 → 交由调用方跳过（不猜）


async def _judge(
    router: Any,
    judge_model: str,
    kind: str,
    question: str,
    answer: str,
    *,
    role: str = "routing_dataset.judge",
) -> int | None:
    """跨厂 cheap 裁判判答案对错：只回 CORRECT/WRONG；返回 1/0/None。"""
    prompt = (
        "你是严格的评审。下面是一道题和某个模型给出的回答，请判断这个回答是否基本正确、"
        "切题、可用（不必完美，但要没有明显错误或答非所问）。\n\n"
        f"【题目类型】{kind}\n【题目】{question}\n\n【回答】\n{answer}\n\n"
        "只回一个词：正确回答就回 CORRECT，错误/答非所问就回 WRONG。不要有任何多余解释。"
    )
    verdict = await _ask(router, judge_model, prompt, max_chars=200, role=role)
    if verdict is None:
        return None
    return _parse_verdict(verdict)


# ──────────────────────────────────────────────────────────────────────────
# 断点续跑：读已有 jsonl 的 (题hash, model) 组合；逐条 append
# ──────────────────────────────────────────────────────────────────────────
def _load_done_keys(path: Path) -> set[tuple[str, str]]:
    """已完成的 (题hash, model) 集合——重跑跳过，绝不重复烧配额。只认真评测样本（source!=scoreboard）。"""
    done: set[tuple[str, str]] = set()
    if not path.exists():
        return done
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:  # noqa: BLE001 坏行跳过（不因一行脏数据全废）
                    continue
                if row.get("source") == "scoreboard":
                    continue  # 伪样本不占真评测的续跑坑位
                q = row.get("q")
                model = row.get("model")
                if isinstance(q, str) and isinstance(model, str):
                    done.add((_q_hash(q), model))
    except Exception:  # noqa: BLE001 读失败当没有历史（大不了重跑）
        return set()
    return done


def _append_row(path: Path, row: dict[str, Any]) -> None:
    """逐条 append 一行（断点续跑的落盘单位；每条独立，中断也不丢已写）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


# ──────────────────────────────────────────────────────────────────────────
# 融合 scoreboard 战绩 → 伪样本（低权重）
# ──────────────────────────────────────────────────────────────────────────
def _scoreboard_pseudo_rows() -> list[dict[str, Any]]:
    """把 scoreboard.dump_all() 的 (model,kind) 胜率转成伪样本行。

    每条 (model,kind) 若有胜率，用胜率直接当"软 correct"（0~1 之间的连续值也允许——训练侧按
    correct 均值聚合软标签，连续值天然可用），weight=_SCOREBOARD_WEIGHT，标 source=scoreboard。
    只取有场次的、且 kind 属于内置评测集的（general 等其它 kind 无对应训练题，跳过）。
    """
    try:
        from orchestrator import scoreboard

        rows_raw = scoreboard.dump_all()
    except Exception:  # noqa: BLE001 战绩坏了当没有，绝不炸数据构造
        return []
    valid_kinds = set(EVAL_SETS.keys())
    out: list[dict[str, Any]] = []
    for r in rows_raw or []:
        kind = r.get("task_kind")
        wr = r.get("win_rate")
        model = r.get("model")
        if not model or kind not in valid_kinds or wr is None:
            continue
        out.append({
            # 伪样本没有具体题面，用一个可辨识的占位 q（训练侧按 (kind, model) 聚合，不依赖题面文本）。
            "q": f"[scoreboard:{kind}]",
            "kind": kind,
            "model": model,
            "correct": round(float(wr), 4),
            "weight": _SCOREBOARD_WEIGHT,
            "source": "scoreboard",
        })
    return out


# ──────────────────────────────────────────────────────────────────────────
# dry-run 预览（不调任何上游）
# ──────────────────────────────────────────────────────────────────────────
def _dry_run() -> int:
    items = _all_items()
    print("=== FUGU 批8 · 神经点将数据构造 [dry-run] ===")
    print(f"task_kind（取自 classify.py 输出集合）：{', '.join(sorted(EVAL_SETS))}")
    total = 0
    for kind in sorted(EVAL_SETS):
        qs = EVAL_SETS[kind]
        total += len(qs)
        print(f"\n【{kind}】{len(qs)} 题：")
        for i, q in enumerate(qs, 1):
            preview = q if len(q) <= 42 else q[:42] + "…"
            print(f"  {i:2d}. {preview}")
    print(f"\n共 {total} 题。")

    # 尝试构 Router 看看会评哪些模型（构不出/无候选也不报错，只是提示）。
    try:
        router = _build_router()
        online = _online_chat_models(router)
        cands = _pick_candidates(online)
        print(f"\n当前在线 chat 模型 {len(online)} 个；将评测的候选（非王牌 cheap+premium，≤{_MAX_CANDIDATES}，cheap 优先）：")
        for m in cands:
            judge = _pick_judge(m, cands, online)
            print(f"  - {m['model']} [{m['tier']} · {m['provider']} · rank{m['rank']}]  裁判→ {judge or '(无跨厂裁判)'}")
        if not cands:
            print("  （无在线候选——真跑前请先在连接中心配好至少一个非王牌 cheap/premium 模型）")
        est = total * len(cands) * 2  # 每样本 = 1 次答题 + 1 次评分
        print(f"\n预计上游调用约 {est} 次（{total} 题 × {len(cands)} 候选 × 2）。真跑请去掉 --dry-run。")
    except Exception as e:  # noqa: BLE001 dry-run 构 Router 失败不算错，仅提示
        print(f"\n（构 Router 预览候选失败：{e!r}；不影响真跑时按当时在线模型评测）")
    print(f"\n输出文件：{_OUT_PATH}")
    return 0


# ──────────────────────────────────────────────────────────────────────────
# 真跑主流程
# ──────────────────────────────────────────────────────────────────────────
async def _run(limit_candidates: int) -> int:
    router = _build_router()
    try:
        online = _online_chat_models(router)
        cands = _pick_candidates(online, limit_candidates)
        if not cands:
            print("[build] 无在线候选模型（非王牌 cheap/premium）——请先在连接中心配置。已中止。")
            return 2
        print(f"[build] 候选 {len(cands)} 个：{', '.join(m['model'] for m in cands)}")

        done = _load_done_keys(_OUT_PATH)
        print(f"[build] 断点续跑：已有 {len(done)} 个 (题,模型) 样本，将跳过。")

        items = _all_items()
        written = 0
        skipped = 0
        for item_index, (kind, q) in enumerate(items, 1):
            qh = _q_hash(q)
            for candidate_index, m in enumerate(cands, 1):
                model = m["model"]
                if (qh, model) in done:
                    skipped += 1
                    continue
                role_prefix = (
                    f"routing_dataset.item_{item_index}.candidate_{candidate_index}"
                )
                answer = await _ask(
                    router,
                    model,
                    q,
                    role=f"{role_prefix}.answer",
                )
                if answer is None:
                    print(f"[build] 跳过（答题失败）: {model} · {kind} · {q[:24]}…")
                    continue
                judge_model = _pick_judge(m, cands, online)
                if judge_model is None:
                    print(f"[build] 跳过（无跨厂裁判）: {model} · {kind}")
                    continue
                verdict = await _judge(
                    router,
                    judge_model,
                    kind,
                    q,
                    answer,
                    role=f"{role_prefix}.judge",
                )
                if verdict is None:
                    print(f"[build] 跳过（评分模糊）: {model} · {kind} · {q[:24]}…")
                    continue
                row = {"q": q, "kind": kind, "model": model,
                       "correct": int(verdict), "weight": 1.0}
                _append_row(_OUT_PATH, row)
                done.add((qh, model))
                written += 1
                print(f"[build] {model} · {kind} · correct={verdict} · {q[:20]}…")

        # 融合 scoreboard 战绩伪样本（低权重，不占真评测续跑坑位）。
        pseudo = _scoreboard_pseudo_rows()
        for row in pseudo:
            _append_row(_OUT_PATH, row)
        print(f"\n[build] 完成：新增真评测 {written} 条，跳过 {skipped} 条，"
              f"融合战绩伪样本 {len(pseudo)} 条 → {_OUT_PATH}")
        return 0
    finally:
        try:
            await router.aclose()
        except Exception:  # noqa: BLE001 关连接失败无所谓
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FUGU 批8① 神经点将数据构造")
    parser.add_argument("--dry-run", action="store_true",
                        help="只预览题目与候选，不调任何上游模型（不烧配额）")
    parser.add_argument("--max-candidates", type=int, default=_MAX_CANDIDATES,
                        help=f"评测候选模型上限（默认 {_MAX_CANDIDATES}）")
    args = parser.parse_args(argv)

    if args.dry_run:
        return _dry_run()
    return asyncio.run(_run(args.max_candidates))


if __name__ == "__main__":
    raise SystemExit(main())
