"""长任务 harness —— workdir 里的持久化任务状态（Anthropic「文件即外部记忆」精髓）。

机主实测反馈 + Anthropic《Effective harnesses for long-running agents》：光靠对话/上下文压缩，
模型跨多个会话干不完长任务；正解是把**任务状态落到工作目录的文件里**，agent 每次开局先读、
收尾更新——于是"关了 app 明天再开，它接着上次干"。

在 workdir 下维护 `.纳川/` 目录：
- `任务.json`：目标 + 步骤清单（每步 done/pending，JSON 不用 Markdown——Anthropic 发现模型更不敢乱改）+ 更新时间。
- `进展.md`：时间线进展笔记（人也能看的日志，git 之外的"agent 记忆"）。

降级第一：任何读写失败一律吞掉当"无状态"，绝不因状态文件挡任务。所有函数对 workdir 不存在/无权限安全。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

_STATE_DIR = ".纳川"
_TASK_FILE = "任务.json"
_JOURNAL_FILE = "进展.md"
# 记忆银行（借鉴 RooFlow）：关键决策 + 约定/模式，跨会话不丢——续跑时优先注入，让"为什么这么做/项目约定"不失忆。
# 和 进展.md（流水账）分开：这里只留**该长期记住的少数几条**，不堆时间线噪音。
_MEMORY_FILE = "记忆.md"
# 判"这是续跑同一个任务"的关键词（短指令 + 这些词 → 接着上次干）。
_CONTINUE_HINT = re.compile(r"继续|接着|接上|go on|continue|resume|下一步|往下做|还没做完", re.I)


def detect_verify_cmd(workdir: str) -> str:
    """探测这个工作目录该怎么"真跑验证"（Anthropic 铁律③：不靠 LLM 判、靠真跑）。

    按项目标志物给一条自检命令：有 pytest/测试目录→pytest；package.json 有 test 脚本→npm test；
    有 Makefile 的 test→make test；Cargo→cargo test；go.mod→go test。探不到返回 ""（退回纯 LLM 判）。
    只返回**只读/自检**类命令，绝不返回会改环境的。
    """
    try:
        p = Path(workdir)
        if not p.is_dir():
            return ""
        names = {x.name for x in p.iterdir()}
        if "pyproject.toml" in names or "pytest.ini" in names or (p / "tests").is_dir():
            return "python -m pytest -q"
        if "package.json" in names:
            try:
                import json as _json
                pkg = _json.loads((p / "package.json").read_text(encoding="utf-8"))
                if isinstance(pkg.get("scripts"), dict) and "test" in pkg["scripts"]:
                    return "npm test --silent"
            except Exception:  # noqa: BLE001
                pass
        if "Cargo.toml" in names:
            return "cargo test"
        if "go.mod" in names:
            return "go test ./..."
        if "Makefile" in names:
            return "make test"
    except Exception:  # noqa: BLE001
        pass
    return ""


def set_verify_cmd(workdir: str, cmd: str) -> None:
    """兼容旧调用；永不把工作区可写文本提升为可执行权限。"""
    del workdir, cmd


def get_verify_cmd(workdir: str) -> str:
    """返回引擎按固定规则重新探测的提示，不信任 ``任务.json`` 中的旧字段。"""
    return detect_verify_cmd(workdir)


def _dir(workdir: str) -> Path:
    return Path(workdir) / _STATE_DIR


def _task_path(workdir: str) -> Path:
    return _dir(workdir) / _TASK_FILE


def _journal_path(workdir: str) -> Path:
    return _dir(workdir) / _JOURNAL_FILE


def _memory_path(workdir: str) -> Path:
    return _dir(workdir) / _MEMORY_FILE


def record_note(workdir: str, kind: str, text: str) -> None:
    """记一条长期记忆到 记忆.md（借鉴 RooFlow 的 decisionLog/systemPatterns）。
    kind：'决策'（为什么这么选/定了什么）或 '约定'（项目惯例/踩过的坑/规范）。全吞异常，失败不挡任务。
    """
    try:
        text = (text or "").strip()
        if not text or not _dir(workdir).exists():
            _dir(workdir).mkdir(parents=True, exist_ok=True)
        k = "决策" if str(kind).strip() in ("决策", "decision", "why") else "约定"
        mp = _memory_path(workdir)
        prev = mp.read_text(encoding="utf-8") if mp.exists() else "# 记忆银行（关键决策 + 约定，跨会话保留）\n"
        stamp = time.strftime("%Y-%m-%d %H:%M")
        mp.write_text(prev + f"- [{k} · {stamp}] {text[:400]}\n", encoding="utf-8")
    except Exception:  # noqa: BLE001
        return


def load(workdir: str) -> Optional[dict[str, Any]]:
    """读 workdir 里的任务状态；不存在/坏了 → None。"""
    try:
        p = _task_path(workdir)
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _parse_steps(plan_text: str) -> list[dict[str, Any]]:
    """把自由文本计划拆成步骤清单：抓「1. / - / 步骤N」这类行做步骤标题。"""
    steps: list[dict[str, Any]] = []
    for line in (plan_text or "").splitlines():
        s = line.strip()
        m = re.match(r"^(?:\d+[.)、]|[-*]|步骤\s*\d+[:：.]?)\s*(.+)$", s)
        if m:
            title = m.group(1).strip()
            # 去掉"验收标准："这类附注只留主干（超长截断）
            title = re.split(r"验收标准[:：]|验收[:：]", title)[0].strip()[:120]
            if title:
                steps.append({"title": title, "done": False})
    if not steps and (plan_text or "").strip():
        steps = [{"title": "完成任务", "done": False}]
    return steps


def is_unfinished(state: Optional[dict[str, Any]]) -> bool:
    if not state:
        return False
    if state.get("completed"):
        return False
    steps = state.get("steps") or []
    return any(not s.get("done") for s in steps) or not steps


def looks_like_continuation(task: str, state: Optional[dict[str, Any]]) -> bool:
    """当前 task 是否在续跑 workdir 里那个未完成的任务。

    判据（任一）：① task 短且含"继续/接着/往下做"等续跑词；② 与已存目标关键词高度重合。
    这样"新任务"不会误接旧任务的进展（避免上下文串味），"接着干"才续跑。
    """
    if not is_unfinished(state):
        return False
    t = (task or "").strip()
    if len(t) <= 30 and _CONTINUE_HINT.search(t):
        return True
    goal = str((state or {}).get("goal") or "")
    if not goal or not t:
        return False
    # 关键词重合度（2 字以上的中文/英文词片段）
    gw = set(re.findall(r"[一-龥]{2,}|[A-Za-z]{3,}", goal))
    tw = set(re.findall(r"[一-龥]{2,}|[A-Za-z]{3,}", t))
    if not gw:
        return False
    overlap = len(gw & tw) / len(gw)
    return overlap >= 0.5


def start_task(workdir: str, goal: str, plan_text: str) -> Optional[dict[str, Any]]:
    """开一个新任务：把目标 + 计划清单落盘，初始化进展日志。返回状态 dict（失败→None）。"""
    try:
        d = _dir(workdir)
        d.mkdir(parents=True, exist_ok=True)
        state = {
            "goal": (goal or "").strip()[:500],
            "steps": _parse_steps(plan_text),
            "completed": False,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        _task_path(workdir).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        _journal_path(workdir).write_text(
            f"# 任务进展\n\n**目标**：{state['goal']}\n\n- [{state['created_at']}] 任务开始，已规划 {len(state['steps'])} 步。\n",
            encoding="utf-8",
        )
        return state
    except Exception:  # noqa: BLE001 状态落盘失败不挡任务
        return None


def record_progress(
    workdir: str, note: str, *, done_titles: Optional[list[str]] = None, completed: bool = False
) -> None:
    """更新进展：标记完成的步骤、追加一条时间线笔记、必要时标任务完成。全吞异常。"""
    try:
        state = load(workdir)
        if state is None:
            return
        if done_titles:
            dl = set(done_titles)
            for s in state.get("steps") or []:
                if s.get("title") in dl:
                    s["done"] = True
        if completed:
            state["completed"] = True
            for s in state.get("steps") or []:
                s["done"] = True
        state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _task_path(workdir).write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        # 追加进展日志
        jp = _journal_path(workdir)
        prev = jp.read_text(encoding="utf-8") if jp.exists() else "# 任务进展\n"
        tag = "✅完成" if completed else "进展"
        jp.write_text(prev + f"- [{state['updated_at']}] {tag}：{(note or '').strip()[:300]}\n", encoding="utf-8")
    except Exception:  # noqa: BLE001
        return


def resume_context(workdir: str) -> str:
    """把当前任务状态格式化成注入 agent 的"续跑上下文"（开局让它秒进入状态）。"""
    state = load(workdir)
    if not state:
        return ""
    steps = state.get("steps") or []
    done = [s["title"] for s in steps if s.get("done")]
    todo = [s["title"] for s in steps if not s.get("done")]
    lines = [
        "【长任务续跑：这个工作目录里有一个未完成的任务，请接着上次的进度往下做，不要从头重来】",
        f"目标：{state.get('goal', '')}",
    ]
    if done:
        lines.append("已完成：" + "；".join(done[:20]))
    if todo:
        lines.append("待办（继续做这些）：" + "；".join(todo[:20]))
    # 记忆银行（RooFlow 借鉴）：关键决策 + 约定优先注入——这些是"为什么/项目惯例"，别再问一遍、别推翻已定的。
    try:
        mp = _memory_path(workdir)
        if mp.exists():
            mem = mp.read_text(encoding="utf-8").strip().splitlines()
            keep = [ln for ln in mem if ln.startswith("- ")][-12:]  # 只留少数几条关键的
            if keep:
                lines.append("关键决策与约定（沿用，别推翻/别重问）：\n" + "\n".join(keep))
    except Exception:  # noqa: BLE001
        pass
    # 附最近几条进展笔记
    try:
        jp = _journal_path(workdir)
        if jp.exists():
            tail = jp.read_text(encoding="utf-8").strip().splitlines()[-5:]
            if tail:
                lines.append("最近进展：\n" + "\n".join(tail))
    except Exception:  # noqa: BLE001
        pass
    # 符号化短期记忆：注入轻量 Mermaid 任务画布（每步全量原文已卸载到 refs/<node_id>.md，
    # 要复盘某步细节按 #node_id 下钻，不必把长日志灌进上下文）。best-effort。
    try:
        from orchestrator import symbolic_memory

        canvas = symbolic_memory.canvas_text(workdir)
        if canvas:
            lines.append(
                "任务画布（Mermaid；每个 #node_id 的全量原文在 refs/<node_id>.md，要看某步细节按 id 下钻）：\n"
                + canvas
            )
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines)


def clear(workdir: str) -> None:
    """清任务状态（任务真完成或用户要重开时）。全吞异常。"""
    try:
        for p in (_task_path(workdir), _journal_path(workdir)):
            if p.exists():
                p.unlink()
        # 一并清符号化画布 + 卸载的 refs（best-effort）
        try:
            from orchestrator import symbolic_memory

            symbolic_memory.clear(workdir)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        return
