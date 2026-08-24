"""符号化短期记忆（借鉴腾讯 TencentDB Agent Memory 的 symbolic memory 思路）。

长任务里最烧 token 的是冗长工具日志（搜索结果、代码、报错栈）。做法：
- 全量细节**卸载**到 `.纳川/refs/<node_id>.md`（证据底层，不进上下文）；
- 上下文里只挂一张轻量 **Mermaid 任务图** `.纳川/画布.md`（结构顶层，带 `#node_id`）；
- 要核对细节时按 `node_id` **下钻**（grep/resolve）拉回原文。

一句话：**「上层存结构，下层存证据」**，确定性下钻、无损可回溯——比一坨扁平日志省 token 又不丢证据。

状态存 `.纳川/画布.json`（JSON 不用 Markdown，模型更不敢乱改；照 Anthropic 长时 agent 铁律②），
`画布.md` 由它渲染给人/模型看。与 task_state 共用 `.纳川/` 目录。
降级第一：任何读写失败一律吞掉当「无画布」，绝不因它挡任务。所有函数对坏 workdir 安全。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional

_STATE_DIR = ".纳川"
_CANVAS_JSON = "画布.json"
_CANVAS_MD = "画布.md"
_REFS_DIR = "refs"

# 节点类型 → Mermaid 形状（用形状一眼区分步骤/报错/完成/决策/笔记）
_SHAPE = {
    "step": ('["', '"]'),        # 矩形：普通步骤
    "error": ('{{"', '"}}'),      # 六边形：报错/异常
    "done": ('(["', '"])'),       # 圆角体育场：已完成
    "decision": ('{"', '"}'),     # 菱形：判定/分叉
    "note": ('>"', '"]'),         # 便签：备注
}
_KIND_MARK = {"step": "", "error": "⚠", "done": "✓", "decision": "?", "note": "🗒"}


def _ok(workdir: str) -> bool:
    """空/纯空白 workdir 直接判否——绝不把 `.纳川` 写进当前工作目录（相对路径会污染仓库）。"""
    return bool((workdir or "").strip())


def _dir(workdir: str) -> Path:
    return Path(workdir) / _STATE_DIR


def _canvas_json_path(workdir: str) -> Path:
    return _dir(workdir) / _CANVAS_JSON


def _canvas_md_path(workdir: str) -> Path:
    return _dir(workdir) / _CANVAS_MD


def _refs_dir(workdir: str) -> Path:
    return _dir(workdir) / _REFS_DIR


def _ref_path(workdir: str, node_id: str) -> Path:
    return _refs_dir(workdir) / f"{node_id}.md"


def _load(workdir: str) -> dict[str, Any]:
    """读画布状态；不存在/坏了 → 空画布 {next:1, nodes:[]}（绝不抛）。"""
    if not _ok(workdir):
        return {"next": 1, "nodes": []}
    try:
        p = _canvas_json_path(workdir)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("nodes"), list):
                data.setdefault("next", len(data["nodes"]) + 1)
                return data
    except Exception:  # noqa: BLE001
        pass
    return {"next": 1, "nodes": []}


def _label(title: str) -> str:
    """Mermaid 标签安全化：去换行、双引号换单引号、压空白、截断（防语法炸+防超长）。"""
    s = re.sub(r"\s+", " ", (title or "").strip()).replace('"', "'")
    return s[:48] if len(s) > 48 else s


def _render(state: dict[str, Any]) -> str:
    """把节点列表渲染成 Mermaid `graph TD`（顶层结构，喂上下文用这个，不含卸载的原文）。"""
    nodes = state.get("nodes") or []
    if not nodes:
        return "graph TD\n  empty[\"（暂无进展节点）\"]"
    lines = ["graph TD"]
    for i, n in enumerate(nodes, 1):
        nid = str(n.get("id") or f"n{i}")
        kind = str(n.get("kind") or "step")
        lb, rb = _SHAPE.get(kind, _SHAPE["step"])
        mark = _KIND_MARK.get(kind, "")
        label = f"{mark}{i}·{_label(str(n.get('title') or ''))}".strip()
        lines.append(f"  {nid}{lb}{label}{rb}")
    # 边：优先按 parent 连；无 parent 的顺序节点串成主链
    prev: Optional[str] = None
    for n in nodes:
        nid = str(n.get("id") or "")
        parent = n.get("parent")
        if parent:
            lines.append(f"  {parent} --> {nid}")
        elif prev:
            lines.append(f"  {prev} --> {nid}")
        prev = nid
    return "\n".join(lines)


def _write_canvas_md(workdir: str, state: dict[str, Any]) -> None:
    """把渲染好的 Mermaid 落成 画布.md（人可读 + 模型可读的顶层结构）。"""
    body = (
        "# 任务画布（符号化短期记忆）\n\n"
        "> 顶层只放结构；每个 `#node_id` 的全量原文在 `refs/<node_id>.md`，按 id 下钻。\n\n"
        "```mermaid\n" + _render(state) + "\n```\n"
    )
    _canvas_md_path(workdir).write_text(body, encoding="utf-8")


def add_node(
    workdir: str,
    title: str,
    detail: str = "",
    *,
    kind: str = "step",
    parent: Optional[str] = None,
) -> Optional[str]:
    """加一个进展节点：分配 node_id → 追加进 Mermaid 画布 → 把全量 detail 卸载到 refs/<id>.md。

    返回 node_id（如 "n3"）；失败返回 None（不抛，不挡任务）。title 进画布（短、轻），
    detail 进 refs（长、重，不进上下文）。kind ∈ step/error/done/decision/note。
    """
    if not _ok(workdir):
        return None
    try:
        d = _dir(workdir)
        d.mkdir(parents=True, exist_ok=True)
        _refs_dir(workdir).mkdir(parents=True, exist_ok=True)
        state = _load(workdir)
        nid = f"n{int(state.get('next', 1))}"
        state["next"] = int(state.get("next", 1)) + 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        node = {"id": nid, "title": (title or "").strip()[:200], "kind": kind, "ts": ts}
        if parent:
            node["parent"] = str(parent)
        state.setdefault("nodes", []).append(node)
        # 卸载全量原文到 refs（证据底层）
        ref_body = (
            f"# {nid} · {(title or '').strip()[:200]}\n\n"
            f"- 类型：{kind}\n- 时间：{ts}\n"
            + (f"- 上游：{parent}\n" if parent else "")
            + "\n---\n\n"
            + (detail or "(无详情)")
        )
        _ref_path(workdir, nid).write_text(ref_body, encoding="utf-8")
        _canvas_json_path(workdir).write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _write_canvas_md(workdir, state)
        return nid
    except Exception:  # noqa: BLE001 画布落盘失败不挡任务
        return None


def canvas_text(workdir: str) -> str:
    """返回当前 Mermaid 画布文本（注入上下文用；无画布 → ""）。轻量，不含 refs 原文。"""
    state = _load(workdir)
    if not (state.get("nodes")):
        return ""
    return _render(state)


def resolve(workdir: str, node_id: str) -> str:
    """按 node_id 下钻：读 refs/<node_id>.md 的全量原文（不存在 → ""）。"""
    if not _ok(workdir):
        return ""
    try:
        nid = (node_id or "").strip().lstrip("#")
        if not re.fullmatch(r"n\d+", nid):
            return ""
        p = _ref_path(workdir, nid)
        return p.read_text(encoding="utf-8") if p.exists() else ""
    except Exception:  # noqa: BLE001
        return ""


def grep(workdir: str, keyword: str) -> list[str]:
    """找出标题或卸载原文里命中 keyword 的 node_id 列表（模型据此定位再下钻）。"""
    kw = (keyword or "").strip()
    if not kw:
        return []
    hits: list[str] = []
    try:
        state = _load(workdir)
        for n in state.get("nodes") or []:
            nid = str(n.get("id") or "")
            if kw.lower() in str(n.get("title") or "").lower():
                hits.append(nid)
                continue
            ref = _ref_path(workdir, nid)
            if ref.exists() and kw.lower() in ref.read_text(encoding="utf-8").lower():
                hits.append(nid)
    except Exception:  # noqa: BLE001
        return hits
    return hits


def clear(workdir: str) -> None:
    """清画布（任务真完成/重开时）。全吞异常。"""
    if not _ok(workdir):
        return
    try:
        for p in (_canvas_json_path(workdir), _canvas_md_path(workdir)):
            if p.exists():
                p.unlink()
        rd = _refs_dir(workdir)
        if rd.is_dir():
            for f in rd.glob("*.md"):
                f.unlink()
            rd.rmdir()
    except Exception:  # noqa: BLE001
        return
