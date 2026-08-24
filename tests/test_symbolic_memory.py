"""符号化短期记忆：Mermaid 画布(顶层结构) + refs/<node_id>.md(卸载原文) + node_id 下钻。"""

from __future__ import annotations

import json

import orchestrator.symbolic_memory as sm


def test_add_node_writes_canvas_and_ref(tmp_path):
    nid = sm.add_node(str(tmp_path), "读代码", "这里是一大段工具日志……" * 50, kind="step")
    assert nid == "n1"
    # 画布 json + md 都落盘
    data = json.loads((tmp_path / ".纳川" / "画布.json").read_text(encoding="utf-8"))
    assert data["nodes"][0]["title"] == "读代码" and data["next"] == 2
    md = (tmp_path / ".纳川" / "画布.md").read_text(encoding="utf-8")
    assert "mermaid" in md and "n1" in md
    # 全量原文卸载到 refs（顶层画布里不含这段长文）
    ref = (tmp_path / ".纳川" / "refs" / "n1.md").read_text(encoding="utf-8")
    assert "一大段工具日志" in ref
    assert "一大段工具日志" not in md  # 顶层只存结构，证据在底层


def test_ids_increment_and_canvas_chains(tmp_path):
    a = sm.add_node(str(tmp_path), "读代码")
    b = sm.add_node(str(tmp_path), "改结构")
    c = sm.add_node(str(tmp_path), "跑测试")
    assert [a, b, c] == ["n1", "n2", "n3"]
    canvas = sm.canvas_text(str(tmp_path))
    assert canvas.startswith("graph TD")
    # 顺序节点自动串成主链
    assert "n1 --> n2" in canvas and "n2 --> n3" in canvas


def test_resolve_drills_down_to_full_text(tmp_path):
    nid = sm.add_node(str(tmp_path), "跑测试报错", "Traceback: ZeroDivisionError line 42", kind="error")
    full = sm.resolve(str(tmp_path), nid)
    assert "ZeroDivisionError line 42" in full
    # 带 # 前缀也认
    assert "ZeroDivisionError" in sm.resolve(str(tmp_path), "#" + nid)
    # 不存在/非法 id → 空串，不抛
    assert sm.resolve(str(tmp_path), "n999") == ""
    assert sm.resolve(str(tmp_path), "垃圾") == ""


def test_error_node_uses_hexagon_shape(tmp_path):
    sm.add_node(str(tmp_path), "崩了", "boom", kind="error")
    canvas = sm.canvas_text(str(tmp_path))
    assert '{{"' in canvas and '⚠' in canvas  # 报错节点用六边形 + ⚠ 标记


def test_parent_edge_explicit(tmp_path):
    root = sm.add_node(str(tmp_path), "主任务")
    child = sm.add_node(str(tmp_path), "子步骤", parent=root)
    canvas = sm.canvas_text(str(tmp_path))
    assert f"{root} --> {child}" in canvas


def test_grep_finds_by_title_and_by_ref_content(tmp_path):
    sm.add_node(str(tmp_path), "读配置文件", "普通日志")
    sm.add_node(str(tmp_path), "跑单测", "FAILED tests/test_login.py::test_expired")
    # 标题命中
    assert sm.grep(str(tmp_path), "配置") == ["n1"]
    # 卸载原文命中（标题里没有 test_login，但 refs 里有）
    assert sm.grep(str(tmp_path), "test_login") == ["n2"]
    assert sm.grep(str(tmp_path), "不存在的词") == []


def test_canvas_text_empty_when_no_nodes(tmp_path):
    assert sm.canvas_text(str(tmp_path)) == ""


def test_bad_workdir_safe(tmp_path):
    # 空 workdir 绝不写盘（相对 .纳川 会污染仓库）→ add_node 返回 None，读类全空
    assert sm.add_node("", "x") is None
    assert sm.canvas_text("") == ""
    assert sm.resolve("", "n1") == ""
    assert sm.grep("", "x") == []
    sm.clear("")  # 不抛


def test_clear_removes_canvas_and_refs(tmp_path):
    sm.add_node(str(tmp_path), "a", "x")
    sm.add_node(str(tmp_path), "b", "y")
    sm.clear(str(tmp_path))
    assert sm.canvas_text(str(tmp_path)) == ""
    assert not (tmp_path / ".纳川" / "画布.json").exists()
    assert not (tmp_path / ".纳川" / "refs").exists()


def test_harness_resume_injects_canvas_and_drilldown(tmp_path):
    """端到端：harness 建了画布 → resume_context 注入轻量 Mermaid、且能按 node_id 下钻全量原文。"""
    import orchestrator.task_state as ts

    ts.start_task(str(tmp_path), "重构导出模块", "1. 读代码\n2. 改结构")
    # 模拟一轮 harness：把「全量工具日志」卸载进画布节点
    big_log = "read_file: 3000行……\n" + ("X" * 5000)
    nid = sm.add_node(str(tmp_path), "读完导出模块代码", big_log, kind="step")
    # 续跑上下文里出现的是轻量画布（含 node_id），而不是 5000 字的原始日志
    ctx = ts.resume_context(str(tmp_path))
    assert "任务画布" in ctx and nid in ctx and "graph TD" in ctx
    assert "X" * 5000 not in ctx  # 大日志没被灌进上下文（省 token 的关键）
    # 要复盘细节时按 node_id 下钻，能拿回全量原文
    assert "X" * 5000 in sm.resolve(str(tmp_path), nid)


def test_task_state_clear_also_clears_canvas(tmp_path):
    """task_state.clear 连符号画布一起清（收尾干净）。"""
    import orchestrator.task_state as ts

    ts.start_task(str(tmp_path), "X", "1. A")
    sm.add_node(str(tmp_path), "干活", "日志")
    ts.clear(str(tmp_path))
    assert sm.canvas_text(str(tmp_path)) == ""
    assert not (tmp_path / ".纳川" / "画布.json").exists()
