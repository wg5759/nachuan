"""长任务 harness：workdir 里的持久化任务状态（.纳川/任务.json + 进展.md）。"""

from __future__ import annotations

import json

import orchestrator.task_state as ts


def test_start_task_writes_state(tmp_path):
    st = ts.start_task(str(tmp_path), "重构整个项目的架构", "1. 读代码\n2. 改结构\n验收标准：测试过\n3. 跑测试")
    assert st is not None
    data = json.loads((tmp_path / ".纳川" / "任务.json").read_text(encoding="utf-8"))
    assert data["goal"] == "重构整个项目的架构"
    titles = [s["title"] for s in data["steps"]]
    assert titles == ["读代码", "改结构", "跑测试"]  # 验收标准被剥掉，只留主干
    assert all(not s["done"] for s in data["steps"])
    assert (tmp_path / ".纳川" / "进展.md").exists()


def test_load_none_when_absent(tmp_path):
    assert ts.load(str(tmp_path)) is None


def test_record_progress_marks_done_and_journals(tmp_path):
    ts.start_task(str(tmp_path), "目标X", "1. A\n2. B\n3. C")
    ts.record_progress(str(tmp_path), "干完了A和B", done_titles=["A", "B"])
    data = ts.load(str(tmp_path))
    done = {s["title"]: s["done"] for s in data["steps"]}
    assert done == {"A": True, "B": True, "C": False}
    journal = (tmp_path / ".纳川" / "进展.md").read_text(encoding="utf-8")
    assert "干完了A和B" in journal


def test_completed_marks_all_and_flag(tmp_path):
    ts.start_task(str(tmp_path), "目标X", "1. A\n2. B")
    ts.record_progress(str(tmp_path), "全部搞定", completed=True)
    data = ts.load(str(tmp_path))
    assert data["completed"] is True and all(s["done"] for s in data["steps"])


def test_continuation_detection(tmp_path):
    ts.start_task(str(tmp_path), "把导出功能做完并加测试", "1. 写导出\n2. 加测试")
    st = ts.load(str(tmp_path))
    # 短续跑词 → 续跑
    assert ts.looks_like_continuation("继续", st) is True
    assert ts.looks_like_continuation("接着往下做", st) is True
    # 关键词高度重合 → 续跑
    assert ts.looks_like_continuation("导出功能和测试还没做完吧", st) is True
    # 完全不相关的新任务 → 不续跑（避免串味）
    assert ts.looks_like_continuation("帮我查下今天的天气", st) is False


def test_continuation_false_when_completed(tmp_path):
    ts.start_task(str(tmp_path), "目标X", "1. A")
    ts.record_progress(str(tmp_path), "done", completed=True)
    st = ts.load(str(tmp_path))
    assert ts.looks_like_continuation("继续", st) is False  # 已完成，无可续


def test_resume_context_has_todo_and_done(tmp_path):
    ts.start_task(str(tmp_path), "做导出", "1. 写导出\n2. 加测试\n3. 写文档")
    ts.record_progress(str(tmp_path), "导出写好了", done_titles=["写导出"])
    ctx = ts.resume_context(str(tmp_path))
    assert "接着上次" in ctx and "做导出" in ctx
    assert "写导出" in ctx  # 已完成里
    assert "加测试" in ctx and "写文档" in ctx  # 待办里


def test_clear_removes_files(tmp_path):
    ts.start_task(str(tmp_path), "X", "1. A")
    ts.clear(str(tmp_path))
    assert ts.load(str(tmp_path)) is None
    assert not (tmp_path / ".纳川" / "任务.json").exists()


def test_record_note_and_resume_injects_memory(tmp_path):
    """记忆银行(RooFlow 借鉴)：关键决策/约定写进 记忆.md，续跑上下文优先带回。"""
    ts.start_task(str(tmp_path), "做导出", "1. 写导出")
    ts.record_note(str(tmp_path), "决策", "用 CSV 不用 Excel（依赖少）")
    ts.record_note(str(tmp_path), "约定", "缩进 2 空格")
    assert (tmp_path / ".纳川" / "记忆.md").exists()
    ctx = ts.resume_context(str(tmp_path))
    assert "关键决策与约定" in ctx
    assert "用 CSV 不用 Excel" in ctx and "缩进 2 空格" in ctx


def test_bad_workdir_safe(tmp_path):
    # 不存在的父目录 / 空 workdir 都不该抛
    assert ts.load("") is None
    assert ts.resume_context("") == ""
    ts.record_progress("", "x")  # 不抛即可


def test_detect_verify_cmd_python(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert ts.detect_verify_cmd(str(tmp_path)) == "python -m pytest -q"


def test_detect_verify_cmd_npm(tmp_path):
    import json as _j
    (tmp_path / "package.json").write_text(_j.dumps({"scripts": {"test": "jest"}}), encoding="utf-8")
    assert ts.detect_verify_cmd(str(tmp_path)) == "npm test --silent"


def test_detect_verify_cmd_none(tmp_path):
    (tmp_path / "readme.txt").write_text("hi", encoding="utf-8")
    assert ts.detect_verify_cmd(str(tmp_path)) == ""


def test_start_task_detects_but_does_not_store_executable_command(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    ts.start_task(str(tmp_path), "改代码", "1. 改\n2. 测")
    assert ts.get_verify_cmd(str(tmp_path)) == "python -m pytest -q"
    state = ts.load(str(tmp_path))
    assert state is not None and "verify_cmd" not in state


def test_writable_task_state_cannot_inject_verification_command(tmp_path):
    ts.start_task(str(tmp_path), "普通任务", "1. 做")
    path = tmp_path / ".纳川" / "任务.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["verify_cmd"] = "powershell -c Get-Content approval_admin_key.txt"
    path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")

    assert ts.get_verify_cmd(str(tmp_path)) == ""
    ts.set_verify_cmd(str(tmp_path), "cmd /c whoami")
    assert ts.get_verify_cmd(str(tmp_path)) == ""
