"""执行脊柱·任务台账：分解解析 + 逐步执行 + 重试 + 断点续跑。"""

from __future__ import annotations

import os
import tempfile

import pytest

from orchestrator.ledger import TaskLedger, freeze_execution_spec, parse_steps, run_job


def _ledger() -> TaskLedger:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return TaskLedger(path)


def test_parse_steps_extracts_json():
    txt = '好的：\n[{"title":"抽帧","detail":"用ffmpeg","kind":"action"},{"title":"分析","kind":"reason"}]\n完成'
    steps = parse_steps(txt)
    assert len(steps) == 2
    assert steps[0]["title"] == "抽帧" and steps[0]["kind"] == "action"
    assert steps[1]["kind"] == "reason"
    assert steps[1]["deps"] == [0]  # 默认线性依赖


def test_parse_steps_bad_input():
    assert parse_steps("没有 JSON 的纯文本") == []


def test_execution_spec_rejects_unbounded_work() -> None:
    with pytest.raises(ValueError, match="at most 100"):
        freeze_execution_spec(
            goal="too many calls",
            steps=[{"title": str(i)} for i in range(101)],
            workdir=".",
            backend="auto",
            mode="plan",
        )


def test_execution_spec_rejects_retired_claude_backend() -> None:
    with pytest.raises(ValueError, match="backend must be auto or codex"):
        freeze_execution_spec(
            goal="must stay disabled",
            steps=[{"title": "one"}],
            workdir=".",
            backend="claude",
            mode="plan",
        )
    with pytest.raises(ValueError, match="goal exceeds"):
        freeze_execution_spec(
            goal="x" * 32_001,
            steps=[{"title": "one"}],
            workdir=".",
            backend="auto",
            mode="plan",
        )


async def test_run_job_all_steps_done():
    led = _ledger()
    jid = led.create_job("造个东西", [{"title": "a"}, {"title": "b"}, {"title": "c"}])
    seen: list[int] = []

    async def ex(step):
        seen.append(step["idx"])
        return f"ok-{step['idx']}"

    out = await run_job(led, jid, ex)
    assert out["status"] == "done"
    assert out["progress"] == "3/3"
    assert seen == [0, 1, 2]  # 按依赖顺序
    assert "ok-0" in out["result"]


async def test_run_job_retries_then_succeeds():
    led = _ledger()
    jid = led.create_job("会抖一下", [{"title": "flaky"}])
    calls = {"n": 0}

    async def ex(step):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("第一次失败")
        return "第二次成功"

    out = await run_job(led, jid, ex, max_attempts=2)
    assert out["status"] == "done"
    assert calls["n"] == 2  # 重试了一次才成功


async def test_resume_after_failure_skips_done():
    """模拟跑崩：第2步耗尽重试→整单 failed；修好后 recover+重跑→从断点续，不重做第1步。"""
    led = _ledger()
    jid = led.create_job("断点续跑", [{"title": "s1"}, {"title": "s2"}])
    runs = {"s1": 0, "s2": 0}
    broken = {"on": True}

    async def ex(step):
        runs[step["title"]] += 1
        if step["title"] == "s2" and broken["on"]:
            raise RuntimeError("s2 坏了")
        return "ok"

    out1 = await run_job(led, jid, ex, max_attempts=2)
    assert out1["status"] == "failed"
    assert runs["s1"] == 1  # 第1步成功一次

    broken["on"] = False  # 修好 s2
    out2 = await run_job(led, jid, ex, max_attempts=2)
    assert out2["status"] == "done"
    assert out2["progress"] == "2/2"
    assert runs["s1"] == 1  # 关键：断点续跑——第1步没有重做（done 被跳过）
