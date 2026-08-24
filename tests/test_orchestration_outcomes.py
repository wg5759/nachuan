"""编排结果必须诚实区分已验证完成、未验证完成和部分产出。"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import orchestrator.conductor as cd
import orchestrator.orchestrated_agent as oa
import orchestrator.scoreboard as sb


@pytest.fixture(autouse=True)
def _isolated_scoreboard(monkeypatch, tmp_path):  # noqa: ANN001
    monkeypatch.setattr(sb, "_db_path", lambda: str(tmp_path / "scoreboard.db"))
    sb.reset()
    yield
    sb.reset()


class _Router:
    def routes_info(self):
        return [
            {
                "model": "worker",
                "provider": "vendor-a",
                "tier": "premium",
                "rank": 1,
                "flagship": False,
            }
        ]

    def resolve(self, model):  # noqa: ANN001
        if model != "worker":
            return None
        return SimpleNamespace(provider=None, upstream_model=model, tier="premium")


@pytest.mark.parametrize(
    ("reply", "steps", "tool_log", "expected_outcome"),
    [
        ("已完成一部分实现，但尚未通过验收", 2, ["read_file(a.py)"], "partial"),
        ("", 0, [], "failed"),
    ],
)
async def test_failed_verification_outcome_reflects_real_progress(
    monkeypatch, tmp_path, reply, steps, tool_log, expected_outcome  # noqa: ANN001
) -> None:
    async def fake_chat(router, req):  # noqa: ANN001
        prompt = str(req.messages[-1].content)
        answer = "FAIL:验收未通过" if "独立审核官" in prompt else "执行计划"
        return ({"choices": [{"message": {"content": answer}}]}, req.model, None)

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": reply,
            "steps": steps,
            "model": model,
            "usage": {},
            "tool_log": tool_log,
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(oa, "chat_with_fallback", fake_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    result = await oa.run_orchestrated_agent(
        _Router(),
        "请分析并重构这个复杂系统架构",
        workdir=str(tmp_path),
        model="worker",
        trinity=False,
        fast_first=False,
    )

    assert result["verified"] is False
    assert result["outcome"] == expected_outcome


async def test_simple_unverified_chat_is_explicitly_unverified(monkeypatch, tmp_path) -> None:
    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "你好！",
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": [],
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    result = await oa.run_orchestrated_agent(
        _Router(), "你好", workdir=str(tmp_path), model="worker", trinity=False
    )

    assert result["verified"] is None
    assert result["outcome"] == "completed_unverified"


async def test_simple_stopped_chat_is_partial_not_completed(monkeypatch, tmp_path) -> None:
    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "墙钟已到，只保留了阶段性结果",
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": ["read_file(a.py)"],
            "file_changes": [],
            "media": [],
            "stopped_reason": "wall_cap",
        }

    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    result = await oa.run_orchestrated_agent(
        _Router(), "你好", workdir=str(tmp_path), model="worker", trinity=False
    )

    assert result["verified"] is None
    assert result["outcome"] == "partial"


def test_stopped_reason_dominates_even_machine_verified_flag() -> None:
    result = {
        "reply": "只完成了一部分",
        "steps": 1,
        "stopped_reason": "capability_violation",
    }

    assert oa.apply_outcome(result, True) == "partial"


async def test_trinity_rejected_output_is_partial(monkeypatch, tmp_path) -> None:
    async def fake_pick(*args, **kwargs):  # noqa: ANN001
        return {"model": "worker", "role": "verifier", "instruction": "验收"}

    async def fake_chat(router, req):  # noqa: ANN001
        return ({"choices": [{"message": {"content": "FAIL:尚未达标"}}]}, req.model, None)

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "留下了可继续的阶段性产出",
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": ["read_file(a.py)"],
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(oa.coordinator, "pick_next", fake_pick)
    monkeypatch.setattr(oa, "chat_with_fallback", fake_chat)
    monkeypatch.setattr(oa, "run_tool_agent", fake_run)

    result = await oa.run_trinity_agent(
        _Router(),
        "分析并重构复杂系统",
        workdir=str(tmp_path),
        first_cast={"model": "worker", "role": "worker", "instruction": "先检查"},
    )

    assert result["verified"] is False
    assert result["outcome"] == "partial"


async def test_conductor_rejected_output_is_partial(monkeypatch, tmp_path) -> None:
    dag = json.dumps({"model_id": ["worker"], "subtasks": ["实现"], "access_list": [[]]})

    async def fake_plan_chat(router, req):  # noqa: ANN001
        return ({"choices": [{"message": {"content": dag}}]}, req.model, None)

    async def fake_verify_chat(router, req):  # noqa: ANN001
        return ({"choices": [{"message": {"content": "FAIL:仍缺验收证据"}}]}, req.model, None)

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        return {
            "reply": "完成了阶段实现",
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": ["read_file(a.py)"],
            "file_changes": [],
            "media": [],
        }

    monkeypatch.setattr(cd, "chat_with_fallback", fake_plan_chat)
    monkeypatch.setattr(oa, "chat_with_fallback", fake_verify_chat)
    monkeypatch.setattr(cd, "run_tool_agent", fake_run)

    result = await cd.run_conductor_agent(
        _Router(), "拆解并实现复杂系统", workdir=str(tmp_path)
    )

    assert result["verified"] is False
    assert result["outcome"] == "partial"
