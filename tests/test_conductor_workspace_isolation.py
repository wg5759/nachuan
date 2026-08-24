"""Conductor 同层节点共享工作区时必须隔离有副作用的执行。"""

from __future__ import annotations

import asyncio
import json

import pytest

import orchestrator.conductor as cd
import orchestrator.orchestrated_agent as oa
import orchestrator.scoreboard as sb
from tests.review_fixtures import trusted_chat_result, trusted_route, with_author_receipt


class _Router:
    def routes_info(self):
        return [
            {
                "model": "worker",
                "provider": "vendor-a",
                "tier": "premium",
                "rank": 1,
                "flagship": False,
                "independence_domain": "sha256:" + "1" * 64,
                "upstream_model": "gpt-4o",
                "model_family": "openai",
            },
            {
                "model": "reviewer",
                "provider": "vendor-b",
                "tier": "premium",
                "rank": 2,
                "flagship": False,
                "independence_domain": "sha256:" + "2" * 64,
                "upstream_model": "claude-sonnet-4-6",
                "model_family": "anthropic",
            },
        ]

    def resolve(self, model):  # noqa: ANN001
        row = next((row for row in self.routes_info() if row["model"] == model), None)
        return trusted_route(row) if row else None


@pytest.fixture(autouse=True)
def _isolated_scoreboard(monkeypatch, tmp_path):  # noqa: ANN001
    monkeypatch.setattr(sb, "_db_path", lambda: str(tmp_path / "scoreboard.db"))
    sb.reset()
    yield
    sb.reset()


@pytest.mark.parametrize(
    ("allow", "expected_max_active"),
    [
        ({"read_file", "write_file"}, 1),
        ({"read_file", "list_dir"}, 2),
    ],
)
async def test_shared_workdir_parallelism_follows_tool_capabilities(
    monkeypatch, tmp_path, allow, expected_max_active  # noqa: ANN001
) -> None:
    dag = json.dumps(
        {
            "model_id": ["worker", "worker"],
            "subtasks": ["修改模块 A", "修改模块 B"],
            "access_list": [[], []],
        }
    )

    async def fake_plan_chat(router, req):  # noqa: ANN001
        route = router.resolve(req.model)
        response = {
            "model": route.upstream_model,
            "choices": [{"message": {"content": dag}}],
        }
        return trusted_chat_result(
            request_payload=req.model_dump(exclude_none=True),
            response=response,
            requested_model=req.model,
            actual_model=req.model,
            route=route,
        )

    async def fake_verify_chat(router, req):  # noqa: ANN001
        route = router.resolve(req.model)
        response = {
            "model": route.upstream_model,
            "choices": [{"message": {"content": "PASS"}}],
        }
        return trusted_chat_result(
            request_payload=req.model_dump(exclude_none=True),
            response=response,
            requested_model=req.model,
            actual_model=req.model,
            route=route,
        )

    active = 0
    max_active = 0

    async def fake_run(router, model, task, **kwargs):  # noqa: ANN001
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.02)
        active -= 1
        return with_author_receipt(router, model, {
            "reply": task,
            "steps": 1,
            "model": model,
            "usage": {},
            "tool_log": ["write_file(shared.py)"],
            "file_changes": ["shared.py"],
            "media": [],
        })

    monkeypatch.setattr(cd, "chat_with_fallback", fake_plan_chat)
    monkeypatch.setattr(oa, "chat_with_fallback", fake_verify_chat)
    monkeypatch.setattr(cd, "run_tool_agent", fake_run)

    result = await cd.run_conductor_agent(
        _Router(),
        "并行修改两个模块",
        workdir=str(tmp_path),
        allow=allow,
    )

    assert result["reviewed"] is False
    assert result["verified"] is False
    assert result["outcome"] == "partial"
    assert (
        result["_route"]["post_summary_review_error"]
        == "no_strong_independent_final_reviewer"
    )
    assert max_active == expected_max_active
