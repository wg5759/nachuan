"""模式系统：难度分类器 + 单答模式调度（用 echo 实测）。"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

import gateway.app as appmod
from gateway.app import app
from gateway.schemas import ChatCompletionResponse, Usage
from orchestrator.classify import classify
from orchestrator.modes import pick_model, run_auto

AUTH = {"Authorization": "Bearer test-key"}


def test_model_call_roles_are_explicit_stable_and_unique():
    source = (
        Path(__file__).parents[1] / "orchestrator" / "modes.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    role_templates: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in {"_ask", "_ask_with_receipt", "_ask_observed", "_org_review"}:
            continue

        role_values = [keyword.value for keyword in node.keywords if keyword.arg == "role"]
        assert len(role_values) == 1, f"{node.func.id} at line {node.lineno} must set one role"
        role_value = role_values[0]
        if isinstance(role_value, ast.Name) and role_value.id == "role":
            continue  # Thin helper forwarding; uniqueness is enforced at its call sites.
        assert isinstance(role_value, (ast.Constant, ast.JoinedStr)), (
            f"{node.func.id} at line {node.lineno} must use a stable role template"
        )
        role_templates.append(ast.unparse(role_value))

    assert role_templates
    assert len(role_templates) == len(set(role_templates)), "model-call role templates must be unique"


def test_pick_model_treats_zero_rank_as_unranked_fallback():
    class RankRouter:
        @staticmethod
        def routes_info():
            return [
                {
                    "model": "unranked",
                    "provider": "vendor-a",
                    "tier": "premium",
                    "rank": 0,
                    "flagship": False,
                },
                {
                    "model": "ranked",
                    "provider": "vendor-b",
                    "tier": "premium",
                    "rank": 7,
                    "flagship": False,
                },
            ]

    assert pick_model(RankRouter(), "premium") == "ranked"


def test_classify_difficulty():
    assert classify("你好")["difficulty"] == "easy"
    assert classify("请证明该算法复杂度并给出优化")["difficulty"] == "hard"
    assert classify("```python\ndef f():\n  pass\n```")["kind"] == "code"
    assert classify("x" * 2000)["difficulty"] == "hard"  # 超长视为难


def test_route_single_answer_modes():
    with TestClient(app) as c:
        # 测试只留 echo provider：别在测试里真调 claude/codex CLI（白占套餐额度、偶发 502）。
        # pick_model 在某档无模型时会兜底到 echo，四个模式都能跑通。
        app.state.router._routes = {
            k: v for k, v in app.state.router._routes.items() if k == "echo"
        }
        for mode in ["smart", "economy", "best", "cascade"]:
            r = c.post(
                "/v1/route",
                headers=AUTH,
                json={"mode": mode, "messages": [{"role": "user", "content": "你好"}]},
            )
            assert r.status_code == 200, mode
            d = r.json()
            assert d["choices"][0]["message"]["content"]  # 拿到答案
            assert d["_route"]["mode"] == mode
            assert d["_route"].get("model")  # 记录了用哪个模型


def test_route_unknown_mode():
    with TestClient(app) as c:
        r = c.post(
            "/v1/route",
            headers=AUTH,
            json={"mode": "nope", "messages": [{"role": "user", "content": "x"}]},
        )
        assert r.status_code == 422


def test_route_usage_uses_invocation_receipt_not_hot_reloaded_router(monkeypatch):
    captured: list[dict] = []

    class PoisonRouter:
        resolve_calls = 0

        def resolve(self, model):  # noqa: ANN001
            self.resolve_calls += 1
            raise AssertionError("usage accounting must not re-resolve a hot route")

    async def fake_mode(router, messages):  # noqa: ANN001
        return {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"total_tokens": 2},
            "_route": {
                "route_receipt_version": 1,
                "model": "actual-model",
                "requested_model": "requested-model",
                "actual_model": "actual-model",
                "provider": "call-time-provider",
                "upstream_model": "call-time-upstream",
                "tier": "premium",
            },
        }

    async def fake_log(logger, **values):  # noqa: ANN001
        captured.append(values)
        return True

    monkeypatch.setitem(appmod.SINGLE_ANSWER_MODES, "receipt-test", fake_mode)
    monkeypatch.setattr(appmod, "_log_usage_best_effort", fake_log)
    with TestClient(app) as client:
        original_router = client.app.state.router
        poison = PoisonRouter()
        client.app.state.router = poison
        try:
            response = client.post(
                "/v1/route",
                headers=AUTH,
                json={
                    "mode": "receipt-test",
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
        finally:
            client.app.state.router = original_router

    assert response.status_code == 200
    assert poison.resolve_calls == 0
    assert captured[-1]["virtual_model"] == "receipt-test"
    assert captured[-1]["provider"] == "call-time-provider"
    assert captured[-1]["upstream_model"] == "call-time-upstream"
    assert captured[-1]["tier"] == "premium"


def test_route_unserved_usage_never_falls_back_to_mode_as_upstream(monkeypatch):
    captured: list[dict] = []

    async def fake_mode(router, messages):  # noqa: ANN001
        return {
            "choices": [{"message": {"content": "local fallback"}}],
            "usage": {},
            "_route": {
                "route_receipt_version": 1,
                "model": None,
                "requested_model": "requested-model",
                "actual_model": None,
                "provider": None,
                "upstream_model": None,
                "tier": None,
                "model_identity_error": "not_called",
            },
        }

    async def fake_log(logger, **values):  # noqa: ANN001
        captured.append(values)
        return True

    monkeypatch.setitem(appmod.SINGLE_ANSWER_MODES, "unserved-test", fake_mode)
    monkeypatch.setattr(appmod, "_log_usage_best_effort", fake_log)
    with TestClient(app) as client:
        response = client.post(
            "/v1/route",
            headers=AUTH,
            json={
                "mode": "unserved-test",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    assert captured[-1]["virtual_model"] == "unserved-test"
    assert captured[-1]["provider"] == "mode-unserved"
    assert captured[-1]["upstream_model"] == ""
    assert captured[-1]["upstream_model"] != "unserved-test"


class _Provider:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def chat(self, req, upstream_model):  # noqa: ANN001
        self.calls.append(upstream_model)
        return ChatCompletionResponse.from_text(
            model=req.model,
            text=f"served:{upstream_model}",
            usage=Usage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        ).model_dump()


class _Router:
    def __init__(self, provider: _Provider) -> None:
        self.provider = provider

    def routes_info(self):
        return [
            {"model": "agnes-flash", "provider": "agnes", "tier": "free", "rank": 1},
            {"model": "gpt-5.4", "provider": "openai", "tier": "premium", "rank": 2},
        ]

    def resolve(self, model):
        if model not in {"agnes-flash", "gpt-5.4"}:
            return None
        tier = "premium" if model == "gpt-5.4" else "free"
        return SimpleNamespace(provider=self.provider, upstream_model=model, tier=tier)


def test_auto_context_followup_prefers_premium():
    provider = _Provider()
    result = asyncio.run(
        run_auto(
            _Router(provider),
            [
                {"role": "assistant", "content": "已启动今日视频渲染。日志：duo_run.log"},
                {
                    "role": "system",
                    "content": "本轮用户是对上一轮的短追问，不是让你解释这个短语本身。",
                },
                {"role": "user", "content": "然后呢？"},
            ],
        )
    )

    assert result["_route"]["tier"] == "context_followup"
    assert result["_route"]["model"] == "gpt-5.4"
    assert provider.calls == ["gpt-5.4"]
