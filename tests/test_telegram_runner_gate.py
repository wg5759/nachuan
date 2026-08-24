from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def _load_runner():
    path = Path(__file__).parents[1] / "scripts" / "run_telegram_bridge.py"
    spec = importlib.util.spec_from_file_location("run_telegram_gate_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_telegram_runner_fails_before_loading_credentials_by_default(monkeypatch):
    runner = _load_runner()
    monkeypatch.delenv("NACHUAN_ENV", raising=False)
    monkeypatch.delenv("NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM", raising=False)
    monkeypatch.setattr(
        runner,
        "get_isolated_bridge_settings",
        lambda: (_ for _ in ()).throw(AssertionError("credentials must not be loaded")),
    )

    assert runner.main() == 78


def test_telegram_runner_stays_disabled_in_production_even_with_confirmation(monkeypatch):
    runner = _load_runner()
    monkeypatch.setenv("NACHUAN_ENV", "production")
    monkeypatch.setenv(
        "NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM",
        runner._EXPERIMENTAL_CONFIRMATION,
    )
    monkeypatch.setattr(
        runner,
        "get_isolated_bridge_settings",
        lambda: (_ for _ in ()).throw(AssertionError("credentials must not be loaded")),
    )

    assert runner.main() == 78


def test_telegram_experiment_requires_exact_development_confirmation():
    runner = _load_runner()
    assert not runner._experimental_enabled(
        {
            "NACHUAN_ENV": "development",
            "NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM": "1",
        }
    )


def test_telegram_development_experiment_uses_only_scoped_bridge_key(monkeypatch):
    runner = _load_runner()
    monkeypatch.setenv("NACHUAN_ENV", "development")
    monkeypatch.setenv(
        "NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM",
        runner._EXPERIMENTAL_CONFIRMATION,
    )
    monkeypatch.setattr(
        runner,
        "get_isolated_bridge_settings",
        lambda: SimpleNamespace(
            telegram_bot_token="bot-token",
            telegram_allowed_set={"developer"},
            bridge_engine_url="http://127.0.0.1:8080",
            bridge_api_key="scoped-key",
            gateway_api_keys="runtime-key-must-not-be-used",
            bridge_model="glm",
        ),
    )
    captured = {}

    class FakeBridge:
        def __init__(self, _token, **kwargs):
            captured.update(kwargs)

        async def run(self):
            return None

    monkeypatch.setattr(runner, "TelegramBridge", FakeBridge)

    assert runner.main() == 0
    assert captured["engine_key"] == "scoped-key"
    assert runner._experimental_enabled(
        {
            "NACHUAN_ENV": "development",
            "NACHUAN_ENABLE_EXPERIMENTAL_TELEGRAM": runner._EXPERIMENTAL_CONFIRMATION,
        }
    )


def test_production_launch_and_release_closed_sets_exclude_telegram():
    root = Path(__file__).parents[1]
    launcher_path = root / "scripts" / "managed_launcher.py"
    launcher_spec = importlib.util.spec_from_file_location(
        "managed_launcher_telegram_closed_set_test", launcher_path
    )
    assert launcher_spec and launcher_spec.loader
    launcher = importlib.util.module_from_spec(launcher_spec)
    launcher_spec.loader.exec_module(launcher)
    supervisor = (root / "scripts" / "start_all.ps1").read_text("utf-8-sig")
    spec = (root / "engine.spec").read_text("utf-8")
    packaging = (root / "desktop" / "electron-builder.yml").read_text("utf-8")

    assert set(launcher._SERVICE_COMMANDS) == {"engine", "weixin", "feishu"}
    assert "run_telegram_bridge.py" not in supervisor
    assert "run_telegram_bridge.py" not in spec
    assert "run_telegram_bridge.py" not in packaging
