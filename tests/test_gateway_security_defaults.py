from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from gateway import auth
from gateway.config import PROJECT_ROOT, Settings, desktop_engine_keys
from gateway.app import app


class _NoKeys:
    api_keys: set[str] = set()


async def test_gateway_without_any_key_fails_closed(monkeypatch) -> None:
    monkeypatch.delenv("NACHUAN_ALLOW_ANONYMOUS_LOCAL", raising=False)
    monkeypatch.setattr(auth, "get_settings", lambda: _NoKeys())
    monkeypatch.setattr(auth, "desktop_engine_keys", lambda: frozenset())

    with pytest.raises(HTTPException) as exc:
        await auth.require_api_key(None)

    assert exc.value.status_code == 503


def test_remote_web_origin_cannot_use_the_loopback_gateway() -> None:
    with TestClient(app) as client:
        denied = client.options(
            "/v1/agent/chat",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        allowed = client.options(
            "/v1/agent/chat",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )

    assert denied.status_code >= 400
    assert "access-control-allow-origin" not in denied.headers
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


def test_supervisor_generates_a_non_default_gateway_key() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
    ).read_text("utf-8")

    assert "RandomNumberGenerator" in script
    assert "$env:GATEWAY_API_KEYS" in script
    assert "$env:APPROVAL_ADMIN_KEY" in script
    assert "approval_admin_key.txt" in script
    assert "$configured -ne 'sk-local-dev-changeme'" in script
    assert 'gateway_api_keys: str = ""' in (
        Path(__file__).resolve().parents[1] / "gateway" / "config.py"
    ).read_text("utf-8")
    assert 'approval_admin_key: str = ""' in (
        Path(__file__).resolve().parents[1] / "gateway" / "config.py"
    ).read_text("utf-8")


def test_relative_runtime_database_is_anchored_to_the_project_root() -> None:
    settings = Settings(usage_db_path="./data/usage.db", _env_file=None)

    assert Path(settings.usage_db_path).is_absolute()
    assert Path(settings.usage_db_path) == (PROJECT_ROOT / "data" / "usage.db").resolve()


def test_gateway_does_not_trust_ambient_roaming_config_files() -> None:
    desktop_engine_keys.cache_clear()
    assert desktop_engine_keys() == frozenset()


def test_scheduled_supervisor_drops_ambient_runtime_credentials_before_key_setup() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
    ).read_text("utf-8")
    scrub_start = script.index("if ($Scheduled) {")
    scrub_end = script.index("# Key creation is inside the cross-session lock", scrub_start)
    scrub = script[scrub_start:scrub_end]

    for name in (
        "GATEWAY_API_KEYS",
        "APPROVAL_ADMIN_KEY",
        "NACHUAN_ALLOW_ANONYMOUS_LOCAL",
    ):
        assert f"Env:{name}" in scrub
    assert "Remove-Item" in scrub
    assert scrub_end < script.index("Ensure-GatewayKey", scrub_end)


def test_supervisor_forces_utf8_for_every_managed_python_child() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
    ).read_text("utf-8-sig")

    assert "$env:PYTHONUTF8 = '1'" in script
    assert "$env:PYTHONIOENCODING = 'utf-8'" in script
    assert script.index("$env:PYTHONUTF8 = '1'") < script.index("function Start-ManagedProcess")


def test_supervisor_resume_hardens_the_runtime_tree_exactly_once() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
    ).read_text("utf-8-sig")
    protect_start = script.index("function Protect-PrivateRuntimeTree")
    protect_end = script.index("function Ensure-ApprovalAdminKey", protect_start)
    runtime_protection = script[protect_start:protect_end]
    resume_start = script.index("if ($Action -eq 'Resume')")
    resume_end = script.index("\nif ($DryRun) {", resume_start)
    resume = script[resume_start:resume_end]
    common_start = script.index("Initialize-PrivateRuntimeTree", resume_end)
    common = script[resume_end:common_start + len("Initialize-PrivateRuntimeTree")]

    assert runtime_protection.count("Protect-PrivateRuntimeTree $DataDir") == 1
    assert "$runtimeTreeInitialized = $false" in script[:protect_start]
    assert resume.count("Initialize-PrivateRuntimeTree") == 1
    assert "$runtimeTreeInitialized = $true" in resume
    assert "if (-not $runtimeTreeInitialized)" in common


def test_supervisor_gives_feishu_cold_sdk_import_a_bounded_startup_grace() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
    ).read_text("utf-8-sig")
    start = script.index("function Start-ManagedProcess")
    stop = script.index("function Stop-ProjectProcesses", start)
    launcher = script[start:stop]
    watchdog = script[script.index("function Invoke-WatchdogCycle") :]

    assert "$FeishuStartupGraceSeconds = 180" in script
    assert "$script:StartedAt[$Name] = $now" in launcher
    assert "$feishuStarting" in watchdog
    assert watchdog.index("elseif ($feishuStarting)") < watchdog.index(
        "feishu liveness/connection failed"
    )


def test_supervisor_does_not_forward_retired_claude_runtime_hooks() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "start_all.ps1"
    ).read_text("utf-8-sig")
    start = script.index("function Get-ManagedServiceEnvironment")
    end = script.index("function Start-ManagedProcess", start)
    managed_environment = script[start:end]

    assert "CLAUDE_CLI_PATH" not in managed_environment
    assert "CLAUDE_CLI_SHA256" not in managed_environment
    assert "CLAUDE_CONFIG_DIR" not in managed_environment


def test_legacy_sync_cannot_send_the_gateway_bearer_to_an_operator_url() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "gateway" / "app.py"
    ).read_text("utf-8")

    assert "SYNC_SERVER_URL is disabled" in source
    assert "sync_cases_once(app.state.cases" not in source
