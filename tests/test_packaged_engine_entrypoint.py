from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


_MANAGED_SUBSCRIPTION_ENVIRONMENT = (
    "CODEX_CLI_PATH",
    "CODEX_CLI_SHA256",
    "CODEX_CLI_TEMP_ROOT",
    "KIMI_CLI_PATH",
    "KIMI_CLI_SHA256",
    "KIMI_CLI_VERSION",
    "KIMI_CLI_TEMP_ROOT",
    "KIMI_CODE_HOME",
    "KIMI_DISABLE_TELEMETRY",
    "KIMI_CODE_NO_AUTO_UPDATE",
)


def test_packaged_engine_enables_required_ledger_before_gateway_import(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "off")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", "wrong.db")
    observed: list[dict[str, str | None]] = []
    fake_gateway = ModuleType("gateway.app")

    def fake_main() -> None:
        import os

        observed.append(
            {
                "mode": os.environ.get("NACHUAN_PROVIDER_CALL_LEDGER_MODE"),
                "path": os.environ.get("NACHUAN_PROVIDER_CALL_LEDGER_PATH"),
                "data_dir": os.environ.get("DATA_DIR"),
                "usage_path": os.environ.get("USAGE_DB_PATH"),
            }
        )

    fake_gateway.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)

    from cli.engine_entrypoint import main

    main()

    assert observed == [
        {
            "mode": "required",
            "path": str(tmp_path / "provider-calls.db"),
            "data_dir": str(tmp_path),
            "usage_path": str(tmp_path / "usage.db"),
        }
    ]


def test_packaged_engine_restores_protected_subscription_binding_before_gateway_import(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CODEX_CLI_PATH", raising=False)
    monkeypatch.delenv("CODEX_CLI_SHA256", raising=False)
    observed: list[tuple[str | None, str | None]] = []
    fake_gateway = ModuleType("gateway.app")

    def fake_load(data_dir: Path) -> dict[str, str]:
        assert data_dir == tmp_path
        return {
            "CODEX_CLI_PATH": r"D:\trusted\codex.exe",
            "CODEX_CLI_SHA256": "a" * 64,
            "CODEX_CLI_TEMP_ROOT": r"D:\trusted\runtime",
        }

    def fake_main() -> None:
        import os

        observed.append(
            (
                os.environ.get("CODEX_CLI_PATH"),
                os.environ.get("CODEX_CLI_SHA256"),
            )
        )

    fake_gateway.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)
    monkeypatch.setattr(
        "gateway.subscription_cli_config.load_subscription_cli_environment",
        fake_load,
    )

    from cli.engine_entrypoint import main

    main()

    assert observed == [(r"D:\trusted\codex.exe", "a" * 64)]


def test_packaged_engine_ignores_all_ambient_subscription_binding_variables(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for name in _MANAGED_SUBSCRIPTION_ENVIRONMENT:
        monkeypatch.setenv(name, f"ambient-{name}")
    observed: list[dict[str, str | None]] = []
    fake_gateway = ModuleType("gateway.app")

    def fake_load(_data_dir: Path) -> dict[str, str]:
        return {
            "KIMI_CLI_PATH": r"D:\trusted\kimi.exe",
            "KIMI_CLI_SHA256": "b" * 64,
            "KIMI_CLI_VERSION": "0.27.0",
            "KIMI_CLI_TEMP_ROOT": r"D:\trusted\kimi-temp",
            "KIMI_CODE_HOME": r"D:\trusted\kimi-home",
            "KIMI_DISABLE_TELEMETRY": "1",
            "KIMI_CODE_NO_AUTO_UPDATE": "1",
        }

    def fake_main() -> None:
        import os

        observed.append(
            {name: os.environ.get(name) for name in _MANAGED_SUBSCRIPTION_ENVIRONMENT}
        )

    fake_gateway.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)
    monkeypatch.setattr(
        "gateway.subscription_cli_config.load_subscription_cli_environment",
        fake_load,
    )

    from cli.engine_entrypoint import main

    main()

    assert observed == [
        {
            "CODEX_CLI_PATH": None,
            "CODEX_CLI_SHA256": None,
            "CODEX_CLI_TEMP_ROOT": None,
            "KIMI_CLI_PATH": r"D:\trusted\kimi.exe",
            "KIMI_CLI_SHA256": "b" * 64,
            "KIMI_CLI_VERSION": "0.27.0",
            "KIMI_CLI_TEMP_ROOT": r"D:\trusted\kimi-temp",
            "KIMI_CODE_HOME": r"D:\trusted\kimi-home",
            "KIMI_DISABLE_TELEMETRY": "1",
            "KIMI_CODE_NO_AUTO_UPDATE": "1",
        }
    ]


def test_packaged_engine_clears_all_subscription_variables_when_binding_is_invalid(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for name in _MANAGED_SUBSCRIPTION_ENVIRONMENT:
        monkeypatch.setenv(name, f"ambient-{name}")
    observed: list[dict[str, str | None]] = []
    fake_gateway = ModuleType("gateway.app")

    def fake_load(_data_dir: Path) -> dict[str, str]:
        from gateway.subscription_cli_config import SubscriptionCliConfigError

        raise SubscriptionCliConfigError("invalid")

    def fake_main() -> None:
        import os

        observed.append(
            {name: os.environ.get(name) for name in _MANAGED_SUBSCRIPTION_ENVIRONMENT}
        )

    fake_gateway.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)
    monkeypatch.setattr(
        "gateway.subscription_cli_config.load_subscription_cli_environment",
        fake_load,
    )

    from cli.engine_entrypoint import main

    main()

    assert observed == [
        {name: None for name in _MANAGED_SUBSCRIPTION_ENVIRONMENT}
    ]
    assert "subscription connectors are disabled" in capsys.readouterr().err


def test_packaged_engine_uses_stable_local_app_data_when_data_dir_is_unset(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    observed: list[str | None] = []
    fake_gateway = ModuleType("gateway.app")

    def fake_main() -> None:
        import os

        observed.append(os.environ.get("DATA_DIR"))

    fake_gateway.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)

    from cli.engine_entrypoint import main

    main()

    assert observed == [str(tmp_path / "Nachuan")]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI migration contract")
def test_first_default_start_imports_legacy_desktop_connections_as_unverified_dpapi(
    monkeypatch, tmp_path: Path
) -> None:
    legacy_key = "synthetic-legacy-agnes-key"
    roaming = tmp_path / "roaming"
    local = tmp_path / "local"
    legacy_path = roaming / "aggregator-desktop" / "data" / "connections.json"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text(
        json.dumps(
            {
                "agnes": {
                    "type": "openai_compat",
                    "api_key": legacy_key,
                    "base_url": "https://apihub.agnes-ai.com/v1",
                    "enabled_models": [
                        {
                            "id": "agnes-flash",
                            "upstream_model": "agnes-2.0-flash",
                            "modality": "chat",
                        },
                        {
                            "id": "agnes-image",
                            "upstream_model": "agnes-image-2.1-flash",
                            "modality": "image",
                        },
                        {
                            "id": "agnes-video",
                            "upstream_model": "agnes-video-v2.0",
                            "modality": "video",
                        },
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    legacy_before = legacy_path.read_bytes()
    gateway_started: list[bool] = []
    fake_gateway = ModuleType("gateway.app")

    def fake_main() -> None:
        destination = local / "Nachuan" / "connections.json"
        gateway_started.append(destination.is_file())

    fake_gateway.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.setenv("LOCALAPPDATA", str(local))

    from cli.engine_entrypoint import main
    from gateway.connections import ConnectionStore

    main()

    destination = local / "Nachuan" / "connections.json"
    assert gateway_started == [True], "migration must finish before Gateway import/start"
    assert legacy_path.read_bytes() == legacy_before
    assert legacy_key.encode() not in destination.read_bytes()
    assert json.loads(destination.read_text("utf-8"))["protection"] == (
        "windows-dpapi-current-user"
    )
    masked = ConnectionStore(destination).masked()["agnes"]
    assert masked["credential_present"] is True
    assert masked["state"] == "legacy_unverified"
    assert masked["verified_at"] is None
