from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import ModuleType

import pytest

import engine_main
from gateway import runtime_profile


def _bind_store_profile(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / runtime_profile.STORE_RUNTIME_PROFILE_MANIFEST_NAME
    data = runtime_profile.STORE_RUNTIME_PROFILE_MANIFEST_PATH.read_bytes()
    target.write_bytes(data)
    monkeypatch.setattr(
        runtime_profile,
        "_expected_packaged_profile_path",
        lambda: target.resolve(),
    )
    monkeypatch.setenv("NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST", str(target.resolve()))
    monkeypatch.setenv(
        "NACHUAN_STORE_RUNTIME_PROFILE_SHA256",
        hashlib.sha256(data).hexdigest(),
    )


def test_source_engine_does_not_force_production_accounting(monkeypatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "off")

    engine_main.enforce_frozen_financial_ledger()

    assert __import__("os").environ["NACHUAN_PROVIDER_CALL_LEDGER_MODE"] == "off"


def test_frozen_engine_requires_trusted_absolute_data_directory(monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("DATA_DIR", raising=False)

    with pytest.raises(RuntimeError, match="absolute DATA_DIR"):
        engine_main.enforce_frozen_financial_ledger()


def test_frozen_engine_overrides_inherited_financial_ledger_settings(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "off")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", "attacker.db")

    engine_main.enforce_frozen_financial_ledger()

    import os

    assert os.environ["NACHUAN_PROVIDER_CALL_LEDGER_MODE"] == "required"
    assert os.environ["NACHUAN_PROVIDER_CALL_LEDGER_PATH"] == str(
        tmp_path / "provider-calls.db"
    )


def test_frozen_entrypoint_preserves_launcher_session_authority_until_app_import(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    _bind_store_profile(monkeypatch, tmp_path)
    authority = {
        "NACHUAN_ENGINE_BOOT_TOKEN": "ab" * 32,
        "NACHUAN_ENGINE_GENERATION": "19",
        "NACHUAN_ENGINE_PORT": "43211",
    }
    for name, value in authority.items():
        monkeypatch.setenv(name, value)
    observed: list[dict[str, str | None]] = []
    fake = ModuleType("gateway.app")

    def main() -> None:
        observed.append(
            {
                name: engine_main.os.environ.get(name)
                for name in (*authority, *ledger_environment)
            }
        )

    fake.main = main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.app", fake)

    ledger_environment = (
        "NACHUAN_PROVIDER_CALL_LEDGER_MODE",
        "NACHUAN_PROVIDER_CALL_LEDGER_PATH",
    )
    original_ledger_environment = {
        name: engine_main.os.environ.get(name) for name in ledger_environment
    }
    with monkeypatch.context() as ledger_env:
        ledger_env.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "off")
        ledger_env.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", "attacker.db")
        assert engine_main.run_engine_entrypoint([]) == 0

    assert observed == [
        {
            **authority,
            "NACHUAN_PROVIDER_CALL_LEDGER_MODE": "required",
            "NACHUAN_PROVIDER_CALL_LEDGER_PATH": str(tmp_path / "provider-calls.db"),
        }
    ]
    assert {
        name: engine_main.os.environ.get(name) for name in ledger_environment
    } == original_ledger_environment


def test_installer_argument_is_exact_and_never_starts_gateway(monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    calls: list[bool] = []
    fake = ModuleType("gateway.installation_bootstrap")
    fake.provision_fixed_authority = lambda: calls.append(True)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.installation_bootstrap", fake)

    assert engine_main.run_engine_entrypoint(
        [engine_main.INSTALLATION_PROVISION_ARGUMENT]
    ) == 0
    assert calls == [True]
    assert engine_main.run_engine_entrypoint(
        [engine_main.INSTALLATION_PROVISION_ARGUMENT, "extra"]
    ) == 64
    assert calls == [True]


def test_packaged_entrypoint_can_run_the_bundled_weixin_bridge_without_starting_gateway(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    _bind_store_profile(monkeypatch, tmp_path)
    calls: list[str] = []
    fake_bridge = ModuleType("scripts.run_weixin_ilink_bridge")
    fake_bridge.main = lambda: calls.append("weixin")  # type: ignore[attr-defined]
    fake_gateway = ModuleType("gateway.app")
    fake_gateway.main = lambda: calls.append("gateway")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scripts.run_weixin_ilink_bridge", fake_bridge)
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)

    assert engine_main.run_engine_entrypoint(["--nachuan-weixin-bridge"]) == 0
    assert calls == ["weixin"]


def test_installer_argument_refuses_source_or_non_windows_execution(monkeypatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert engine_main.run_engine_entrypoint(
        [engine_main.INSTALLATION_PROVISION_ARGUMENT]
    ) == 77

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "posix")
    assert engine_main.run_engine_entrypoint(
        [engine_main.INSTALLATION_PROVISION_ARGUMENT]
    ) == 77


def test_installer_failure_returns_fixed_nonsecret_error(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    fake = ModuleType("gateway.installation_bootstrap")

    def fail() -> None:
        raise RuntimeError("SECRET C:/ProgramData owner SID")

    fake.provision_fixed_authority = fail  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gateway.installation_bootstrap", fake)

    assert engine_main.run_engine_entrypoint(
        [engine_main.INSTALLATION_PROVISION_ARGUMENT]
    ) == 69
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "NACHUAN_INSTALLATION_AUTHORITY_FAILED\n"
    assert "SECRET" not in captured.err


def test_isolated_plugin_worker_argument_rejects_nonfrozen_or_unattested_callers(
    monkeypatch,
) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert engine_main.run_engine_entrypoint(
        [
            engine_main.ISOLATED_PLUGIN_WORKER_ARGUMENT,
            "plugin.py",
            "1024",
            "1024",
            "500",
            str(64 * 1024 * 1024),
        ]
    ) == 77

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    fake_attestation = ModuleType("orchestrator.windows_appcontainer")
    fake_attestation.current_process_is_nachuan_appcontainer = lambda: False  # type: ignore[attr-defined]
    fake_attestation.fence_current_process_singleton = lambda **_kwargs: False  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "orchestrator.windows_appcontainer",
        fake_attestation,
    )
    assert engine_main.run_engine_entrypoint(
        [
            engine_main.ISOLATED_PLUGIN_WORKER_ARGUMENT,
            "plugin.py",
            "1024",
            "1024",
            "500",
            str(64 * 1024 * 1024),
        ]
    ) == 77
    assert engine_main.run_engine_entrypoint(
        [engine_main.ISOLATED_PLUGIN_WORKER_ARGUMENT, "plugin.py", "1024"]
    ) == 64


def test_attested_frozen_isolated_plugin_worker_dispatches_only_closed_arguments(
    monkeypatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    fake_attestation = ModuleType("orchestrator.windows_appcontainer")
    fake_attestation.current_process_is_nachuan_appcontainer = lambda: True  # type: ignore[attr-defined]
    fake_attestation.fence_current_process_singleton = lambda **_kwargs: True  # type: ignore[attr-defined]
    calls: list[tuple[str, int, int]] = []
    fake_worker = ModuleType("cli.isolated_plugin_worker_entrypoint")

    def run(path: str, *, max_request: int, max_response: int) -> int:
        calls.append((path, max_request, max_response))
        return 23

    fake_worker.run = run  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "orchestrator.windows_appcontainer",
        fake_attestation,
    )
    monkeypatch.setitem(sys.modules, "cli.isolated_plugin_worker_entrypoint", fake_worker)

    assert engine_main.run_engine_entrypoint(
        [
            engine_main.ISOLATED_PLUGIN_WORKER_ARGUMENT,
            "plugin.py",
            "2048",
            "4096",
            "500",
            str(64 * 1024 * 1024),
        ]
    ) == 23
    assert calls == [("plugin.py", 2048, 4096)]
