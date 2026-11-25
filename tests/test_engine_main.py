from __future__ import annotations

import hashlib
import os
import subprocess
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


def test_packaged_entrypoint_can_run_the_bundled_feishu_bridge_without_starting_gateway(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    _bind_store_profile(monkeypatch, tmp_path)
    calls: list[str] = []
    fake_bridge = ModuleType("scripts.run_feishu_bridge")
    fake_bridge.main = lambda: calls.append("feishu")  # type: ignore[attr-defined]
    fake_gateway = ModuleType("gateway.app")
    fake_gateway.main = lambda: calls.append("gateway")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scripts.run_feishu_bridge", fake_bridge)
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)

    assert engine_main.run_engine_entrypoint(["--nachuan-feishu-bridge"]) == 0
    assert calls == ["feishu"]


@pytest.mark.parametrize(
    "argument,module_name",
    (
        ("--nachuan-weixin-bridge", "scripts.run_weixin_ilink_bridge"),
        ("--nachuan-feishu-bridge", "scripts.run_feishu_bridge"),
    ),
)
def test_installed_bridge_verbs_refuse_source_or_nonwindows_callers(
    monkeypatch, argument, module_name
) -> None:
    calls: list[str] = []
    fake_bridge = ModuleType(module_name)
    fake_bridge.main = lambda: calls.append("bridge")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module_name, fake_bridge)

    monkeypatch.delattr(sys, "frozen", raising=False)
    assert engine_main.run_engine_entrypoint([argument]) == 77
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "posix")
    assert engine_main.run_engine_entrypoint([argument]) == 77
    assert calls == []


def test_engine_spec_freezes_both_installed_channel_bridges() -> None:
    source = (Path(__file__).parents[1] / "engine.spec").read_text("utf-8")

    assert "'scripts.run_weixin_ilink_bridge'" in source
    assert "'scripts.run_feishu_bridge'" in source


@pytest.mark.parametrize('argument,module_name', [('--nachuan-feishu-bridge', 'scripts.run_feishu_bridge'), ('--nachuan-weixin-bridge', 'scripts.run_weixin_ilink_bridge')])
@pytest.mark.parametrize('status,expected', [(None, 0), (0, 0), (1, 1), (78, 78), (True, 69), ('0', 69), (-1, 69)])
def test_packaged_bridge_exit_status_is_not_discarded(monkeypatch, tmp_path, argument, module_name, status, expected):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    _bind_store_profile(monkeypatch, tmp_path)
    fake=ModuleType(module_name)
    fake.main=lambda: status
    monkeypatch.setitem(sys.modules, module_name, fake)
    assert engine_main.run_engine_entrypoint([argument]) == expected


def test_frozen_and_packaged_release_gates_require_the_nachuan_core_host() -> None:
    root = Path(__file__).parents[1]
    spec = (root / "engine.spec").read_text("utf-8")
    release_gate = (
        root / "desktop" / "scripts" / "_verify_pack.mjs"
    ).read_text("utf-8")
    required_modules = (
        "gateway.windows_nachuan_core_service_host",
        "gateway.installed_channel_service_runtime",
        "gateway.installed_channel_drain",
        "gateway.installed_channel_child_drain_runtime",
        "gateway.windows_installed_drain_pipe",
        "gateway.installed_nachuan_core_identity",
        "gateway.installed_service_machine_vault",
        "gateway.installed_service_state_acl",
    )

    assert "'gateway.windows_nachuan_core_service_host'" in spec
    assert "'gateway.installed_channel_service_runtime'" in spec
    assert "'gateway.installed_channel_drain'" in spec
    assert "'gateway.installed_channel_child_drain_runtime'" in spec
    assert "'gateway.windows_installed_drain_pipe'" in spec
    for module in required_modules:
        assert f"'{module}'" in release_gate


def test_packaged_entrypoint_dispatches_the_installed_channel_supervisor(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    installed_resources = (tmp_path / "installed" / "resources").resolve()
    engine = installed_resources / "engine" / "engine.exe"
    engine.parent.mkdir(parents=True)
    engine.write_bytes(b"test-only-engine")
    profile = installed_resources / runtime_profile.STORE_RUNTIME_PROFILE_MANIFEST_NAME
    profile.write_bytes(runtime_profile.STORE_RUNTIME_PROFILE_MANIFEST_PATH.read_bytes())
    monkeypatch.setattr(sys, "executable", str(engine))
    monkeypatch.delenv("NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST", raising=False)
    monkeypatch.delenv("NACHUAN_STORE_RUNTIME_PROFILE_SHA256", raising=False)
    calls: list[str] = []
    fake_supervisor = ModuleType("gateway.installed_channel_supervisor_entrypoint")
    fake_supervisor.run = lambda: calls.append("supervisor") or 0  # type: ignore[attr-defined]
    fake_gateway = ModuleType("gateway.app")
    fake_gateway.main = lambda: calls.append("gateway")  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.installed_channel_supervisor_entrypoint",
        fake_supervisor,
    )
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)

    assert engine_main.run_engine_entrypoint(["--nachuan-channel-supervisor"]) == 0
    assert calls == ["supervisor"]
    assert os.environ["NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST"] == str(profile)
    assert os.environ["NACHUAN_STORE_RUNTIME_PROFILE_SHA256"] == hashlib.sha256(
        profile.read_bytes()
    ).hexdigest()


def test_installed_supervisor_missing_profile_fails_with_fixed_receipt(
    monkeypatch, tmp_path, capsys
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    engine = (
        tmp_path / "installed" / "resources" / "engine" / "engine.exe"
    ).resolve()
    engine.parent.mkdir(parents=True)
    engine.write_bytes(b"test-only-engine")
    monkeypatch.setattr(sys, "executable", str(engine))
    calls: list[str] = []
    fake_supervisor = ModuleType("gateway.installed_channel_supervisor_entrypoint")
    fake_supervisor.run = lambda: calls.append("supervisor") or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.installed_channel_supervisor_entrypoint",
        fake_supervisor,
    )

    assert engine_main.run_engine_entrypoint(["--nachuan-channel-supervisor"]) == 69
    assert calls == []
    assert capsys.readouterr().err == "NACHUAN_CHANNEL_SUPERVISOR_FAILED\n"


def test_installed_channel_supervisor_verb_refuses_source_or_nonwindows(
    monkeypatch,
) -> None:
    calls: list[str] = []
    fake_supervisor = ModuleType("gateway.installed_channel_supervisor_entrypoint")
    fake_supervisor.run = lambda: calls.append("supervisor") or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.installed_channel_supervisor_entrypoint",
        fake_supervisor,
    )

    monkeypatch.delattr(sys, "frozen", raising=False)
    assert engine_main.run_engine_entrypoint(["--nachuan-channel-supervisor"]) == 77
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "posix")
    assert engine_main.run_engine_entrypoint(["--nachuan-channel-supervisor"]) == 77
    assert calls == []


def test_nachuan_core_service_verb_refuses_source_or_nonwindows(
    monkeypatch,
) -> None:
    calls: list[str] = []
    fake_host = ModuleType("gateway.windows_nachuan_core_service_host")
    fake_host.run = lambda: calls.append("service") or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.windows_nachuan_core_service_host",
        fake_host,
    )

    monkeypatch.delattr(sys, "frozen", raising=False)
    assert engine_main.run_engine_entrypoint(["--nachuan-core-service"]) == 77
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "posix")
    assert engine_main.run_engine_entrypoint(["--nachuan-core-service"]) == 77
    assert calls == []


def test_packaged_entrypoint_dispatches_only_the_nachuan_core_service(
    monkeypatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    calls: list[str] = []
    fake_host = ModuleType("gateway.windows_nachuan_core_service_host")
    fake_host.run = lambda: calls.append("service") or 23  # type: ignore[attr-defined]
    fake_supervisor = ModuleType("gateway.installed_channel_supervisor_entrypoint")
    fake_supervisor.run = lambda: calls.append("supervisor") or 0  # type: ignore[attr-defined]
    fake_gateway = ModuleType("gateway.app")
    fake_gateway.main = lambda: calls.append("gateway")  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.windows_nachuan_core_service_host",
        fake_host,
    )
    monkeypatch.setitem(
        sys.modules,
        "gateway.installed_channel_supervisor_entrypoint",
        fake_supervisor,
    )
    monkeypatch.setitem(sys.modules, "gateway.app", fake_gateway)

    assert engine_main.run_engine_entrypoint(["--nachuan-core-service"]) == 23
    assert calls == ["service"]


def test_service_verb_reaches_dispatcher_before_runtime_profile_import() -> None:
    script = r'''
import importlib.abc
import sys
from types import ModuleType

class RuntimeProfileBlocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "gateway.runtime_profile":
            raise RuntimeError("runtime profile imported before dispatcher")
        return None

sys.meta_path.insert(0, RuntimeProfileBlocker())
import engine_main
sys.frozen = True
engine_main.os.name = "nt"
fake = ModuleType("gateway.windows_nachuan_core_service_host")
fake.run = lambda: 0
sys.modules["gateway.windows_nachuan_core_service_host"] = fake
raise SystemExit(engine_main.run_engine_entrypoint(["--nachuan-core-service"]))
'''
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_nachuan_core_service_failure_is_fixed_and_nonsecret(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    fake_host = ModuleType("gateway.windows_nachuan_core_service_host")

    def fail() -> int:
        raise RuntimeError("SECRET C:/ProgramData/Nachuan token SID")

    fake_host.run = fail  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.windows_nachuan_core_service_host",
        fake_host,
    )

    assert engine_main.run_engine_entrypoint(["--nachuan-core-service"]) == 69
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "NACHUAN_CORE_SERVICE_FAILED\n"
    assert "SECRET" not in captured.err


def test_nachuan_core_service_verb_rejects_extra_arguments(monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(engine_main.os, "name", "nt")
    calls: list[str] = []
    fake_host = ModuleType("gateway.windows_nachuan_core_service_host")
    fake_host.run = lambda: calls.append("service") or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules,
        "gateway.windows_nachuan_core_service_host",
        fake_host,
    )

    assert engine_main.run_engine_entrypoint(
        ["--nachuan-core-service", "extra"]
    ) == 64
    assert calls == []


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
