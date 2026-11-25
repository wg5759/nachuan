from __future__ import annotations

import hashlib
import threading

import pytest

from gateway.installed_channel_drain import (
    InstalledDrainBinding,
    InstalledDrainOperation,
    InstalledDrainRoleReceipt,
    InstalledDrainSummary,
)
from gateway.installed_channel_health_probe import InstalledRoleHealthProof
from gateway.installed_channel_supervisor import (
    InstalledChannelEpochAnchor,
    InstalledChannelSupervisorRuntime,
    InstalledChannelSupervisorContractError,
    build_installed_channel_launches,
    build_installed_channel_launches_from_config,
)
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt
from gateway.installed_channel_config import InstalledChannelSupervisorConfig
from gateway.installation_root import (
    InstallationRootSnapshot,
    UpdaterState,
    installation_principal,
)


def _valid_inputs(tmp_path):
    engine_dir = tmp_path / "installed" / "resources" / "engine"
    data_dir = tmp_path / "user-data" / "data"
    vault_dir = tmp_path / "local-data" / "Nachuan" / "data"
    engine_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    vault_dir.mkdir(parents=True)
    engine = engine_dir / "engine.exe"
    engine.write_bytes(b"test-only-frozen-engine")
    vault = vault_dir / "connections.json"
    vault.write_text("{}", encoding="utf-8")
    verification_key = vault_dir / "connections.json.verification-key"
    verification_key.write_text("test-only", encoding="utf-8")
    profile = tmp_path / "store-runtime-profile.v1.json"
    profile.write_text('{"schema":"nachuan.runtime-profile/v1"}', encoding="utf-8")
    profile_digest = hashlib.sha256(profile.read_bytes()).hexdigest()
    return {
        "engine_executable": engine,
        "data_directory": data_dir,
        "connections_path": vault,
        "engine_port": 43123,
        "engine_generation": 19,
        "engine_boot_token": "a" * 64,
        "runtime_key": "sk-local-" + "1" * 64,
        "approval_key": "sk-approval-" + "2" * 64,
        "paid_media_key": "sk-paid-media-" + "3" * 64,
        "weixin_bridge_key": "sk-bridge-v2-weixin-" + "4" * 64,
        "feishu_bridge_key": "sk-bridge-v2-feishu-" + "5" * 64,
        "feishu_app_id": "cli_test_app_id",
        "feishu_app_secret": "test-feishu-secret-value",
        "runtime_profile_manifest": profile,
        "runtime_profile_sha256": profile_digest,
        "source_environment": {},
        "_verification_key": verification_key,
    }


def _installation_snapshot(*, epoch: int = 4) -> InstallationRootSnapshot:
    installation_id = "a" * 64
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest="b" * 64,
        epoch=epoch,
        root_revision=9,
        status="active",
        lock_kind="none",
        lock_reason_digest=None,
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=installation_principal(installation_id, epoch),
        components=(),
        updater=UpdaterState(
            release_sequence=1,
            keyring_sequence=1,
            artifact_digest="c" * 64,
            state_digest="d" * 64,
        ),
    )


def test_installed_launches_use_one_engine_and_role_scoped_environments(tmp_path) -> None:
    engine_dir = tmp_path / "installed" / "resources" / "engine"
    data_dir = tmp_path / "user-data" / "data"
    vault_dir = tmp_path / "local-data" / "Nachuan" / "data"
    engine_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    vault_dir.mkdir(parents=True)
    engine = engine_dir / "engine.exe"
    engine.write_bytes(b"test-only-frozen-engine")
    vault = vault_dir / "connections.json"
    vault.write_text("{}", encoding="utf-8")
    (vault_dir / "connections.json.verification-key").write_text(
        "test-only", encoding="utf-8"
    )
    profile = tmp_path / "store-runtime-profile.v1.json"
    profile.write_text('{"schema":"nachuan.runtime-profile/v1"}', encoding="utf-8")
    profile_digest = hashlib.sha256(profile.read_bytes()).hexdigest()

    launches = build_installed_channel_launches(
        engine_executable=engine,
        data_directory=data_dir,
        connections_path=vault,
        engine_port=43123,
        engine_generation=19,
        engine_boot_token="a" * 64,
        runtime_key="sk-local-" + "1" * 64,
        approval_key="sk-approval-" + "2" * 64,
        paid_media_key="sk-paid-media-" + "3" * 64,
        weixin_bridge_key="sk-bridge-v2-weixin-" + "4" * 64,
        feishu_bridge_key="sk-bridge-v2-feishu-" + "5" * 64,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="test-feishu-secret-value",
        runtime_profile_manifest=profile,
        runtime_profile_sha256=profile_digest,
        source_environment={
            "SYSTEMROOT": r"C:\Windows",
            "WINDIR": r"C:\Windows",
            "COMSPEC": r"C:\Windows\System32\cmd.exe",
            "LOCALAPPDATA": str(tmp_path / "local-data"),
            "APPDATA": str(tmp_path / "user-data"),
            "HTTP_PROXY": "http://attacker.invalid:8080",
            "PATH": r"C:\attacker",
            "GATEWAY_API_KEYS": "attacker-runtime-key",
            "FEISHU_APP_SECRET": "attacker-feishu-secret",
        },
    )

    assert tuple(launches) == ("engine", "weixin", "feishu")
    assert {launch.command for launch in launches.values()} == {str(engine.resolve())}
    assert launches["engine"].args == ()
    assert launches["weixin"].args == ("--nachuan-weixin-bridge",)
    assert launches["feishu"].args == ("--nachuan-feishu-bridge",)
    assert {launch.cwd for launch in launches.values()} == {str(engine_dir.resolve())}

    engine_env = launches["engine"].environment
    weixin_env = launches["weixin"].environment
    feishu_env = launches["feishu"].environment
    assert engine_env["GATEWAY_API_KEYS"] == "sk-local-" + "1" * 64
    assert engine_env["APPROVAL_ADMIN_KEY"] == "sk-approval-" + "2" * 64
    assert engine_env["NACHUAN_PAID_MEDIA_API_KEY"] == "sk-paid-media-" + "3" * 64
    assert engine_env["NACHUAN_CONNECTIONS_PATH"] == str(vault.resolve())
    assert engine_env["NACHUAN_WEIXIN_BRIDGE_API_KEY"] == "sk-bridge-v2-weixin-" + "4" * 64
    assert engine_env["NACHUAN_FEISHU_BRIDGE_API_KEY"] == "sk-bridge-v2-feishu-" + "5" * 64
    assert "FEISHU_APP_SECRET" not in engine_env

    assert weixin_env["NACHUAN_WEIXIN_BRIDGE_API_KEY"] == "sk-bridge-v2-weixin-" + "4" * 64
    assert "NACHUAN_FEISHU_BRIDGE_API_KEY" not in weixin_env
    assert "GATEWAY_API_KEYS" not in weixin_env
    assert "APPROVAL_ADMIN_KEY" not in weixin_env
    assert "NACHUAN_CONNECTIONS_PATH" not in weixin_env
    assert "FEISHU_APP_SECRET" not in weixin_env

    assert feishu_env["NACHUAN_FEISHU_BRIDGE_API_KEY"] == "sk-bridge-v2-feishu-" + "5" * 64
    assert feishu_env["FEISHU_APP_ID"] == "cli_test_app_id"
    assert feishu_env["FEISHU_APP_SECRET"] == "test-feishu-secret-value"
    assert "NACHUAN_WEIXIN_BRIDGE_API_KEY" not in feishu_env
    assert "GATEWAY_API_KEYS" not in feishu_env
    assert "APPROVAL_ADMIN_KEY" not in feishu_env
    assert "NACHUAN_CONNECTIONS_PATH" not in feishu_env

    for launch in launches.values():
        assert "HTTP_PROXY" not in launch.environment
        assert "HTTPS_PROXY" not in launch.environment
        assert "ALL_PROXY" not in launch.environment
        assert "PATH" not in launch.environment
        assert launch.environment["NACHUAN_RUNTIME_PROFILE"] == "store"
        assert launch.environment["NACHUAN_STORE_RUNTIME_PROFILE_MANIFEST"] == str(
            profile.resolve()
        )
        assert launch.environment["NACHUAN_STORE_RUNTIME_PROFILE_SHA256"] == profile_digest
        assert launch.environment["BRIDGE_ENGINE_URL"] == "http://127.0.0.1:43123"
    assert "test-feishu-secret-value" not in repr(launches)


def test_installed_launches_require_the_connection_verification_key(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    verification_key = inputs.pop("_verification_key")
    verification_key.unlink()

    with pytest.raises(
        InstalledChannelSupervisorContractError,
        match="connection verification key is unavailable",
    ):
        build_installed_channel_launches(**inputs)


def test_installed_launches_reject_profile_drift_without_leaking_secrets(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    inputs["runtime_profile_sha256"] = "0" * 64

    with pytest.raises(
        InstalledChannelSupervisorContractError,
        match="runtime profile digest mismatch",
    ) as failure:
        build_installed_channel_launches(**inputs)

    assert "test-feishu-secret-value" not in str(failure.value)


def test_installation_epoch_anchor_rejects_a_rolled_back_configuration(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    config = InstalledChannelSupervisorConfig(
        generation=1,
        engine_port=inputs["engine_port"],
        runtime_key=inputs["runtime_key"],
        approval_key=inputs["approval_key"],
        paid_media_key=inputs["paid_media_key"],
        weixin_bridge_key=inputs["weixin_bridge_key"],
        feishu_bridge_key=inputs["feishu_bridge_key"],
        feishu_app_id=inputs["feishu_app_id"],
        feishu_app_secret=inputs["feishu_app_secret"],
    )
    snapshot = _installation_snapshot()
    current_anchor = InstalledChannelEpochAnchor.from_snapshot(
        snapshot, config_generation=1
    )
    launches = build_installed_channel_launches_from_config(
        config=config,
        installation_snapshot=snapshot,
        epoch_anchor=current_anchor,
        engine_executable=inputs["engine_executable"],
        data_directory=inputs["data_directory"],
        connections_path=inputs["connections_path"],
        engine_boot_token=inputs["engine_boot_token"],
        runtime_profile_manifest=inputs["runtime_profile_manifest"],
        runtime_profile_sha256=inputs["runtime_profile_sha256"],
    )
    assert launches["engine"].environment["NACHUAN_ENGINE_GENERATION"] == "1"

    rolled_back = InstalledChannelEpochAnchor.from_snapshot(
        snapshot, config_generation=2
    )
    with pytest.raises(
        InstalledChannelSupervisorContractError,
        match="configuration generation differs from installation anchor",
    ):
        build_installed_channel_launches_from_config(
            config=config,
            installation_snapshot=snapshot,
            epoch_anchor=rolled_back,
            engine_executable=inputs["engine_executable"],
            data_directory=inputs["data_directory"],
            connections_path=inputs["connections_path"],
            engine_boot_token=inputs["engine_boot_token"],
            runtime_profile_manifest=inputs["runtime_profile_manifest"],
            runtime_profile_sha256=inputs["runtime_profile_sha256"],
        )


def test_runtime_assigns_suspended_children_to_one_job_before_resume(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)

    class Process:
        def __init__(self, pid):
            self.pid = pid

    class Manager:
        def __init__(self):
            self.operations = []
            self.next_pid = 100

        def spawn_suspended(self, role, launch):
            self.next_pid += 1
            process = Process(self.next_pid)
            self.operations.append(("spawn_suspended", role, launch.args))
            return process

        def assign_to_job(self, role, process):
            self.operations.append(("assign_to_job", role, process.pid))

        def resume(self, role, process):
            self.operations.append(("resume", role, process.pid))

        def terminate_job(self):
            self.operations.append(("terminate_job",))

    manager = Manager()
    probed = []

    def health(role, process):
        probed.append((role, process.pid))
        return True

    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=health,
    )
    state = runtime.start()

    assert tuple(state.pids) == ("engine", "weixin", "feishu")
    assert list(state.pids.values()) == [101, 102, 103]
    assert manager.operations == [
        ("spawn_suspended", "engine", ()),
        ("assign_to_job", "engine", 101),
        ("resume", "engine", 101),
        ("spawn_suspended", "weixin", ("--nachuan-weixin-bridge",)),
        ("assign_to_job", "weixin", 102),
        ("resume", "weixin", 102),
        ("spawn_suspended", "feishu", ("--nachuan-feishu-bridge",)),
        ("assign_to_job", "feishu", 103),
        ("resume", "feishu", 103),
    ]
    assert probed == [("engine", 101), ("weixin", 102), ("feishu", 103)]
    runtime.close()
    assert manager.operations[-1] == ("terminate_job",)


def test_runtime_never_starts_channels_when_engine_attestation_fails(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)

    class Process:
        pid = 101

    class Manager:
        def __init__(self):
            self.operations = []

        def spawn_suspended(self, role, _launch):
            self.operations.append(("spawn_suspended", role))
            return Process()

        def assign_to_job(self, role, _process):
            self.operations.append(("assign_to_job", role))

        def resume(self, role, _process):
            self.operations.append(("resume", role))

        def terminate_job(self):
            self.operations.append(("terminate_job",))

    manager = Manager()
    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=lambda _role, _process: False,
    )

    with pytest.raises(
        InstalledChannelSupervisorContractError,
        match="installed engine startup failed",
    ):
        runtime.start()

    assert manager.operations == [
        ("spawn_suspended", "engine"),
        ("assign_to_job", "engine"),
        ("resume", "engine"),
        ("terminate_job",),
    ]


def test_external_stop_after_engine_resume_prevents_channel_spawn(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)
    stop_event = threading.Event()

    class Process:
        pid = 101

    class Manager:
        def __init__(self) -> None:
            self.operations = []

        def spawn_suspended(self, role, _launch):
            self.operations.append(("spawn_suspended", role))
            return Process()

        def assign_to_job(self, role, _process) -> None:
            self.operations.append(("assign_to_job", role))

        def resume(self, role, _process) -> None:
            self.operations.append(("resume", role))
            if role == "engine":
                stop_event.set()

        def terminate_job(self) -> None:
            self.operations.append(("terminate_job",))

    manager = Manager()
    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=lambda _role, _process: (_ for _ in ()).throw(
            AssertionError("Stop after resume must skip health and channels")
        ),
    )

    with pytest.raises(
        InstalledChannelSupervisorContractError,
        match="installed engine startup failed",
    ):
        runtime.start(stop_event=stop_event)

    assert manager.operations == [
        ("spawn_suspended", "engine"),
        ("assign_to_job", "engine"),
        ("resume", "engine"),
        ("terminate_job",),
    ]


@pytest.mark.parametrize(
    ("stop_after", "expected_operations"),
    (
        (
            "spawn_suspended",
            [
                ("spawn_suspended", "engine"),
                ("terminate_job",),
            ],
        ),
        (
            "assign_to_job",
            [
                ("spawn_suspended", "engine"),
                ("assign_to_job", "engine"),
                ("terminate_job",),
            ],
        ),
    ),
)
def test_external_stop_prevents_suspended_child_from_reaching_resume(
    tmp_path,
    stop_after,
    expected_operations,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)
    stop_event = threading.Event()

    class Process:
        pid = 101

    class Manager:
        def __init__(self) -> None:
            self.operations = []

        def spawn_suspended(self, role, _launch):
            self.operations.append(("spawn_suspended", role))
            if stop_after == "spawn_suspended":
                stop_event.set()
            return Process()

        def assign_to_job(self, role, _process) -> None:
            self.operations.append(("assign_to_job", role))
            if stop_after == "assign_to_job":
                stop_event.set()

        def resume(self, role, _process) -> None:
            self.operations.append(("resume", role))

        def terminate_job(self) -> None:
            self.operations.append(("terminate_job",))

    manager = Manager()
    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=lambda _role, _process: True,
    )

    with pytest.raises(InstalledChannelSupervisorContractError):
        runtime.start(stop_event=stop_event)
    assert manager.operations == expected_operations


def test_runtime_delegates_force_and_quiescence_to_process_manager(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    class Manager:
        def __init__(self) -> None:
            self.next_pid = 600
            self.quiescent = False
            self.forces = 0

        def spawn_suspended(self, _role, _launch):
            self.next_pid += 1
            return Process(self.next_pid)

        def assign_to_job(self, _role, _process) -> None:
            return None

        def resume(self, _role, _process) -> None:
            return None

        def terminate_job(self) -> None:
            self.force_close()

        def force_close(self) -> None:
            self.forces += 1
            self.quiescent = True

        def is_quiescent(self) -> bool:
            return self.quiescent

    manager = Manager()
    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=lambda _role, _process: True,
    )
    runtime.start()

    assert runtime.is_quiescent() is False
    assert runtime.force_close() is None
    assert runtime.is_quiescent() is True
    assert manager.forces == 1


def test_runtime_keeps_channels_started_but_reports_not_ready_without_provider(
    tmp_path,
) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)

    class Process:
        def __init__(self, pid):
            self.pid = pid

    class Manager:
        def __init__(self):
            self.next_pid = 200
            self.terminated = 0

        def spawn_suspended(self, _role, _launch):
            self.next_pid += 1
            return Process(self.next_pid)

        def assign_to_job(self, _role, _process):
            return None

        def resume(self, _role, _process):
            return None

        def terminate_job(self):
            self.terminated += 1

    def health(role, process):
        return InstalledRoleHealthProof(
            role=role,
            pid=process.pid,
            state="provider_unavailable",
            attested=True,
            start_allowed=True,
            ready=False,
            restart_recommended=False,
        )

    manager = Manager()
    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=health,
    )

    state = runtime.start()

    assert tuple(state.pids) == ("engine", "weixin", "feishu")
    assert state.ready is False
    assert tuple(state.proofs) == ("engine", "weixin", "feishu")
    assert all(proof.start_allowed and not proof.ready for proof in state.proofs.values())
    runtime.close()
    assert manager.terminated == 1


def test_runtime_uses_reviewed_drain_factory_before_natural_job_close(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    class Manager:
        def __init__(self) -> None:
            self.operations: list[object] = []
            self.processes: dict[str, Process] = {}

        def spawn_suspended(self, role, _launch):
            process = Process(8000 + len(self.processes))
            self.processes[role] = process
            return process

        def assign_to_job(self, _role, _process):
            return None

        def resume(self, _role, _process):
            return None

        def process_receipt(self, role, process):
            offset = {"engine": 1, "weixin": 2, "feishu": 3}[role]
            return InstalledChannelProcessReceipt(
                pid=process.pid,
                started_utc_ticks=100 + offset,
                command_line_sha256=str(offset) * 64,
            )

        def wait_for_quiescence(self, *, timeout_ms):
            self.operations.append(("wait_for_quiescence", timeout_ms))
            return True

        def close_quiescent(self):
            self.operations.append(("close_quiescent",))

        def terminate_job(self):
            self.operations.append(("terminate_job",))

        def force_close(self):
            self.operations.append(("force_close",))

        def is_quiescent(self):
            return bool(self.operations and self.operations[-1] == ("close_quiescent",))

    manager = Manager()
    observed: list[object] = []

    class Drain:
        def __init__(self, receipts):
            self.receipts = receipts
            self.operation = InstalledDrainOperation(
                binding=InstalledDrainBinding(
                    installation_id="a" * 64,
                    installation_epoch=1,
                    config_generation=1,
                    service_boot_id="b" * 64,
                ),
                stop_id="c" * 64,
                stop_generation=1,
                deadline_utc_ns=9_000_000_000_000_000_000,
            )

        def drain(self, *, timeout_ms):
            observed.append(("drain", timeout_ms))
            operation = self.operation
            role_receipts = {}
            for role, process in self.receipts.items():
                role_receipts[role] = InstalledDrainRoleReceipt(
                    operation=operation,
                    role=role,
                    process=process,
                    phase="exit_requested",
                    claim_gate_closed=role != "engine",
                    admission_closed=role == "engine",
                    active_claims=0,
                    active_requests=0,
                    active_background_jobs=0,
                    provider_open_calls=0,
                    unknown_unpersisted=0,
                    submitted_unknown=0,
                )
            return InstalledDrainSummary(
                operation=operation,
                business_drained=True,
                exit_acknowledged=True,
                submitted_unknown=0,
                action_sequence=(
                    "weixin:close_claims",
                    "feishu:close_claims",
                    "engine:close_admission",
                    "weixin:exit",
                    "feishu:exit",
                    "engine:exit",
                ),
                role_receipts=role_receipts,
            )

    def drain_factory(receipts):
        observed.append(("receipts", tuple(receipts), tuple(r.pid for r in receipts.values())))
        return Drain(receipts)

    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=lambda _role, _process: True,
        drain_controller_factory=drain_factory,
    )
    runtime.start()

    runtime.close()

    assert observed == [
        ("receipts", ("engine", "weixin", "feishu"), (8000, 8001, 8002)),
        ("drain", 24_000),
    ]
    assert manager.operations == [
        ("wait_for_quiescence", 4_000),
        ("close_quiescent",),
    ]
    assert runtime.is_quiescent() is True


def test_runtime_invalid_drain_receipt_keeps_force_close_available(tmp_path) -> None:
    inputs = _valid_inputs(tmp_path)
    inputs.pop("_verification_key")
    launches = build_installed_channel_launches(**inputs)

    class Process:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    class Manager:
        def __init__(self) -> None:
            self.forces = 0
            self.quiescent = False

        def spawn_suspended(self, role, _launch):
            return Process({"engine": 9001, "weixin": 9002, "feishu": 9003}[role])

        def assign_to_job(self, _role, _process):
            return None

        def resume(self, _role, _process):
            return None

        def process_receipt(self, role, process):
            offset = {"engine": 1, "weixin": 2, "feishu": 3}[role]
            return InstalledChannelProcessReceipt(
                pid=process.pid,
                started_utc_ticks=200 + offset,
                command_line_sha256=str(offset) * 64,
            )

        def wait_for_quiescence(self, *, timeout_ms):
            return False

        def close_quiescent(self):
            raise AssertionError("unsafe close")

        def terminate_job(self):
            raise AssertionError("grace path must not force")

        def force_close(self):
            self.forces += 1
            self.quiescent = True

        def is_quiescent(self):
            return self.quiescent

    class Drain:
        operation = InstalledDrainOperation(
            binding=InstalledDrainBinding(
                installation_id="a" * 64,
                installation_epoch=1,
                config_generation=1,
                service_boot_id="b" * 64,
            ),
            stop_id="c" * 64,
            stop_generation=1,
            deadline_utc_ns=9_000_000_000_000_000_000,
        )

        def drain(self, *, timeout_ms):
            return None

    manager = Manager()
    runtime = InstalledChannelSupervisorRuntime(
        launches=launches,
        process_manager=manager,
        health_probe=lambda _role, _process: True,
        drain_controller_factory=lambda _receipts: Drain(),
    )
    runtime.start()

    with pytest.raises(
        InstalledChannelSupervisorContractError,
        match="installed process tree graceful close failed",
    ):
        runtime.close()
    assert runtime.is_quiescent() is False

    assert runtime.force_close() is None
    assert manager.forces == 1
    assert runtime.is_quiescent() is True
