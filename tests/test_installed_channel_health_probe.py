from __future__ import annotations

import hashlib
import hmac
import json

from gateway.installed_channel_health_probe import (
    InstalledChannelHealthProbe,
    InstalledChannelRuntimeHealthAdapter,
    InstalledRoleHealthProof,
)
from gateway.installed_channel_supervisor import InstalledChannelSupervisorState
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt


def _receipt(pid: int = 4321) -> InstalledChannelProcessReceipt:
    return InstalledChannelProcessReceipt(
        pid=pid,
        started_utc_ticks=133_000_000_000_000_001,
        command_line_sha256="a" * 64,
    )


def test_attested_engine_without_provider_allows_channels_but_is_not_ready(tmp_path) -> None:
    boot_token = "12" * 32
    challenge = "34" * 32
    proof = hmac.new(
        bytes.fromhex(boot_token), challenge.encode("ascii"), hashlib.sha256
    ).hexdigest()
    seen: list[tuple[str, float, int]] = []

    def fetch(url: str, timeout_seconds: float, maximum_bytes: int):
        seen.append((url, timeout_seconds, maximum_bytes))
        return {
            "status": "ok",
            "readiness": "ok",
            "pid": 4321,
            "boot_proof": proof,
            "checks": {
                "database": {"ready": True},
                "financial_ledger": {"required": True, "ready": True},
                "connection_store": {"ready": True},
                "providers": {"ready": False},
            },
        }

    probe = InstalledChannelHealthProbe(
        data_directory=tmp_path.resolve(),
        engine_port=18888,
        engine_boot_token=boot_token,
        challenge_factory=lambda: challenge,
        json_fetch=fetch,
    )

    result = probe.probe_engine(_receipt())

    assert result.role == "engine"
    assert result.pid == 4321
    assert result.attested is True
    assert result.start_allowed is True
    assert result.ready is False
    assert result.restart_recommended is False
    assert result.state == "provider_unavailable"
    assert seen == [
        (
            f"http://127.0.0.1:18888/health?challenge={challenge}",
            2.0,
            65536,
        )
    ]


def test_attested_engine_with_unready_database_cannot_start_channels(tmp_path) -> None:
    boot_token = "56" * 32
    challenge = "78" * 32
    proof = hmac.new(
        bytes.fromhex(boot_token), challenge.encode("ascii"), hashlib.sha256
    ).hexdigest()
    document = {
        "status": "ok",
        "readiness": "degraded",
        "pid": 4321,
        "boot_proof": proof,
        "checks": {
            "database": {"ready": False},
            "financial_ledger": {"required": True, "ready": True},
            "connection_store": {"ready": True},
            "providers": {"ready": True},
        },
    }
    probe = InstalledChannelHealthProbe(
        data_directory=tmp_path.resolve(),
        engine_port=18889,
        engine_boot_token=boot_token,
        challenge_factory=lambda: challenge,
        json_fetch=lambda _url, _timeout, _maximum: document,
    )

    result = probe.probe_engine(_receipt())

    assert result.attested is True
    assert result.start_allowed is False
    assert result.ready is False
    assert result.restart_recommended is True
    assert result.state == "database_unready"


def test_connected_channel_can_stay_started_while_provider_is_unavailable(tmp_path) -> None:
    now = 100.0
    (tmp_path / "weixin_bridge_health.json").write_text(
        json.dumps(
            {
                "schema": "nachuan.weixin-bridge-health.v1",
                "updated_at": 99.0,
                "fresh_until": 109.0,
                "freshness_ttl_seconds": 10.0,
                "pid": 4322,
                "state": "degraded",
                "ready": False,
                "fresh": True,
                "connected": True,
                "access_configured": True,
                "bridge_key_configured": True,
                "engine_available": False,
                "pending_inbound": 0,
                "pending_outbound": 0,
                "dead_inbound": 0,
                "dead_outbound": 0,
                "oldest_processing_age_seconds": 0.0,
                "consecutive_poll_failures": 0,
                "last_error_code": "",
                "engine_readiness_reason": "requested_model_unavailable",
                "readiness_reasons": ["requested_model_unavailable"],
            }
        ),
        encoding="utf-8",
    )
    probe = InstalledChannelHealthProbe(
        data_directory=tmp_path.resolve(),
        engine_port=18890,
        engine_boot_token="90" * 32,
        wall_clock=lambda: now,
    )
    engine = InstalledRoleHealthProof(
        role="engine",
        pid=4321,
        state="provider_unavailable",
        attested=True,
        start_allowed=True,
        ready=False,
        restart_recommended=False,
    )

    result = probe.probe_channel("weixin", _receipt(4322), engine)

    assert result.attested is True
    assert result.start_allowed is True
    assert result.ready is False
    assert result.restart_recommended is False
    assert result.state == "provider_unavailable"


def test_runtime_health_adapter_requires_engine_proof_before_channels(
    tmp_path, monkeypatch
) -> None:
    probe = InstalledChannelHealthProbe(
        data_directory=tmp_path.resolve(),
        engine_port=18891,
        engine_boot_token="ab" * 32,
    )
    processes = {
        "engine": object(),
        "weixin": object(),
        "feishu": object(),
    }
    receipts = {
        "engine": _receipt(5001),
        "weixin": _receipt(5002),
        "feishu": _receipt(5003),
    }

    class Manager:
        def process_receipt(self, role, process):
            assert process is processes[role]
            return receipts[role]

    engine = InstalledRoleHealthProof(
        role="engine",
        pid=5001,
        state="ready",
        attested=True,
        start_allowed=True,
        ready=True,
        restart_recommended=False,
    )
    seen: list[tuple[str, int, str]] = []
    monkeypatch.setattr(probe, "probe_engine", lambda receipt: engine)

    def probe_channel(role, receipt, engine_proof):
        seen.append((role, receipt.pid, engine_proof.state))
        return InstalledRoleHealthProof(
            role=role,
            pid=receipt.pid,
            state="ready",
            attested=True,
            start_allowed=True,
            ready=True,
            restart_recommended=False,
        )

    monkeypatch.setattr(probe, "probe_channel", probe_channel)
    adapter = InstalledChannelRuntimeHealthAdapter(probe=probe, process_manager=Manager())

    assert adapter("engine", processes["engine"]) == engine
    assert adapter("weixin", processes["weixin"]).ready is True
    assert adapter("feishu", processes["feishu"]).ready is True
    assert seen == [("weixin", 5002, "ready"), ("feishu", 5003, "ready")]


def test_runtime_health_adapter_polls_bounded_startup_until_attested(tmp_path, monkeypatch) -> None:
    probe = InstalledChannelHealthProbe(
        data_directory=tmp_path.resolve(),
        engine_port=18892,
        engine_boot_token="cd" * 32,
    )
    receipt = _receipt(6001)

    class Process:
        def poll(self):
            return None

    class Manager:
        def process_receipt(self, role, _process):
            assert role == "engine"
            return receipt

    results = iter(
        (
            InstalledRoleHealthProof(
                role="engine",
                pid=6001,
                state="unreachable",
                attested=False,
                start_allowed=False,
                ready=False,
                restart_recommended=True,
            ),
            InstalledRoleHealthProof(
                role="engine",
                pid=6001,
                state="ready",
                attested=True,
                start_allowed=True,
                ready=True,
                restart_recommended=False,
            ),
        )
    )
    monkeypatch.setattr(probe, "probe_engine", lambda _receipt: next(results))
    clock = [10.0]

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    adapter = InstalledChannelRuntimeHealthAdapter(
        probe=probe,
        process_manager=Manager(),
        monotonic_clock=lambda: clock[0],
        sleeper=sleep,
        startup_timeout_seconds=5.0,
        poll_interval_seconds=0.25,
    )

    result = adapter("engine", Process())

    assert result.ready is True
    assert clock[0] == 10.25


def test_runtime_health_adapter_refreshes_all_role_proofs(tmp_path, monkeypatch) -> None:
    probe = InstalledChannelHealthProbe(
        data_directory=tmp_path.resolve(),
        engine_port=18893,
        engine_boot_token="ef" * 32,
    )
    receipts = {
        "engine": _receipt(7001),
        "weixin": _receipt(7002),
        "feishu": _receipt(7003),
    }

    class Runtime:
        def process_receipts(self):
            return receipts

    class Manager:
        def process_receipt(self, _role, _process):
            raise AssertionError("startup path is not used")

    def proof(role: str, pid: int) -> InstalledRoleHealthProof:
        return InstalledRoleHealthProof(
            role=role,
            pid=pid,
            state="ready",
            attested=True,
            start_allowed=True,
            ready=True,
            restart_recommended=False,
        )

    monkeypatch.setattr(probe, "probe_engine", lambda receipt: proof("engine", receipt.pid))
    monkeypatch.setattr(
        probe,
        "probe_channel",
        lambda role, receipt, _engine: proof(role, receipt.pid),
    )
    adapter = InstalledChannelRuntimeHealthAdapter(probe=probe, process_manager=Manager())
    previous = InstalledChannelSupervisorState(
        pids={"engine": 7001, "weixin": 7002, "feishu": 7003},
        ready=False,
    )

    refreshed = adapter.check_runtime(Runtime(), previous)

    assert refreshed.ready is True
    assert refreshed.start_allowed is True
    assert tuple(refreshed.proofs) == ("engine", "weixin", "feishu")
