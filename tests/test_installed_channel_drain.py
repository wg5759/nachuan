from __future__ import annotations

from dataclasses import replace
import json
import threading

import pytest

from gateway.installed_channel_drain import (
    InstalledChannelDrainContractError,
    InstalledChannelDrainTimeout,
    InstalledChildDrainFence,
    InstalledDrainBinding,
    InstalledDrainCommand,
    InstalledDrainOperation,
    InstalledDrainProtocol,
    InstalledDrainRoleReceipt,
    InstalledDrainUnknownPersistenceReceipt,
    InstalledParentDrainCoordinator,
    derive_installed_drain_role_key,
)
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt


def _binding() -> InstalledDrainBinding:
    return InstalledDrainBinding(
        installation_id="a" * 64,
        installation_epoch=7,
        config_generation=11,
        service_boot_id="b" * 64,
    )


def _operation() -> InstalledDrainOperation:
    return InstalledDrainOperation(
        binding=_binding(),
        stop_id="c" * 64,
        stop_generation=3,
        deadline_utc_ns=1_900_000_000_000_000_000,
    )


def _process(role: str) -> InstalledChannelProcessReceipt:
    offset = {"engine": 1, "weixin": 2, "feishu": 3}[role]
    return InstalledChannelProcessReceipt(
        pid=4100 + offset,
        started_utc_ticks=133_000_000_000_000_000 + offset,
        command_line_sha256=(str(offset) * 64),
    )


def _receipt(
    role: str,
    *,
    phase: str,
    operation: InstalledDrainOperation | None = None,
    process: InstalledChannelProcessReceipt | None = None,
    active_claims: int = 0,
    active_requests: int = 0,
    active_background_jobs: int = 0,
    provider_open_calls: int = 0,
    unknown_unpersisted: int = 0,
    submitted_unknown: int = 0,
) -> InstalledDrainRoleReceipt:
    return InstalledDrainRoleReceipt(
        operation=operation or _operation(),
        role=role,
        process=process or _process(role),
        phase=phase,
        claim_gate_closed=role != "engine" and phase in {"claims_closed", "drained"},
        admission_closed=role == "engine" and phase in {"admission_closed", "drained"},
        active_claims=active_claims,
        active_requests=active_requests,
        active_background_jobs=active_background_jobs,
        provider_open_calls=provider_open_calls,
        unknown_unpersisted=unknown_unpersisted,
        submitted_unknown=submitted_unknown,
    )


def test_authenticated_drain_frame_rejects_tamper_and_replay() -> None:
    operation = _operation()
    process = _process("weixin")
    role_key = derive_installed_drain_role_key(
        control_key=b"k" * 32,
        binding=operation.binding,
        role="weixin",
        process=process,
    )
    parent = InstalledDrainProtocol(
        role_key=role_key,
        binding=operation.binding,
        role="weixin",
        process=process,
    )
    child = InstalledDrainProtocol(
        role_key=role_key,
        binding=operation.binding,
        role="weixin",
        process=process,
    )
    command = InstalledDrainCommand(operation=operation, action="close_claims")

    encoded = parent.encode_command(command)
    assert child.decode_command(encoded) == command
    with pytest.raises(InstalledChannelDrainContractError, match="sequence"):
        child.decode_command(encoded)

    tampered = bytearray(parent.encode_command(command))
    tampered[-8] ^= 1
    with pytest.raises(InstalledChannelDrainContractError, match="authentication"):
        InstalledDrainProtocol(
            role_key=role_key,
            binding=operation.binding,
            role="weixin",
            process=process,
        ).decode_command(bytes(tampered))

    noncanonical = json.dumps(
        json.loads(parent.encode_command(command).decode("ascii")),
        sort_keys=True,
        indent=2,
    ).encode("ascii")
    with pytest.raises(InstalledChannelDrainContractError, match="authentication"):
        InstalledDrainProtocol(
            role_key=role_key,
            binding=operation.binding,
            role="weixin",
            process=process,
        ).decode_command(noncanonical)


def test_role_keys_are_derived_per_role_and_process_identity() -> None:
    binding = _binding()
    root = b"r" * 32
    weixin = derive_installed_drain_role_key(
        control_key=root,
        binding=binding,
        role="weixin",
        process=_process("weixin"),
    )
    feishu = derive_installed_drain_role_key(
        control_key=root,
        binding=binding,
        role="feishu",
        process=_process("feishu"),
    )
    moved_process = replace(_process("weixin"), pid=9998)
    moved = derive_installed_drain_role_key(
        control_key=root,
        binding=binding,
        role="weixin",
        process=moved_process,
    )

    assert len(weixin) == 32
    assert len({weixin, feishu, moved}) == 3
    with pytest.raises(InstalledChannelDrainContractError, match="key"):
        derive_installed_drain_role_key(
            control_key=b"\0" * 32,
            binding=binding,
            role="weixin",
            process=_process("weixin"),
        )


def test_authenticated_role_receipt_round_trips_without_free_form_payload() -> None:
    operation = _operation()
    process = _process("feishu")
    role_key = derive_installed_drain_role_key(
        control_key=b"z" * 32,
        binding=operation.binding,
        role="feishu",
        process=process,
    )
    parent = InstalledDrainProtocol(
        role_key=role_key,
        binding=operation.binding,
        role="feishu",
        process=process,
    )
    child = InstalledDrainProtocol(
        role_key=role_key,
        binding=operation.binding,
        role="feishu",
        process=process,
    )
    receipt = _receipt(
        "feishu",
        phase="drained",
        operation=operation,
        process=process,
        submitted_unknown=2,
    )

    assert parent.decode_receipt(child.encode_receipt(receipt)) == receipt


def test_child_claim_fence_rechecks_generation_before_commit() -> None:
    operation = _operation()
    fence = InstalledChildDrainFence(
        binding=operation.binding,
        role="weixin",
        process=_process("weixin"),
    )
    permit = fence.try_begin_claim()
    assert permit is not None

    receipt = fence.apply_command(
        InstalledDrainCommand(operation=operation, action="close_claims")
    )

    assert receipt.phase == "drained"
    assert receipt.claim_gate_closed is True
    assert fence.commit_claim(permit) is False
    assert fence.try_begin_claim() is None


def test_claim_drain_race_never_commits_after_gate_ack() -> None:
    for round_index in range(20):
        operation = replace(_operation(), stop_generation=round_index + 1)
        fence = InstalledChildDrainFence(
            binding=operation.binding,
            role="weixin",
            process=_process("weixin"),
        )
        barrier = threading.Barrier(33)
        ack = threading.Event()
        results: list[tuple[object, bool, bool]] = []
        result_lock = threading.Lock()

        def worker() -> None:
            permit = fence.try_begin_claim()
            assert permit is not None
            barrier.wait()
            ack_before_commit = ack.is_set()
            committed = fence.commit_claim(permit)
            with result_lock:
                results.append((permit, committed, ack_before_commit))

        workers = [threading.Thread(target=worker) for _ in range(32)]
        for worker_thread in workers:
            worker_thread.start()
        barrier.wait()
        fence.apply_command(
            InstalledDrainCommand(operation=operation, action="close_claims")
        )
        ack.set()
        for worker_thread in workers:
            worker_thread.join(5)
            assert not worker_thread.is_alive()

        assert not any(committed and ack_before for _, committed, ack_before in results)
        assert fence.try_begin_claim() is None
        for permit, committed, _ack_before in results:
            if committed:
                fence.finish_claim(permit)
        assert fence.snapshot(operation=operation).phase == "drained"


def test_child_fence_drains_only_after_committed_claim_and_unknown_are_closed() -> None:
    operation = _operation()
    fence = InstalledChildDrainFence(
        binding=operation.binding,
        role="feishu",
        process=_process("feishu"),
    )
    permit = fence.try_begin_claim()
    assert permit is not None and fence.commit_claim(permit)
    provider = fence.try_enter_provider(permit)
    assert provider is not None

    receipt = fence.apply_command(
        InstalledDrainCommand(operation=operation, action="close_claims")
    )
    assert receipt.phase == "claims_closed"
    assert receipt.active_claims == 1
    assert receipt.provider_open_calls == 1

    fence.mark_provider_unknown(provider)
    receipt = fence.snapshot(operation=operation)
    assert receipt.unknown_unpersisted == 1

    fence.persist_provider_unknown(
        provider,
        InstalledDrainUnknownPersistenceReceipt(
            operation=operation,
            role="feishu",
            process=_process("feishu"),
            provider_permit_id=provider.permit_id,
            work_permit_id=permit.permit_id,
            ledger_generation=9,
            record_sha256="e" * 64,
            outcome="submitted_unknown",
            retry_safe=False,
        ),
    )
    fence.finish_claim(permit)
    receipt = fence.snapshot(operation=operation)
    assert receipt.phase == "drained"
    assert receipt.submitted_unknown == 1


def test_committed_claim_cannot_enter_provider_after_claim_gate_ack() -> None:
    operation = _operation()
    fence = InstalledChildDrainFence(
        binding=operation.binding,
        role="weixin",
        process=_process("weixin"),
    )
    permit = fence.try_begin_claim()
    assert permit is not None and fence.commit_claim(permit)

    receipt = fence.apply_command(
        InstalledDrainCommand(operation=operation, action="close_claims")
    )

    assert receipt.phase == "claims_closed"
    assert fence.try_enter_provider(permit) is None
    fence.finish_claim(permit)
    assert fence.snapshot(operation=operation).phase == "drained"


def test_gateway_admission_stays_open_until_its_own_command() -> None:
    operation = _operation()
    fence = InstalledChildDrainFence(
        binding=operation.binding,
        role="engine",
        process=_process("engine"),
    )
    permit = fence.try_begin_admission()
    assert permit is not None and fence.commit_admission(permit)
    assert fence.try_begin_admission() is not None

    receipt = fence.apply_command(
        InstalledDrainCommand(operation=operation, action="close_admission")
    )
    assert receipt.phase == "admission_closed"
    assert receipt.active_requests == 1
    assert fence.try_begin_admission() is None

    fence.finish_admission(permit)
    assert fence.snapshot(operation=operation).phase == "drained"


def test_gateway_background_jobs_are_counted_by_the_fence() -> None:
    operation = _operation()
    fence = InstalledChildDrainFence(
        binding=operation.binding,
        role="engine",
        process=_process("engine"),
    )
    background = fence.try_begin_background()
    assert background is not None and fence.commit_background(background)

    receipt = fence.apply_command(
        InstalledDrainCommand(operation=operation, action="close_admission")
    )
    assert receipt.phase == "admission_closed"
    assert receipt.active_background_jobs == 1
    assert fence.try_begin_background() is None

    fence.finish_background(background)
    assert fence.snapshot(operation=operation).phase == "drained"


class _ScriptedEndpoint:
    def __init__(self, receipts: list[InstalledDrainRoleReceipt], log: list[str]) -> None:
        self._receipts = list(receipts)
        self._last = receipts[-1]
        self.log = log

    def request(self, command: InstalledDrainCommand) -> None:
        self.log.append(f"request:{command.action}:{self._last.role}")
        if command.action == "exit":
            self._receipts.clear()
            self._last = replace(self._last, phase="exit_requested")

    def snapshot(self, operation: InstalledDrainOperation) -> InstalledDrainRoleReceipt:
        self.log.append(f"snapshot:{self._last.role}")
        if self._receipts:
            self._last = self._receipts.pop(0)
        return self._last


def test_parent_drain_orders_channels_before_gateway_and_gateway_exits_last() -> None:
    log: list[str] = []
    endpoints = {
        "engine": _ScriptedEndpoint([_receipt("engine", phase="drained")], log),
        "weixin": _ScriptedEndpoint(
            [
                _receipt(
                    "weixin",
                    phase="claims_closed",
                    provider_open_calls=1,
                    unknown_unpersisted=1,
                ),
                _receipt("weixin", phase="drained", submitted_unknown=1),
            ],
            log,
        ),
        "feishu": _ScriptedEndpoint([_receipt("feishu", phase="drained")], log),
    }
    now = [10.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    coordinator = InstalledParentDrainCoordinator(
        operation=_operation(),
        processes={role: _process(role) for role in ("engine", "weixin", "feishu")},
        endpoints=endpoints,
        monotonic_clock=lambda: now[0],
        sleeper=sleep,
    )

    result = coordinator.drain(timeout_ms=1_000)

    requests = [entry for entry in log if entry.startswith("request:")]
    assert requests == [
        "request:close_claims:weixin",
        "request:close_claims:feishu",
        "request:close_admission:engine",
        "request:exit:weixin",
        "request:exit:feishu",
        "request:exit:engine",
    ]
    assert result.business_drained is True
    assert result.exit_acknowledged is True
    assert result.submitted_unknown == 1


def test_concurrent_duplicate_parent_drain_sends_one_command_sequence() -> None:
    log: list[str] = []
    endpoints = {
        role: _ScriptedEndpoint([_receipt(role, phase="drained")], log)
        for role in ("engine", "weixin", "feishu")
    }
    coordinator = InstalledParentDrainCoordinator(
        operation=_operation(),
        processes={role: _process(role) for role in ("engine", "weixin", "feishu")},
        endpoints=endpoints,
    )
    barrier = threading.Barrier(17)
    results = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait()
            results.append(coordinator.drain(timeout_ms=1_000))
        except BaseException as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    workers = [threading.Thread(target=worker) for _ in range(16)]
    for worker_thread in workers:
        worker_thread.start()
    barrier.wait()
    for worker_thread in workers:
        worker_thread.join(5)
        assert not worker_thread.is_alive()

    assert errors == []
    assert len(results) == 16
    assert all(result is results[0] for result in results)
    assert len([entry for entry in log if entry.startswith("request:")]) == 6


def test_parent_drain_does_not_close_gateway_before_channel_receipt_is_safe() -> None:
    log: list[str] = []
    unsafe = _receipt("weixin", phase="claims_closed", unknown_unpersisted=1)
    endpoints = {
        "engine": _ScriptedEndpoint([_receipt("engine", phase="drained")], log),
        "weixin": _ScriptedEndpoint([unsafe], log),
        "feishu": _ScriptedEndpoint([_receipt("feishu", phase="drained")], log),
    }
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += max(0.2, seconds)

    coordinator = InstalledParentDrainCoordinator(
        operation=_operation(),
        processes={role: _process(role) for role in ("engine", "weixin", "feishu")},
        endpoints=endpoints,
        monotonic_clock=lambda: now[0],
        sleeper=sleep,
    )

    with pytest.raises(InstalledChannelDrainTimeout):
        coordinator.drain(timeout_ms=500)

    assert "request:close_admission:engine" not in log
    assert "request:exit:engine" not in log


def test_parent_rejects_receipt_from_the_wrong_process_before_advancing() -> None:
    log: list[str] = []
    wrong = replace(_process("weixin"), pid=9999)
    endpoints = {
        "engine": _ScriptedEndpoint([_receipt("engine", phase="drained")], log),
        "weixin": _ScriptedEndpoint(
            [_receipt("weixin", phase="drained", process=wrong)], log
        ),
        "feishu": _ScriptedEndpoint([_receipt("feishu", phase="drained")], log),
    }
    coordinator = InstalledParentDrainCoordinator(
        operation=_operation(),
        processes={role: _process(role) for role in ("engine", "weixin", "feishu")},
        endpoints=endpoints,
    )

    with pytest.raises(InstalledChannelDrainContractError, match="process"):
        coordinator.drain(timeout_ms=100)

    assert "request:close_admission:engine" not in log


def test_parent_enforces_signed_wall_deadline_and_monotonic_clock_order() -> None:
    log: list[str] = []
    endpoints = {
        role: _ScriptedEndpoint([_receipt(role, phase="drained")], log)
        for role in ("engine", "weixin", "feishu")
    }
    expired = replace(_operation(), deadline_utc_ns=99)
    coordinator = InstalledParentDrainCoordinator(
        operation=expired,
        processes={role: _process(role) for role in ("engine", "weixin", "feishu")},
        endpoints=endpoints,
        utc_ns_clock=lambda: 100,
    )
    with pytest.raises(InstalledChannelDrainTimeout):
        coordinator.drain(timeout_ms=100)
    assert log == []

    ticks = iter((2.0, 1.0))
    coordinator = InstalledParentDrainCoordinator(
        operation=_operation(),
        processes={role: _process(role) for role in ("engine", "weixin", "feishu")},
        endpoints=endpoints,
        monotonic_clock=lambda: next(ticks),
        utc_ns_clock=lambda: 1,
    )
    with pytest.raises(InstalledChannelDrainContractError, match="backwards"):
        coordinator.drain(timeout_ms=100)


def test_child_stop_is_idempotent_but_conflicting_operation_fails_closed() -> None:
    operation = _operation()
    fence = InstalledChildDrainFence(
        binding=operation.binding,
        role="weixin",
        process=_process("weixin"),
    )
    command = InstalledDrainCommand(operation=operation, action="close_claims")
    first = fence.apply_command(command)
    second = fence.apply_command(command)
    assert second == first

    conflict = replace(operation, stop_id="d" * 64)
    with pytest.raises(InstalledChannelDrainContractError, match="conflict"):
        fence.apply_command(
            InstalledDrainCommand(operation=conflict, action="close_claims")
        )
