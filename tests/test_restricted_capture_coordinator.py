from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

import gateway.restricted_capture_operation_store as operation_store_module
from gateway.maintenance_ticket_store import (
    MaintenanceTicketStore,
    MaintenanceTicketStoreDependencies,
    MaintenanceTicketUnavailable,
)
from gateway.restricted_capture_contract import (
    RestrictedCapturePublishedResult,
    RestrictedCaptureRecoveryDecision,
    RestrictedCaptureRequest,
    RestrictedCaptureRootLockResult,
    RestrictedCaptureStageResult,
    RestrictedCaptureVerifiedStageResult,
)
from gateway.restricted_capture_coordinator import (
    RestrictedCaptureAuthorizationError,
    RestrictedCaptureCoordinator,
    RestrictedCaptureCoordinatorUnavailable,
)
from gateway.restricted_capture_operation_store import RestrictedCaptureOperationStore


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _request() -> RestrictedCaptureRequest:
    return RestrictedCaptureRequest(
        requester_sid_digest=_digest("requester-sid"),
        installation_id=_digest("installation"),
        epoch=5,
        root_revision=41,
        operation_digest=_digest("capture-operation"),
    )


def _maintenance_ticket_dependencies() -> MaintenanceTicketStoreDependencies:
    return MaintenanceTicketStoreDependencies(
        wall_clock=lambda: 2_000_000_000.0,
        random_bytes=lambda size: b"R" * size,
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent,
    )


class _Tickets:
    def __init__(self, *, claim_result: bool = True) -> None:
        self.claim_result = claim_result
        self.claims: list[tuple[str, dict[str, object]]] = []
        self.finishes: list[tuple[str, bool]] = []

    def claim(self, secret: str, **bindings: object) -> bool:
        self.claims.append((secret, bindings))
        return self.claim_result

    def finish(self, secret: str, *, success: bool) -> bool:
        self.finishes.append((secret, success))
        return True


class _Adapter:
    def __init__(self) -> None:
        self.events: list[str] = []

    def _event(self, value: str) -> str:
        self.events.append(value)
        return _digest(value)

    def fence_global(self, _request: RestrictedCaptureRequest) -> str:
        return self._event("fence:global")

    def begin_drain(self, _request: RestrictedCaptureRequest, component: str) -> str:
        return self._event(f"drain:begin:{component}")

    def await_quiescent(
        self,
        _request: RestrictedCaptureRequest,
        component: str,
    ) -> str:
        return self._event(f"drain:await:{component}")

    def reread_root_revision(self, request: RestrictedCaptureRequest) -> int:
        self.events.append("root:reread")
        return request.root_revision

    def lock_root(
        self,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureRootLockResult:
        return RestrictedCaptureRootLockResult(
            locked_root_revision=request.root_revision + 1,
            root_snapshot_digest=self._event("root:lock"),
            root_lock_evidence_digest=_digest("root-lock-evidence"),
        )

    def stage(self, _request: RestrictedCaptureRequest) -> RestrictedCaptureStageResult:
        return RestrictedCaptureStageResult(
            artifact_set_digest=_digest("artifact-set"),
            staging_evidence_digest=self._event("stage"),
        )

    def verify_stage(
        self,
        _request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureVerifiedStageResult:
        return RestrictedCaptureVerifiedStageResult(
            artifact_set_digest=_digest("artifact-set"),
            manifest_sha256=_digest("manifest"),
            verification_evidence_digest=self._event("stage:verify"),
        )

    def publish(
        self,
        _request: RestrictedCaptureRequest,
    ) -> RestrictedCapturePublishedResult:
        return RestrictedCapturePublishedResult(
            artifact_set_digest=_digest("artifact-set"),
            manifest_sha256=_digest("manifest"),
            publication_evidence_digest=self._event("publish"),
        )

    def resume_root(self, _request: RestrictedCaptureRequest) -> str:
        return self._event("root:resume")

    def release_component(self, _request: RestrictedCaptureRequest, component: str) -> str:
        return self._event(f"release:{component}")

    def release_global(self, _request: RestrictedCaptureRequest) -> str:
        return self._event("release:global")

    def inspect_recovery(self, *_args, **_kwargs) -> RestrictedCaptureRecoveryDecision:
        return RestrictedCaptureRecoveryDecision(
            target_phase="failed_clean",
            checkpoint={"cleanupEvidenceDigest": _digest("inspected-clean")},
        )

    def reconcile_artifacts_for_failed_clean(
        self,
        _request: RestrictedCaptureRequest,
        *,
        failed_phase: str,
        **_bindings: object,
    ) -> str:
        return self._event(f"artifacts:reconcile:{failed_phase}")


class _RecoveryAuthority:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def authorize_recovery(
        self,
        request: RestrictedCaptureRequest,
        **_bindings: object,
    ) -> str:
        self.calls.append(request.operation_digest)
        return _digest("service-recovery-authority")


class _TicketFinalizer:
    def __init__(self, *, result: bool = True) -> None:
        self.result = result
        self.calls: list[tuple[str, bool]] = []

    def is_claimed_operation(self, _request: RestrictedCaptureRequest) -> bool:
        return self.result

    def finalize_claimed_operation(
        self,
        request: RestrictedCaptureRequest,
        *,
        success: bool,
    ) -> bool:
        self.calls.append((request.operation_digest, success))
        return self.result


class _TerminalAwareTickets(_Tickets):
    """Small stateful stand-in for the real one-way ticket state machine."""

    def __init__(self) -> None:
        super().__init__()
        self.state = "prepared"
        self.claimed_bindings: dict[str, object] | None = None

    def claim(self, secret: str, **bindings: object) -> bool:
        claimed = super().claim(secret, **bindings)
        if claimed:
            self.state = "claimed"
            self.claimed_bindings = dict(bindings)
        return claimed

    def finish(self, secret: str, *, success: bool) -> bool:
        self.finishes.append((secret, success))
        if self.state != "claimed":
            return False
        self.state = "consumed" if success else "failed"
        return True


class _TerminalAwareFinalizer(_TicketFinalizer):
    def __init__(self, tickets: _TerminalAwareTickets) -> None:
        super().__init__()
        self.tickets = tickets

    def is_claimed_operation(self, request: RestrictedCaptureRequest) -> bool:
        expected = {
            "requester_sid_digest": request.requester_sid_digest,
            "installation_id": request.installation_id,
            "epoch": request.epoch,
            "root_revision": request.root_revision,
            "operation_digest": request.operation_digest,
        }
        return (
            self.tickets.state == "claimed"
            and self.tickets.claimed_bindings == expected
        )

    def finalize_claimed_operation(
        self,
        request: RestrictedCaptureRequest,
        *,
        success: bool,
    ) -> bool:
        self.calls.append((request.operation_digest, success))
        expected = {
            "requester_sid_digest": request.requester_sid_digest,
            "installation_id": request.installation_id,
            "epoch": request.epoch,
            "root_revision": request.root_revision,
            "operation_digest": request.operation_digest,
        }
        if self.tickets.claimed_bindings != expected:
            return False
        terminal = "consumed" if success else "failed"
        if self.tickets.state == terminal:
            return True
        if self.tickets.state != "claimed":
            return False
        self.tickets.state = terminal
        return True


class _SingleUseTickets(_Tickets):
    def finish(self, secret: str, *, success: bool) -> bool:
        self.finishes.append((secret, success))
        return len(self.finishes) == 1


def test_capture_completes_in_fixed_order_and_finishes_ticket(tmp_path: Path) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _Tickets()
    adapter = _Adapter()
    recovery_authority = _RecoveryAuthority()
    fault_checkpoints: list[str] = []
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=recovery_authority,
        ticket_finalizer=_TicketFinalizer(),
        fault_injector=fault_checkpoints.append,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    completed = coordinator.capture(secret, request)

    assert completed.phase == "completed"
    assert [
        receipt.to_phase
        for receipt in operations.receipts(request.operation_digest)
        if receipt.from_phase != receipt.to_phase
    ] == [
        "claimed",
        "fencing",
        "quiescent",
        "root_locked",
        "staging",
        "staged_verified",
        "published",
        "resuming",
        "completed",
    ]
    assert adapter.events == [
        "fence:global",
        "drain:begin:desktop",
        "drain:begin:gateway",
        "drain:begin:gateway_assets",
        "drain:begin:channel_media",
        "drain:await:desktop",
        "drain:await:gateway",
        "drain:await:gateway_assets",
        "drain:await:channel_media",
        "root:reread",
        "root:lock",
        "stage",
        "stage:verify",
        "publish",
        "root:resume",
        "release:channel_media",
        "release:gateway_assets",
        "release:gateway",
        "release:desktop",
        "release:global",
    ]
    assert tickets.finishes == [(secret, True)]
    assert secret.encode("ascii") not in (tmp_path / "operations.db").read_bytes()
    for receipt in operations.receipts(request.operation_digest):
        assert f"{receipt.checkpoint_kind}.before_commit" in fault_checkpoints
        assert f"{receipt.checkpoint_kind}.after_commit" in fault_checkpoints


def test_one_successful_secret_finish_is_not_consumed_twice(tmp_path: Path) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('single-use-ticket')}"
    tickets = _SingleUseTickets()
    finalizer = _TicketFinalizer(result=False)
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=RestrictedCaptureOperationStore.provision(
            tmp_path / "operations.db"
        ),
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    completed = coordinator.capture(secret, request)

    assert completed.phase == "completed"
    assert tickets.finishes == [(secret, True)]
    assert finalizer.calls == []


def test_claim_failure_has_zero_operation_or_adapter_side_effects(tmp_path: Path) -> None:
    request = _request()
    tickets = _Tickets(claim_result=False)
    adapter = _Adapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureAuthorizationError):
        coordinator.capture("not-claimed", request)

    assert operations.get(request.operation_digest) is None
    assert adapter.events == []
    assert tickets.finishes == []


def test_store_failure_after_ticket_claim_still_finishes_ticket_false(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _Tickets()
    adapter = _Adapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")

    def _fail_create(*_args, **_kwargs):  # noqa: ANN202
        raise RuntimeError("injected operation store failure")

    monkeypatch.setattr(operations, "create_claimed_and_acquire_lease", _fail_create)
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    assert tickets.finishes == [(secret, False)]
    assert adapter.events == []


def test_real_claimed_ticket_without_operation_is_recovered_by_exact_binding(
    tmp_path: Path,
) -> None:
    request = _request()
    tickets = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('service-boot')}",
        dependencies=_maintenance_ticket_dependencies(),
    )
    issued = tickets.issue(
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
        ttl_seconds=600,
    )
    assert tickets.claim(
        issued.secret,
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
    ) is True
    assert tickets.state(issued.secret) == "claimed"
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=tickets,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("orphan-recovery-owner"),
    )

    completed = coordinator.recover_claimed(request)

    assert completed.phase == "completed"
    assert tickets.state(issued.secret) == "consumed"
    assert tickets.finish(issued.secret, success=True) is False


def test_real_claimed_ticket_orphan_recovery_rejects_a_different_binding(
    tmp_path: Path,
) -> None:
    request = _request()
    tickets = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('service-boot')}",
        dependencies=_maintenance_ticket_dependencies(),
    )
    issued = tickets.issue(
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
        ttl_seconds=600,
    )
    assert tickets.claim(
        issued.secret,
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
    ) is True
    wrong_request = RestrictedCaptureRequest(
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision + 1,
        operation_digest=request.operation_digest,
    )
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=tickets,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("orphan-recovery-owner"),
    )

    with pytest.raises(RestrictedCaptureAuthorizationError):
        coordinator.recover_claimed(wrong_request)

    assert operations.get(request.operation_digest) is None
    assert tickets.state(issued.secret) == "claimed"


def test_real_claimed_ticket_orphan_recovery_rejects_duplicate_exact_bindings(
    tmp_path: Path,
) -> None:
    request = _request()
    random_values = iter((b"A" * 32, b"B" * 32))
    dependencies = MaintenanceTicketStoreDependencies(
        wall_clock=lambda: 2_000_000_000.0,
        random_bytes=lambda size: next(random_values),
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent,
    )
    tickets = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('service-boot')}",
        dependencies=dependencies,
    )
    issued = [
        tickets.issue(
            requester_sid_digest=request.requester_sid_digest,
            installation_id=request.installation_id,
            epoch=request.epoch,
            root_revision=request.root_revision,
            operation_digest=request.operation_digest,
            ttl_seconds=600,
        )
        for _ in range(2)
    ]
    assert tickets.claim(
        issued[0].secret,
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
    ) is True
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=tickets,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("duplicate-binding-owner"),
    )

    with pytest.raises(RestrictedCaptureAuthorizationError):
        coordinator.recover_claimed(request)

    assert operations.get(request.operation_digest) is None
    assert tickets.state(issued[0].secret) == "claimed"
    assert tickets.state(issued[1].secret) == "prepared"


def test_real_claimed_ticket_orphan_recovery_rejects_a_foreign_service_boot(
    tmp_path: Path,
) -> None:
    request = _request()
    path = tmp_path / "maintenance-tickets.db"
    dependencies = _maintenance_ticket_dependencies()
    original = MaintenanceTicketStore.provision(
        path,
        service_boot_id=f"service-boot-v1:{_digest('service-boot-a')}",
        dependencies=dependencies,
    )
    issued = original.issue(
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
        ttl_seconds=600,
    )
    assert original.claim(
        issued.secret,
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
    ) is True
    restarted = MaintenanceTicketStore.open(
        path,
        service_boot_id=f"service-boot-v1:{_digest('service-boot-b')}",
        dependencies=dependencies,
    )
    with pytest.raises(MaintenanceTicketUnavailable):
        original.is_claimed_operation(request)
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=restarted,
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=restarted,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("foreign-boot-owner"),
    )

    with pytest.raises(RestrictedCaptureAuthorizationError):
        coordinator.recover_claimed(request)

    assert operations.get(request.operation_digest) is None
    assert restarted.is_claimed_operation(request) is False


def test_real_ticket_claim_response_loss_is_repaired_without_a_public_secret(
    tmp_path: Path,
) -> None:
    request = _request()
    tickets = MaintenanceTicketStore.provision(
        tmp_path / "maintenance-tickets.db",
        service_boot_id=f"service-boot-v1:{_digest('service-boot')}",
        dependencies=_maintenance_ticket_dependencies(),
    )
    issued = tickets.issue(
        requester_sid_digest=request.requester_sid_digest,
        installation_id=request.installation_id,
        epoch=request.epoch,
        root_revision=request.root_revision,
        operation_digest=request.operation_digest,
        ttl_seconds=600,
    )

    class _ClaimResponseLost:
        def claim(self, secret: str, **bindings: object) -> bool:
            assert tickets.claim(secret, **bindings) is True
            raise RuntimeError("injected loss after durable ticket claim")

        def finish(self, secret: str, *, success: bool) -> bool:
            return tickets.finish(secret, success=success)

    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=_ClaimResponseLost(),
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=tickets,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("claim-loss-owner"),
    )

    with pytest.raises(
        RestrictedCaptureCoordinatorUnavailable,
        match="claim outcome is unavailable",
    ):
        coordinator.capture(issued.secret, request)

    assert tickets.state(issued.secret) == "claimed"
    assert operations.get(request.operation_digest) is None

    completed = coordinator.recover_claimed(request)

    assert completed.phase == "completed"
    assert tickets.state(issued.secret) == "consumed"


class _AwaitFailureAdapter(_Adapter):
    def await_quiescent(
        self,
        _request: RestrictedCaptureRequest,
        component: str,
    ) -> str:
        self.events.append(f"drain:await:{component}")
        if component == "gateway":
            raise RuntimeError("injected await failure")
        return _digest(f"drain:await:{component}")


def test_drain_wait_failure_releases_only_journaled_holds_in_reverse_order(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _AwaitFailureAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    state = operations.get(request.operation_digest)
    assert state is not None and state.phase == "recovery_required"
    assert not any(event.startswith("release:") for event in adapter.events)
    assert tickets.state == "claimed"
    assert tickets.finishes == []

    state = coordinator.recover(request.operation_digest)

    assert state.phase == "failed_clean"
    assert adapter.events[-5:] == [
        "release:channel_media",
        "release:gateway_assets",
        "release:gateway",
        "release:desktop",
        "release:global",
    ]
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]
    assert [
        receipt.checkpoint["component"]
        for receipt in operations.receipts(request.operation_digest)
        if receipt.checkpoint_kind == "cleanup_component_released"
    ] == ["channel_media", "gateway_assets", "gateway", "desktop"]


def test_failure_with_journaled_holds_defers_cleanup_to_recovery(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('deferred-cleanup-ticket')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _AwaitFailureAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert failed.last_receipt.checkpoint["failedPhase"] == "fencing"
    assert not any(event.startswith("release:") for event in adapter.events)
    assert tickets.state == "claimed"
    assert tickets.finishes == []

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert adapter.events[-5:] == [
        "release:channel_media",
        "release:gateway_assets",
        "release:gateway",
        "release:desktop",
        "release:global",
    ]
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]


class _StageOutcomeUnknownAdapter(_Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.fail_stage = True
        self.recovery_checkpoint: dict[str, object] | None = None

    def stage(self, _request: RestrictedCaptureRequest) -> RestrictedCaptureStageResult:
        self.events.append("stage")
        if self.fail_stage:
            self.fail_stage = False
            raise RuntimeError("injected stage outcome unknown")
        return super().stage(_request)

    def inspect_recovery(
        self,
        *_args,
        **_kwargs,
    ) -> RestrictedCaptureRecoveryDecision:
        assert self.recovery_checkpoint is not None
        self.events.append("recovery:inspect")
        return RestrictedCaptureRecoveryDecision(
            target_phase="staging",
            checkpoint=self.recovery_checkpoint,
        )


class _ResumeOutcomeUnknownAdapter(_Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.fail_resume_once = True

    def resume_root(self, _request: RestrictedCaptureRequest) -> str:
        self.events.append("root:resume")
        if self.fail_resume_once:
            self.fail_resume_once = False
            raise RuntimeError("injected Root resume outcome unknown")
        return _digest("root:resume")

    def inspect_recovery(self, *_args, **_kwargs) -> RestrictedCaptureRecoveryDecision:
        self.events.append("recovery:inspect")
        return RestrictedCaptureRecoveryDecision(
            target_phase="failed_clean",
            checkpoint={"cleanupEvidenceDigest": _digest("inspected-clean")},
        )


class _FenceOutcomeUnknownAdapter(_Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.global_held = False
        self.release_evidence = _digest("uncertain-global-release")

    def fence_global(self, _request: RestrictedCaptureRequest) -> str:
        self.events.append("fence:global")
        self.global_held = True
        raise RuntimeError("injected global-fence outcome unknown")

    def release_global(self, _request: RestrictedCaptureRequest) -> str:
        self.events.append("release:global")
        self.global_held = False
        return self.release_evidence

    def inspect_recovery(self, *_args, **_kwargs) -> RestrictedCaptureRecoveryDecision:
        self.events.append("recovery:inspect")
        return RestrictedCaptureRecoveryDecision(
            target_phase="failed_clean",
            checkpoint={"cleanupEvidenceDigest": _digest("inspected-clean")},
        )


class _DrainBeginOutcomeUnknownAdapter(_Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.held_components: set[str] = set()
        self.global_held = False
        self.fail_begin_once = True

    def fence_global(self, _request: RestrictedCaptureRequest) -> str:
        self.events.append("fence:global")
        self.global_held = True
        return _digest("fence:global")

    def begin_drain(self, _request: RestrictedCaptureRequest, component: str) -> str:
        self.events.append(f"drain:begin:{component}")
        self.held_components.add(component)
        if self.fail_begin_once:
            self.fail_begin_once = False
            raise RuntimeError("injected drain-begin outcome unknown")
        return _digest(f"drain:begin:{component}")

    def release_component(self, _request: RestrictedCaptureRequest, component: str) -> str:
        self.events.append(f"release:{component}")
        self.held_components.discard(component)
        return _digest(f"release:{component}")

    def release_global(self, _request: RestrictedCaptureRequest) -> str:
        self.events.append("release:global")
        self.global_held = False
        return _digest("release:global")

    def inspect_recovery(self, *_args, **_kwargs) -> RestrictedCaptureRecoveryDecision:
        self.events.append("recovery:inspect")
        return RestrictedCaptureRecoveryDecision(
            target_phase="failed_clean",
            checkpoint={"cleanupEvidenceDigest": _digest("inspected-clean")},
        )


class _RootLockOutcomeUnknownAdapter(_Adapter):
    def __init__(self) -> None:
        super().__init__()
        self.root_held = False

    def lock_root(
        self,
        _request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureRootLockResult:
        self.events.append("root:lock")
        self.root_held = True
        raise RuntimeError("injected Root-lock outcome unknown")

    def resume_root(self, _request: RestrictedCaptureRequest) -> str:
        self.events.append("root:resume")
        self.root_held = False
        return _digest("root:resume")

    def inspect_recovery(self, *_args, **_kwargs) -> RestrictedCaptureRecoveryDecision:
        self.events.append("recovery:inspect")
        return RestrictedCaptureRecoveryDecision(
            target_phase="failed_clean",
            checkpoint={"cleanupEvidenceDigest": _digest("inspected-clean")},
        )


class _StageArtifactCleanupAdapter(_Adapter):
    def stage(self, _request: RestrictedCaptureRequest) -> RestrictedCaptureStageResult:
        self.events.append("stage")
        raise RuntimeError("injected partial staging outcome unknown")

    def inspect_recovery(self, *_args, **_kwargs) -> RestrictedCaptureRecoveryDecision:
        self.events.append("recovery:inspect")
        return RestrictedCaptureRecoveryDecision(
            target_phase="failed_clean",
            checkpoint={"cleanupEvidenceDigest": _digest("inspected-partial-stage")},
        )


class _RaisingObservedAuthority:
    def __init__(self, events: list[tuple[object, ...]]) -> None:
        self.events = events

    def authorize_recovery(
        self,
        request: RestrictedCaptureRequest,
        *,
        journal_revision: int,
        last_receipt_digest: str,
    ) -> str:
        self.events.append(
            (
                "authorize",
                request.operation_digest,
                journal_revision,
                last_receipt_digest,
            )
        )
        raise RuntimeError("injected recovery authority outage")


def test_recover_authorizes_post_acquire_state_and_releases_on_authority_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    adapter = _StageOutcomeUnknownAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    initial = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("initial-owner"),
    )
    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        initial.capture(secret, request)
    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    receipts = operations.receipts(request.operation_digest)
    root = next(
        receipt.checkpoint
        for receipt in receipts
        if receipt.checkpoint_kind == "root_locked"
    )
    quiescent = next(
        receipt.checkpoint
        for receipt in receipts
        if receipt.checkpoint_kind == "quiescent"
    )
    adapter.recovery_checkpoint = {
        "snapshotId": request.snapshot_id,
        "lockedRootRevision": root["lockedRootRevision"],
        "rootSnapshotDigest": root["rootSnapshotDigest"],
        "quiescenceDigest": root["quiescenceDigest"],
        "desktopEvidenceDigest": quiescent["desktopEvidenceDigest"],
        "artifactSetDigest": _digest("artifact-set"),
        "stagingEvidenceDigest": _digest("inspected-partial"),
    }

    events: list[tuple[object, ...]] = []
    original_get = operations.get
    original_acquire = operations.acquire_execution_lease
    original_release = operations.release_execution_lease

    def _tracked_get(operation_digest: str):  # noqa: ANN202
        state = original_get(operation_digest)
        events.append(
            (
                "get",
                None if state is None else state.revision,
                None if state is None else state.last_receipt_digest,
            )
        )
        return state

    def _tracked_acquire(*args, **kwargs):  # noqa: ANN202
        events.append(("acquire",))
        return original_acquire(*args, **kwargs)

    def _tracked_release(lease):  # noqa: ANN202
        events.append(("release", lease.generation))
        return original_release(lease)

    monkeypatch.setattr(operations, "get", _tracked_get)
    monkeypatch.setattr(operations, "acquire_execution_lease", _tracked_acquire)
    monkeypatch.setattr(operations, "release_execution_lease", _tracked_release)
    coordinator = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=adapter,
        recovery_authority=_RaisingObservedAuthority(events),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("recovery-owner"),
    )

    with pytest.raises(
        RestrictedCaptureCoordinatorUnavailable,
        match="authorization failed",
    ):
        coordinator.recover(request.operation_digest)

    labels = [event[0] for event in events]
    assert labels[:4] == ["get", "acquire", "get", "authorize"]
    assert labels[-1] == "release"
    authorize = events[3]
    assert authorize[2:] == (failed.revision, failed.last_receipt_digest)
    replacement = operations.acquire_execution_lease(
        request.operation_digest,
        owner_digest=_digest("replacement-owner"),
        now_ms=1_000,
        lease_ms=60_000,
    )
    assert operations.release_execution_lease(replacement) is True


def test_recovery_authority_outage_does_not_block_conservative_safe_cleanup(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('authority-cleanup-ticket')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _StageArtifactCleanupAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    initial = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("initial-owner"),
    )
    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        initial.capture(secret, request)
    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert tickets.state == "claimed"
    capture_event_count = len(adapter.events)

    authority_events: list[tuple[object, ...]] = []
    recovery = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RaisingObservedAuthority(authority_events),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("recovery-owner"),
    )

    with pytest.raises(
        RestrictedCaptureCoordinatorUnavailable,
        match="authorization failed",
    ):
        recovery.recover(request.operation_digest)

    still_recoverable = operations.get(request.operation_digest)
    assert still_recoverable is not None
    assert still_recoverable.phase == "recovery_required"
    recovery_events = adapter.events[capture_event_count:]
    assert recovery_events == [
        "recovery:inspect",
        "artifacts:reconcile:root_locked",
        "root:resume",
        "release:channel_media",
        "release:gateway_assets",
        "release:gateway",
        "release:desktop",
        "release:global",
    ]
    assert authority_events[-1][2:] == (
        still_recoverable.revision,
        still_recoverable.last_receipt_digest,
    )
    assert tickets.state == "claimed"
    assert finalizer.calls == []

    resumed = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("resumed-recovery-owner"),
    )

    resolved = resumed.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]


def test_stage_outcome_unknown_recovers_from_inspected_partial_without_restaging(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _TerminalAwareTickets()
    adapter = _StageOutcomeUnknownAdapter()
    authority = _RecoveryAuthority()
    finalizer = _TerminalAwareFinalizer(tickets)
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=authority,
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)
    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert tickets.state == "claimed"
    assert tickets.finishes == []
    receipts = operations.receipts(request.operation_digest)
    root = next(
        receipt.checkpoint
        for receipt in receipts
        if receipt.checkpoint_kind == "root_locked"
    )
    quiescent = next(
        receipt.checkpoint
        for receipt in receipts
        if receipt.checkpoint_kind == "quiescent"
    )
    adapter.recovery_checkpoint = {
        "snapshotId": request.snapshot_id,
        "lockedRootRevision": root["lockedRootRevision"],
        "rootSnapshotDigest": root["rootSnapshotDigest"],
        "quiescenceDigest": root["quiescenceDigest"],
        "desktopEvidenceDigest": quiescent["desktopEvidenceDigest"],
        "artifactSetDigest": _digest("artifact-set"),
        "stagingEvidenceDigest": _digest("inspected-partial"),
    }

    completed = coordinator.recover(request.operation_digest)

    assert completed.phase == "completed"
    assert adapter.events.count("stage") == 1
    assert "recovery:inspect" in adapter.events
    assert authority.calls == [request.operation_digest]
    assert tickets.state == "consumed"
    assert finalizer.calls == [(request.operation_digest, True)]


def test_exact_nine_slot_uncertainty_converges_through_decreasing_cleanup_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    adapter = _ResumeOutcomeUnknownAdapter()
    authority = _RecoveryAuthority()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    capacity_shifted = False
    reserves: list[int] = []
    original_assert = operations.assert_effect_capacity

    def _tracked_assert(*args, **kwargs):  # noqa: ANN202
        if capacity_shifted:
            reserves.append(int(kwargs["reserve_receipts"]))
        return original_assert(*args, **kwargs)

    def _fault(checkpoint: str) -> None:
        nonlocal capacity_shifted
        if checkpoint == "resuming.after_commit":
            monkeypatch.setattr(
                operation_store_module,
                "MAX_CAPTURE_RECEIPTS_PER_OPERATION",
                25,
            )
            capacity_shifted = True

    monkeypatch.setattr(operations, "assert_effect_capacity", _tracked_assert)
    coordinator = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=adapter,
        recovery_authority=authority,
        ticket_finalizer=_TicketFinalizer(),
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)
    failed = operations.get(request.operation_digest)
    assert failed is not None
    assert failed.phase == "recovery_required"
    assert failed.revision == 17
    assert reserves == [9]

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert resolved.revision == 24
    cleanup_kinds = [
        receipt.checkpoint_kind
        for receipt in operations.receipts(request.operation_digest)
        if receipt.checkpoint_kind.startswith("cleanup_")
    ]
    assert cleanup_kinds == [
        "cleanup_root_resumed",
        "cleanup_component_released",
        "cleanup_component_released",
        "cleanup_component_released",
        "cleanup_component_released",
        "cleanup_global_released",
    ]
    assert reserves[1:] == [1, 7, 7, 6, 5, 4, 3, 2, 1]
    assert authority.calls == [request.operation_digest]


def test_unjournaled_uncertain_global_hold_is_reconciled_before_failed_clean(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    adapter = _FenceOutcomeUnknownAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)
    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert adapter.global_held is True
    assert not any(
        receipt.to_phase == "fencing"
        for receipt in operations.receipts(request.operation_digest)
    )

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert adapter.global_held is False
    assert adapter.events[-2:] == ["recovery:inspect", "release:global"]
    assert resolved.last_receipt.checkpoint["cleanupEvidenceDigest"] != _digest(
        "inspected-clean"
    )


def test_global_fence_success_before_receipt_commit_is_recovered_conservatively(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('fence-commit-gap-ticket')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _DrainBeginOutcomeUnknownAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")

    def _fault(checkpoint: str) -> None:
        if checkpoint == "fencing.before_commit":
            raise RuntimeError("injected fence receipt commit gap")

    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert failed.last_receipt.checkpoint["failedPhase"] == "claimed"
    assert adapter.global_held is True
    assert tickets.state == "claimed"

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert adapter.global_held is False
    assert adapter.events == ["fence:global", "recovery:inspect", "release:global"]
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]


def test_uncertain_drain_begin_replays_full_reverse_component_superset(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('cleanup-replay-ticket')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _DrainBeginOutcomeUnknownAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    fail_once = True

    def _fault(checkpoint: str) -> None:
        nonlocal fail_once
        if (
            fail_once
            and checkpoint
            == "cleanup_uncertain_component_released.channel_media.after_effect"
        ):
            fail_once = False
            raise RuntimeError("injected crash after unjournaled release")

    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )
    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    assert tickets.state == "claimed"
    assert finalizer.calls == []

    first_recovery = coordinator.recover(request.operation_digest)
    assert first_recovery.phase == "recovery_required"
    assert tickets.state == "claimed"
    assert finalizer.calls == []
    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]
    assert adapter.held_components == set()
    assert adapter.global_held is False
    releases = [event for event in adapter.events if event.startswith("release:")]
    assert releases == [
        "release:channel_media",
        "release:channel_media",
        "release:gateway_assets",
        "release:gateway",
        "release:desktop",
        "release:global",
    ]


@pytest.mark.parametrize(
    ("lost_response_checkpoint", "expected_releases"),
    [
        (
            "cleanup_component_released.after_commit",
            [
                "release:channel_media",
                "release:channel_media",
                "release:gateway_assets",
                "release:gateway",
                "release:desktop",
                "release:global",
            ],
        ),
        (
            "recovery.failed_clean.before_commit",
            [
                "release:channel_media",
                "release:gateway_assets",
                "release:gateway",
                "release:desktop",
                "release:global",
                "release:channel_media",
                "release:gateway_assets",
                "release:gateway",
                "release:desktop",
                "release:global",
            ],
        ),
    ],
)
def test_committed_cleanup_or_terminal_commit_gap_retries_to_failed_clean(
    tmp_path: Path,
    lost_response_checkpoint: str,
    expected_releases: list[str],
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest(lost_response_checkpoint)}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _AwaitFailureAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    fail_once = True

    def _fault(checkpoint: str) -> None:
        nonlocal fail_once
        if fail_once and checkpoint == lost_response_checkpoint:
            fail_once = False
            raise RuntimeError("injected committed cleanup response loss")

    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("cleanup-commit-gap-owner"),
    )
    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    interrupted = coordinator.recover(request.operation_digest)

    assert interrupted.phase == "recovery_required"
    assert tickets.state == "claimed"
    assert finalizer.calls == []

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]
    releases = [event for event in adapter.events if event.startswith("release:")]
    assert releases == expected_releases


def test_uncertain_root_lock_resumes_root_before_journaled_reverse_cleanup(
    tmp_path: Path,
) -> None:
    request = _request()
    adapter = _RootLockOutcomeUnknownAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )
    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(
            f"maintenance-ticket-v1:{_digest('ticket-secret')}",
            request,
        )
    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert adapter.root_held is True

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert adapter.root_held is False
    assert adapter.events[-7:] == [
        "recovery:inspect",
        "root:resume",
        "release:channel_media",
        "release:gateway_assets",
        "release:gateway",
        "release:desktop",
        "release:global",
    ]


def test_root_lock_success_before_receipt_commit_is_recovered_conservatively(
    tmp_path: Path,
) -> None:
    class _RootHoldAdapter(_Adapter):
        def __init__(self) -> None:
            super().__init__()
            self.root_held = False

        def lock_root(
            self,
            request: RestrictedCaptureRequest,
        ) -> RestrictedCaptureRootLockResult:
            self.root_held = True
            return super().lock_root(request)

        def resume_root(self, request: RestrictedCaptureRequest) -> str:
            self.root_held = False
            return super().resume_root(request)

    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('root-commit-gap-ticket')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _RootHoldAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")

    def _fault(checkpoint: str) -> None:
        if checkpoint == "root_locked.before_commit":
            raise RuntimeError("injected Root-lock receipt commit gap")

    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert failed.last_receipt.checkpoint["failedPhase"] == "quiescent"
    assert adapter.root_held is True
    assert tickets.state == "claimed"
    capture_event_count = len(adapter.events)

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert adapter.root_held is False
    recovery_events = adapter.events[capture_event_count:]
    assert recovery_events[0] == "root:resume"
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]


def test_partial_stage_artifact_cleanup_is_typed_and_crash_replayable(
    tmp_path: Path,
) -> None:
    request = _request()
    adapter = _StageArtifactCleanupAdapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    fail_once = True

    def _fault(checkpoint: str) -> None:
        nonlocal fail_once
        if fail_once and checkpoint == "cleanup_artifacts.root_locked.after_effect":
            fail_once = False
            raise RuntimeError("injected crash after artifact cleanup")

    coordinator = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )
    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(
            f"maintenance-ticket-v1:{_digest('ticket-secret')}",
            request,
        )
    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert failed.last_receipt.checkpoint["failedPhase"] == "root_locked"

    interrupted = coordinator.recover(request.operation_digest)
    assert interrupted.phase == "recovery_required"
    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert adapter.events.count("artifacts:reconcile:root_locked") == 2
    assert resolved.last_receipt.checkpoint["cleanupEvidenceDigest"] != _digest(
        "inspected-partial-stage"
    )


def test_pre_effect_failure_after_staging_stays_recoverable_until_typed_cleanup(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('pre-effect-ticket')}"
    tickets = _TerminalAwareTickets()
    finalizer = _TerminalAwareFinalizer(tickets)
    adapter = _Adapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")

    def _fault(checkpoint: str) -> None:
        if checkpoint == "staged_verified.verify.before_effect":
            raise RuntimeError("injected pre-effect gate failure")

    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        fault_injector=_fault,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    failed = operations.get(request.operation_digest)
    assert failed is not None and failed.phase == "recovery_required"
    assert failed.last_receipt.checkpoint["failedPhase"] == "staging"
    assert not any(
        receipt.checkpoint_kind.startswith("cleanup_")
        for receipt in operations.receipts(request.operation_digest)
    )
    assert tickets.state == "claimed"
    assert tickets.finishes == []

    resolved = coordinator.recover(request.operation_digest)

    assert resolved.phase == "failed_clean"
    assert "artifacts:reconcile:staging" in adapter.events
    assert tickets.state == "failed"
    assert finalizer.calls == [(request.operation_digest, False)]


class _FinishUnavailableTickets(_Tickets):
    def finish(self, secret: str, *, success: bool) -> bool:
        self.finishes.append((secret, success))
        raise RuntimeError("injected ticket finish outage")


def test_completed_operation_never_becomes_failed_when_lease_or_finish_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _FinishUnavailableTickets()
    finalizer = _TicketFinalizer()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    monkeypatch.setattr(operations, "release_execution_lease", lambda _lease: False)
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    completed = coordinator.capture(secret, request)

    assert completed.phase == "completed"
    assert tickets.finishes == [(secret, True)]
    assert finalizer.calls == [(request.operation_digest, True)]
    assert all(success is not False for _, success in tickets.finishes)


def test_terminal_recovery_retries_exact_binding_ticket_finalization(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _FinishUnavailableTickets()
    finalizer = _TicketFinalizer(result=False)
    authority = _RecoveryAuthority()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=authority,
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)
    completed = operations.get(request.operation_digest)
    assert completed is not None and completed.phase == "completed"
    assert all(success is not False for _, success in tickets.finishes)

    finalizer.result = True
    reconciled = coordinator.recover(request.operation_digest)

    assert reconciled.phase == "completed"
    assert finalizer.calls[-1] == (request.operation_digest, True)
    assert authority.calls == []


def test_terminal_reconciliation_does_not_depend_on_recovery_authority(
    tmp_path: Path,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    initial = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("initial-owner"),
    )
    completed = initial.capture(secret, request)
    receipt_count = completed.receipt_count

    authority_events: list[tuple[object, ...]] = []
    finalizer = _TicketFinalizer()
    recovery = RestrictedCaptureCoordinator(
        tickets=_Tickets(),
        operations=operations,
        adapter=_Adapter(),
        recovery_authority=_RaisingObservedAuthority(authority_events),
        ticket_finalizer=finalizer,
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("reconciliation-owner"),
    )

    reconciled = recovery.recover(request.operation_digest)

    assert reconciled.phase == "completed"
    assert reconciled.receipt_count == receipt_count
    assert authority_events == []
    assert finalizer.calls == [(request.operation_digest, True)]


def test_effect_is_not_called_without_worst_case_terminal_receipt_reserve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    secret = f"maintenance-ticket-v1:{_digest('ticket-secret')}"
    tickets = _Tickets()
    adapter = _Adapter()
    operations = RestrictedCaptureOperationStore.provision(tmp_path / "operations.db")
    monkeypatch.setattr(
        operation_store_module,
        "MAX_CAPTURE_RECEIPTS_PER_OPERATION",
        9,
    )
    coordinator = RestrictedCaptureCoordinator(
        tickets=tickets,
        operations=operations,
        adapter=adapter,
        recovery_authority=_RecoveryAuthority(),
        ticket_finalizer=_TicketFinalizer(),
        clock_ms=lambda: 1_000,
        lease_owner_digest_factory=lambda: _digest("execution-owner"),
    )

    with pytest.raises(RestrictedCaptureCoordinatorUnavailable):
        coordinator.capture(secret, request)

    state = operations.get(request.operation_digest)
    assert state is not None and state.phase == "failed_clean"
    assert adapter.events == []
    assert tickets.finishes == [(secret, False)]
