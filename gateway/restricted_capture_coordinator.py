"""Service-neutral orchestration for a restricted installation capture.

Both execution entry points take the operation-store lease and renew it before
every external adapter effect.  This lease only serializes honest service-core
callers using the same store and a non-rollback clock.  It is not a Windows
service identity, boot fence, hostile same-SID boundary, or clock-rollback
proof; the production LocalService adapter must close those NO-GO items.

The coordinator does not set backup/restore readiness and is not wired into
the production app in this slice.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import secrets
import time
from typing import Callable, TypeVar

from gateway.restricted_capture_contract import (
    CAPTURE_COMPONENT_ORDER,
    CapturePhase,
    MaintenanceTicketAuthority,
    RestrictedCaptureAdapter,
    RestrictedCapturePublishedResult,
    RestrictedCaptureRecoveryAuthority,
    RestrictedCaptureRecoveryDecision,
    RestrictedCaptureRequest,
    RestrictedCaptureRootLockResult,
    RestrictedCaptureStageResult,
    RestrictedCaptureTicketFinalizationAuthority,
    RestrictedCaptureVerifiedStageResult,
    require_counter,
    require_digest,
)
from gateway.restricted_capture_operation_store import (
    RestrictedCaptureExecutionLease,
    RestrictedCaptureOperation,
    RestrictedCaptureOperationConflict,
    RestrictedCaptureOperationStore,
)


_EVIDENCE_DOMAIN = b"nachuan.restricted-capture.coordinator-evidence.v2\0"
_HALT_PHASES = frozenset({"completed", "failed_clean", "recovery_required"})
_RECOVERY_EFFECT_PHASES = frozenset(
    {"root_locked", "staging", "staged_verified", "published", "resuming"}
)
_LEASE_MS = 60_000
_T = TypeVar("_T")


class RestrictedCaptureCoordinatorError(RuntimeError):
    pass


class RestrictedCaptureAuthorizationError(RestrictedCaptureCoordinatorError):
    pass


class RestrictedCaptureCoordinatorUnavailable(RestrictedCaptureCoordinatorError):
    pass


class _StepFailure(Exception):
    def __init__(
        self,
        checkpoint: str,
        cause: Exception,
        *,
        outcome_uncertain: bool,
        effect_started: bool = True,
    ) -> None:
        super().__init__(checkpoint)
        self.checkpoint = checkpoint
        self.cause = cause
        self.outcome_uncertain = outcome_uncertain
        self.effect_started = effect_started


class _RecoveryAuthorizationFailure(Exception):
    pass


def _evidence_digest(label: str, value: object) -> str:
    encoded = json.dumps(
        {"label": label, "value": value},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return sha256(_EVIDENCE_DOMAIN + encoded).hexdigest()


def _default_clock_ms() -> int:
    return time.time_ns() // 1_000_000


def _default_lease_owner_digest() -> str:
    return sha256(secrets.token_bytes(32)).hexdigest()


def _claim_checkpoint(request: RestrictedCaptureRequest) -> dict[str, str]:
    return {
        "claimBindingDigest": _evidence_digest(
            "ticket-claim-binding",
            {
                "requesterSidDigest": request.requester_sid_digest,
                "installationId": request.installation_id,
                "epoch": request.epoch,
                "rootRevision": request.root_revision,
                "operationDigest": request.operation_digest,
            },
        )
    }


@dataclass(slots=True)
class _LeaseSession:
    operations: RestrictedCaptureOperationStore
    token: RestrictedCaptureExecutionLease
    clock_ms: Callable[[], int]
    lease_ms: int
    fault_injector: Callable[[str], None]

    def effect(
        self,
        checkpoint: str,
        action: Callable[[], _T],
        *,
        outcome_uncertain: bool,
        reserve_receipts: int,
    ) -> _T:
        try:
            now = require_counter(self.clock_ms(), "restricted capture lease clock")
            self.operations.assert_effect_capacity(
                self.token.operation_digest,
                lease=self.token,
                now_ms=now,
                reserve_receipts=reserve_receipts,
            )
            self.token = self.operations.renew_execution_lease(
                self.token,
                now_ms=now,
                lease_ms=self.lease_ms,
            )
            self.fault_injector(f"{checkpoint}.before_effect")
        except _StepFailure:
            raise
        except Exception as exc:
            raise _StepFailure(
                checkpoint,
                exc,
                outcome_uncertain=False,
                effect_started=False,
            ) from exc
        try:
            result = action()
            self.fault_injector(f"{checkpoint}.after_effect")
            after_now = require_counter(
                self.clock_ms(), "restricted capture post-effect lease clock"
            )
            self.token = self.operations.renew_execution_lease(
                self.token,
                now_ms=after_now,
                lease_ms=self.lease_ms,
            )
            return result
        except _StepFailure:
            raise
        except Exception as exc:
            raise _StepFailure(
                checkpoint,
                exc,
                outcome_uncertain=outcome_uncertain,
                effect_started=True,
            ) from exc


class RestrictedCaptureCoordinator:
    def __init__(
        self,
        *,
        tickets: MaintenanceTicketAuthority,
        operations: RestrictedCaptureOperationStore,
        adapter: RestrictedCaptureAdapter,
        recovery_authority: RestrictedCaptureRecoveryAuthority,
        ticket_finalizer: RestrictedCaptureTicketFinalizationAuthority,
        fault_injector: Callable[[str], None] = lambda _checkpoint: None,
        clock_ms: Callable[[], int] = _default_clock_ms,
        lease_owner_digest_factory: Callable[[], str] = _default_lease_owner_digest,
        lease_ms: int = _LEASE_MS,
    ) -> None:
        if not 1_000 <= lease_ms <= 300_000:
            raise ValueError("restricted capture lease duration is invalid")
        self._tickets = tickets
        self._operations = operations
        self._adapter = adapter
        self._recovery_authority = recovery_authority
        self._ticket_finalizer = ticket_finalizer
        self._fault_injector = fault_injector
        self._clock_ms = clock_ms
        self._lease_owner_digest_factory = lease_owner_digest_factory
        self._lease_ms = lease_ms

    def capture(
        self,
        ticket_secret: str,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureOperation:
        if not isinstance(ticket_secret, str) or not isinstance(
            request, RestrictedCaptureRequest
        ):
            raise RestrictedCaptureAuthorizationError(
                "restricted capture authorization is invalid"
            )
        try:
            claimed = self._tickets.claim(
                ticket_secret,
                requester_sid_digest=request.requester_sid_digest,
                installation_id=request.installation_id,
                epoch=request.epoch,
                root_revision=request.root_revision,
                operation_digest=request.operation_digest,
            )
        except Exception as exc:
            # Claim may already be durable even though its response was lost.
            # Without an operation receipt there is no safe public-secret
            # finalization path; the service-only exact-binding orphan repair
            # entry point must reconcile this outcome.
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture ticket claim outcome is unavailable"
            ) from exc
        if claimed is not True:
            raise RestrictedCaptureAuthorizationError(
                "restricted capture authorization was not claimed"
            )

        state: RestrictedCaptureOperation | None = None
        session: _LeaseSession | None = None
        try:
            self._fault_injector("claimed.before_commit")
            owner = require_digest(
                self._lease_owner_digest_factory(), "restricted capture lease owner"
            )
            now = require_counter(self._clock_ms(), "restricted capture lease clock")
            state, token = self._operations.create_claimed_and_acquire_lease(
                request,
                checkpoint=_claim_checkpoint(request),
                owner_digest=owner,
                now_ms=now,
                lease_ms=self._lease_ms,
            )
            session = _LeaseSession(
                operations=self._operations,
                token=token,
                clock_ms=self._clock_ms,
                lease_ms=self._lease_ms,
                fault_injector=self._fault_injector,
            )
            self._fault_injector("claimed.after_commit")
            state = self._drive(state, session)
            if state.phase != "completed":
                raise RestrictedCaptureCoordinatorUnavailable(
                    "restricted capture did not complete"
                )
        except Exception as exc:
            if state is not None and session is not None:
                try:
                    state = self._record_failure(state, session, exc)
                except Exception:
                    pass
            if session is not None:
                try:
                    self._operations.release_execution_lease(session.token)
                except Exception:
                    pass
            current_known = False
            try:
                current = self._operations.get(request.operation_digest)
                current_known = True
            except Exception:
                current = state
            if current is not None and current.phase == "completed":
                if self._finalize_ticket(
                    request,
                    success=True,
                    ticket_secret=ticket_secret,
                ):
                    return current
            elif current is not None and current.phase == "failed_clean":
                self._finalize_ticket(
                    request,
                    success=False,
                    ticket_secret=ticket_secret,
                )
            elif current is None and current_known:
                # The claimed ticket may be failed only when the operation
                # store authoritatively proves that no durable operation was
                # published.  Nonterminal/recovery state keeps the one-way
                # ticket claimed for service recovery.
                self._finalize_ticket(
                    request,
                    success=False,
                    ticket_secret=ticket_secret,
                )
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture did not complete"
            ) from exc

        lease_released = False
        if session is not None:
            try:
                lease_released = (
                    self._operations.release_execution_lease(session.token) is True
                )
            except Exception:
                pass
        if not self._finalize_ticket(
            request,
            success=True,
            ticket_secret=ticket_secret,
        ):
            raise RestrictedCaptureCoordinatorUnavailable(
                "completed capture ticket finalization was not confirmed"
            )
        # A stale terminal-operation lease is recoverable by expiry and must
        # never rewrite a completed operation into a failed ticket.
        _ = lease_released
        return state

    def recover_claimed(
        self,
        request: RestrictedCaptureRequest,
    ) -> RestrictedCaptureOperation:
        """Repair a cross-store orphan after ticket claim but before receipt one.

        This is an internal service entry point.  A public caller cannot use a
        secret here: the ticket store must independently prove one exact,
        unambiguous active-boot claimed binding before operation receipt one is
        created.
        """

        if not isinstance(request, RestrictedCaptureRequest):
            raise RestrictedCaptureAuthorizationError(
                "restricted capture authorization is invalid"
            )
        existing = self._operations.get(request.operation_digest)
        if existing is not None:
            if existing.request != request:
                raise RestrictedCaptureAuthorizationError(
                    "restricted capture authorization binding is invalid"
                )
            return self.recover(request.operation_digest)
        try:
            claimed = self._ticket_finalizer.is_claimed_operation(request)
        except Exception as exc:
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture claimed ticket reconciliation is unavailable"
            ) from exc
        if claimed is not True:
            raise RestrictedCaptureAuthorizationError(
                "restricted capture claimed ticket binding was not confirmed"
            )

        state: RestrictedCaptureOperation | None = None
        session: _LeaseSession | None = None
        try:
            owner = require_digest(
                self._lease_owner_digest_factory(), "restricted capture lease owner"
            )
            now = require_counter(self._clock_ms(), "restricted capture lease clock")
            state, token = self._operations.create_claimed_and_acquire_lease(
                request,
                checkpoint=_claim_checkpoint(request),
                owner_digest=owner,
                now_ms=now,
                lease_ms=self._lease_ms,
            )
            session = _LeaseSession(
                operations=self._operations,
                token=token,
                clock_ms=self._clock_ms,
                lease_ms=self._lease_ms,
                fault_injector=self._fault_injector,
            )
            state = self._drive(state, session)
        except Exception as exc:
            if state is not None and session is not None:
                try:
                    state = self._record_failure(state, session, exc)
                except Exception:
                    pass
            current = state
            try:
                current = self._operations.get(request.operation_digest) or current
            except Exception:
                pass
            if current is not None and current.phase in {"completed", "failed_clean"}:
                if self._finalize_ticket(
                    request,
                    success=current.phase == "completed",
                ):
                    return current
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture claimed ticket recovery did not complete"
            ) from exc
        finally:
            if session is not None:
                try:
                    self._operations.release_execution_lease(session.token)
                except Exception:
                    pass

        if state.phase not in {"completed", "failed_clean"}:
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture claimed ticket recovery did not converge"
            )
        if not self._finalize_ticket(
            request,
            success=state.phase == "completed",
        ):
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture terminal ticket reconciliation failed"
            )
        return state

    def recover(self, operation_digest: str) -> RestrictedCaptureOperation:
        """Internal service-only recovery entry point.

        The caller cannot supply a public secret or recovery decision.  The
        injected service authority and adapter are the only decision sources.
        """

        operation_id = require_digest(operation_digest, "restricted capture operation")
        if self._operations.get(operation_id) is None:
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture operation does not exist"
            )
        session = self._acquire_session(operation_id)
        state: RestrictedCaptureOperation | None = None
        try:
            # Recovery decisions are always made after lease acquisition and
            # a locked-owner reread.  A failed-clean decision may perform only
            # conservative/idempotent cleanup before authorization; the
            # terminal resolution remains bound to a freshly authorized final
            # revision and chain head.
            state = self._operations.get(operation_id)
            if state is None:
                raise RestrictedCaptureCoordinatorUnavailable(
                    "restricted capture operation does not exist"
                )
            if state.phase in {"completed", "failed_clean"}:
                if self._finalize_ticket(
                    state.request,
                    success=state.phase == "completed",
                ):
                    return state
                raise RestrictedCaptureCoordinatorUnavailable(
                    "restricted capture terminal ticket reconciliation failed"
                )
            try:
                if state.phase == "recovery_required":
                    state = self._resolve_recovery(state, session)
                else:
                    # Legacy/non-recovery states may continue only after the
                    # same exact-head service authorization.
                    self._authorize_recovery_state(state)
                if state.phase not in {
                    "completed",
                    "failed_clean",
                    "recovery_required",
                }:
                    state = self._drive(state, session)
            except _RecoveryAuthorizationFailure as exc:
                state = self._operations.get(operation_id) or state
                raise RestrictedCaptureCoordinatorUnavailable(
                    "restricted capture recovery authorization failed"
                ) from exc
            except Exception as exc:
                try:
                    state = self._record_failure(state, session, exc)
                except Exception as failure_exc:
                    raise RestrictedCaptureCoordinatorUnavailable(
                        "restricted capture recovery did not converge"
                    ) from failure_exc
        finally:
            try:
                self._operations.release_execution_lease(session.token)
            except Exception:
                pass
        if state is None:
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture recovery state is unavailable"
            )
        if state.phase in {"completed", "failed_clean"} and not self._finalize_ticket(
            state.request,
            success=state.phase == "completed",
        ):
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture terminal ticket reconciliation failed"
            )
        return state

    def _authorize_recovery_state(
        self,
        state: RestrictedCaptureOperation,
    ) -> tuple[str, int, str]:
        revision = state.revision
        last_receipt_digest = state.last_receipt_digest
        try:
            evidence = require_digest(
                self._recovery_authority.authorize_recovery(
                    state.request,
                    journal_revision=revision,
                    last_receipt_digest=last_receipt_digest,
                ),
                "service recovery authority evidence",
            )
        except Exception as exc:
            raise _RecoveryAuthorizationFailure() from exc
        return evidence, revision, last_receipt_digest

    def _finalize_ticket(
        self,
        request: RestrictedCaptureRequest,
        *,
        success: bool,
        ticket_secret: str | None = None,
    ) -> bool:
        if ticket_secret is not None:
            try:
                if self._tickets.finish(ticket_secret, success=success) is True:
                    return True
            except Exception:
                pass
        try:
            return (
                self._ticket_finalizer.finalize_claimed_operation(
                    request,
                    success=success,
                )
                is True
            )
        except Exception:
            return False

    def _acquire_session(self, operation_digest: str) -> _LeaseSession:
        owner = require_digest(
            self._lease_owner_digest_factory(), "restricted capture lease owner"
        )
        now = require_counter(self._clock_ms(), "restricted capture lease clock")
        token = self._operations.acquire_execution_lease(
            operation_digest,
            owner_digest=owner,
            now_ms=now,
            lease_ms=self._lease_ms,
        )
        return _LeaseSession(
            operations=self._operations,
            token=token,
            clock_ms=self._clock_ms,
            lease_ms=self._lease_ms,
            fault_injector=self._fault_injector,
        )

    def _advance(
        self,
        state: RestrictedCaptureOperation,
        to_phase: CapturePhase,
        checkpoint: dict[str, object],
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        self._fault_injector(f"{to_phase}.before_commit")
        advanced = self._operations.transition(
            state.request.operation_digest,
            expected_phase=state.phase,
            expected_revision=state.revision,
            to_phase=to_phase,
            checkpoint=checkpoint,
            lease=session.token,
            now_ms=require_counter(
                session.clock_ms(), "restricted capture checkpoint lease clock"
            ),
        )
        self._fault_injector(f"{to_phase}.after_commit")
        return advanced

    def _record_progress(
        self,
        state: RestrictedCaptureOperation,
        checkpoint_kind: str,
        checkpoint: dict[str, object],
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        self._fault_injector(f"{checkpoint_kind}.before_commit")
        advanced = self._operations.record_progress(
            state.request.operation_digest,
            expected_phase=state.phase,
            expected_revision=state.revision,
            checkpoint_kind=checkpoint_kind,
            checkpoint=checkpoint,
            lease=session.token,
            now_ms=require_counter(
                session.clock_ms(), "restricted capture checkpoint lease clock"
            ),
        )
        self._fault_injector(f"{checkpoint_kind}.after_commit")
        return advanced

    def _record_cleanup_progress(
        self,
        state: RestrictedCaptureOperation,
        checkpoint_kind: str,
        checkpoint: dict[str, object],
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        self._fault_injector(f"{checkpoint_kind}.before_commit")
        advanced = self._operations.record_cleanup_progress(
            state.request.operation_digest,
            expected_phase=state.phase,
            expected_revision=state.revision,
            checkpoint_kind=checkpoint_kind,
            checkpoint=checkpoint,
            lease=session.token,
            now_ms=require_counter(
                session.clock_ms(), "restricted capture checkpoint lease clock"
            ),
        )
        self._fault_injector(f"{checkpoint_kind}.after_commit")
        return advanced

    def _hold_count(self, state: RestrictedCaptureOperation) -> int:
        receipts = self._operations.receipts(state.request.operation_digest)
        root_held = any(
            receipt.to_phase == "root_locked" for receipt in receipts
        ) and not any(
            receipt.checkpoint_kind in {"root_resumed", "cleanup_root_resumed"}
            for receipt in receipts
        )
        held_components: list[str] = []
        for receipt in receipts:
            if receipt.checkpoint_kind == "drain_begun":
                component = str(receipt.checkpoint["component"])
                if component not in held_components:
                    held_components.append(component)
            elif receipt.checkpoint_kind in {
                "component_released",
                "cleanup_component_released",
            }:
                component = str(receipt.checkpoint["component"])
                if component in held_components:
                    held_components.remove(component)
        global_held = any(
            receipt.to_phase == "fencing" for receipt in receipts
        ) and not any(
            receipt.checkpoint_kind
            in {"global_released", "cleanup_global_released"}
            for receipt in receipts
        )
        return int(root_held) + len(held_components) + int(global_held)

    def _cleanup_receipt_reserve(
        self,
        state: RestrictedCaptureOperation,
        *,
        possible_unjournaled_hold: bool = False,
    ) -> int:
        # One receipt per held resource plus the failed_clean transition.
        return (
            self._hold_count(state)
            + int(possible_unjournaled_hold)
            + 1
        )

    def _resume_receipts_remaining(self, state: RestrictedCaptureOperation) -> int:
        receipts = self._operations.receipts(state.request.operation_digest)
        remaining = 0
        if not any(receipt.checkpoint_kind == "root_resumed" for receipt in receipts):
            remaining += 1
        released = {
            str(receipt.checkpoint["component"])
            for receipt in receipts
            if receipt.checkpoint_kind == "component_released"
        }
        remaining += sum(
            component not in released for component in CAPTURE_COMPONENT_ORDER
        )
        if not any(
            receipt.checkpoint_kind == "global_released" for receipt in receipts
        ):
            remaining += 1
        return remaining + 1  # completed

    def _happy_receipts_remaining(
        self,
        state: RestrictedCaptureOperation,
        *,
        phase: CapturePhase | None = None,
    ) -> int:
        current = state.phase if phase is None else phase
        resume = self._resume_receipts_remaining(state)
        if current == "claimed":
            return 22
        if current == "fencing":
            receipts = self._operations.receipts(state.request.operation_digest)
            progress = sum(
                receipt.checkpoint_kind in {"drain_begun", "drain_quiescent"}
                for receipt in receipts
            )
            return (8 - progress) + 6 + resume
        before_resume = {
            "quiescent": 5,
            "root_locked": 4,
            "staging": 3,
            "staged_verified": 2,
            "published": 1,
            "resuming": 0,
        }.get(current)
        if before_resume is None:
            return 0
        return before_resume + resume

    @staticmethod
    def _continuation_target(failed_phase: CapturePhase) -> CapturePhase | None:
        return {
            "root_locked": "staging",
            "staging": "staged_verified",
            "staged_verified": "published",
            "published": "resuming",
            "resuming": "resuming",
        }.get(failed_phase)  # type: ignore[return-value]

    def _recovery_failed_phase(
        self,
        state: RestrictedCaptureOperation,
    ) -> CapturePhase:
        """Return the immutable failure phase from the recovery entry receipt.

        Cleanup progress is appended while the operation remains in
        ``recovery_required``.  Therefore the journal head may be a
        ``cleanup_*`` receipt and cannot itself be expected to carry
        ``failedPhase``.
        """

        for receipt in reversed(
            self._operations.receipts(state.request.operation_digest)
        ):
            if receipt.checkpoint_kind != "recovery_required":
                continue
            failed_phase = receipt.checkpoint.get("failedPhase")
            if failed_phase in {
                "claimed",
                "fencing",
                "quiescent",
                "root_locked",
                "staging",
                "staged_verified",
                "published",
                "resuming",
            }:
                return failed_phase  # type: ignore[return-value]
            break
        raise RestrictedCaptureCoordinatorUnavailable(
            "restricted capture recovery checkpoint is invalid"
        )

    def _recovery_target_reserve(
        self,
        state: RestrictedCaptureOperation,
        target_phase: CapturePhase,
    ) -> int:
        if target_phase == "failed_clean":
            return self._cleanup_receipt_reserve(state)
        failed_phase = self._recovery_failed_phase(state)
        allowed_target = self._continuation_target(failed_phase)
        if target_phase != allowed_target:
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture recovery target is not monotonic"
            )
        # The first receipt resolves recovery_required to the target; all
        # remaining target-phase receipts must still fit after that commit.
        return 1 + self._happy_receipts_remaining(state, phase=target_phase)

    def _normal_effect_reserve(
        self,
        state: RestrictedCaptureOperation,
        *,
        possible_unjournaled_hold: bool = False,
    ) -> int:
        success = self._happy_receipts_remaining(state)
        cleanup = self._cleanup_receipt_reserve(
            state,
            possible_unjournaled_hold=possible_unjournaled_hold,
        )
        continuation = self._continuation_target(state.phase)
        if continuation is not None:
            cleanup = max(
                cleanup,
                1 + self._happy_receipts_remaining(state, phase=continuation),
            )
        # One recovery_required receipt precedes either recovery branch.
        return max(success, 1 + cleanup)

    def _assert_receipt_reserve(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
        reserve_receipts: int,
    ) -> None:
        self._operations.assert_effect_capacity(
            state.request.operation_digest,
            lease=session.token,
            now_ms=require_counter(
                session.clock_ms(), "restricted capture capacity lease clock"
            ),
            reserve_receipts=reserve_receipts,
        )

    def _drive(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        while state.phase not in _HALT_PHASES:
            request = state.request
            if state.phase == "claimed":
                evidence = session.effect(
                    "fencing.global",
                    lambda: require_digest(
                        self._adapter.fence_global(request), "global fence evidence"
                    ),
                    outcome_uncertain=True,
                    reserve_receipts=self._normal_effect_reserve(
                        state,
                        possible_unjournaled_hold=True,
                    ),
                )
                try:
                    state = self._advance(
                        state,
                        "fencing",
                        {"globalFenceDigest": evidence},
                        session,
                    )
                except Exception as exc:
                    # The fence may be live even when publishing its first
                    # journal receipt failed or its committed response was
                    # lost.  Preserve that uncertainty for conservative
                    # release instead of manufacturing failed_clean.
                    raise _StepFailure(
                        "fencing.global",
                        exc,
                        outcome_uncertain=True,
                    ) from exc
            elif state.phase == "fencing":
                state = self._drive_fencing(state, session)
            elif state.phase == "quiescent":
                result = session.effect(
                    "root_locked.root",
                    lambda: self._adapter.lock_root(request),
                    outcome_uncertain=True,
                    reserve_receipts=self._normal_effect_reserve(
                        state,
                        possible_unjournaled_hold=True,
                    ),
                )
                if not isinstance(result, RestrictedCaptureRootLockResult):
                    raise _StepFailure(
                        "root_locked.root",
                        ValueError("Root lock result is invalid"),
                        outcome_uncertain=True,
                    )
                quiescent = self._phase_checkpoint(state, "quiescent")
                try:
                    state = self._advance(
                        state,
                        "root_locked",
                        {
                            "lockedRootRevision": result.locked_root_revision,
                            "rootSnapshotDigest": result.root_snapshot_digest,
                            "rootLockEvidenceDigest": result.root_lock_evidence_digest,
                            "quiescenceDigest": quiescent["quiescenceDigest"],
                        },
                        session,
                    )
                except Exception as exc:
                    # Root may already be locked even if the corresponding
                    # journal receipt could not be published.  Recovery must
                    # conservatively resume it before a clean terminal state.
                    raise _StepFailure(
                        "root_locked.root",
                        exc,
                        outcome_uncertain=True,
                    ) from exc
            elif state.phase == "root_locked":
                result = session.effect(
                    "staging.stage",
                    lambda: self._adapter.stage(request),
                    outcome_uncertain=True,
                    reserve_receipts=self._normal_effect_reserve(state),
                )
                if not isinstance(result, RestrictedCaptureStageResult):
                    raise _StepFailure(
                        "staging.stage",
                        ValueError("staging result is invalid"),
                        outcome_uncertain=True,
                    )
                binding = self._staged_binding(state)
                state = self._advance(
                    state,
                    "staging",
                    {
                        **binding,
                        "artifactSetDigest": result.artifact_set_digest,
                        "stagingEvidenceDigest": result.staging_evidence_digest,
                    },
                    session,
                )
            elif state.phase == "staging":
                result = session.effect(
                    "staged_verified.verify",
                    lambda: self._adapter.verify_stage(request),
                    outcome_uncertain=True,
                    reserve_receipts=self._normal_effect_reserve(state),
                )
                if not isinstance(result, RestrictedCaptureVerifiedStageResult):
                    raise _StepFailure(
                        "staged_verified.verify",
                        ValueError("stage verification result is invalid"),
                        outcome_uncertain=True,
                    )
                staging = self._phase_checkpoint(state, "staging")
                if result.artifact_set_digest != staging["artifactSetDigest"]:
                    raise _StepFailure(
                        "staged_verified.verify",
                        ValueError("verified artifact set changed"),
                        outcome_uncertain=True,
                    )
                state = self._advance(
                    state,
                    "staged_verified",
                    {
                        **self._staged_binding(state),
                        "artifactSetDigest": result.artifact_set_digest,
                        "manifestSha256": result.manifest_sha256,
                        "verificationEvidenceDigest": result.verification_evidence_digest,
                    },
                    session,
                )
            elif state.phase == "staged_verified":
                result = session.effect(
                    "published.publish",
                    lambda: self._adapter.publish(request),
                    outcome_uncertain=True,
                    reserve_receipts=self._normal_effect_reserve(state),
                )
                if not isinstance(result, RestrictedCapturePublishedResult):
                    raise _StepFailure(
                        "published.publish",
                        ValueError("publication result is invalid"),
                        outcome_uncertain=True,
                    )
                verified = self._phase_checkpoint(state, "staged_verified")
                if (
                    result.artifact_set_digest != verified["artifactSetDigest"]
                    or result.manifest_sha256 != verified["manifestSha256"]
                ):
                    raise _StepFailure(
                        "published.publish",
                        ValueError("published artifact binding changed"),
                        outcome_uncertain=True,
                    )
                state = self._advance(
                    state,
                    "published",
                    {
                        **self._staged_binding(state),
                        "artifactSetDigest": result.artifact_set_digest,
                        "manifestSha256": result.manifest_sha256,
                        "publicationEvidenceDigest": result.publication_evidence_digest,
                    },
                    session,
                )
            elif state.phase == "published":
                self._assert_receipt_reserve(
                    state,
                    session,
                    self._normal_effect_reserve(state),
                )
                state = self._advance(
                    state,
                    "resuming",
                    {
                        "resumeIntentDigest": _evidence_digest(
                            "resume-intent", state.last_receipt_digest
                        )
                    },
                    session,
                )
            elif state.phase == "resuming":
                state = self._drive_resuming(state, session)
            else:
                raise RestrictedCaptureCoordinatorUnavailable(
                    "restricted capture operation phase is unsupported"
                )
        return state

    def _drive_fencing(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        request = state.request
        receipts = self._operations.receipts(request.operation_digest)
        begun = {
            str(receipt.checkpoint["component"])
            for receipt in receipts
            if receipt.checkpoint_kind == "drain_begun"
        }
        for component in CAPTURE_COMPONENT_ORDER:
            if component in begun:
                continue
            checkpoint_name = f"drain_begun.{component}"
            evidence = session.effect(
                checkpoint_name,
                lambda component=component: require_digest(
                    self._adapter.begin_drain(request, component),
                    "component drain-begin evidence",
                ),
                outcome_uncertain=True,
                reserve_receipts=self._normal_effect_reserve(
                    state,
                    possible_unjournaled_hold=True,
                ),
            )
            try:
                state = self._record_progress(
                    state,
                    "drain_begun",
                    {"component": component, "beginEvidenceDigest": evidence},
                    session,
                )
            except Exception as exc:
                raise _StepFailure(
                    checkpoint_name,
                    exc,
                    outcome_uncertain=True,
                ) from exc

        receipts = self._operations.receipts(request.operation_digest)
        quiescent_components = {
            str(receipt.checkpoint["component"]): str(
                receipt.checkpoint["quiescenceEvidenceDigest"]
            )
            for receipt in receipts
            if receipt.checkpoint_kind == "drain_quiescent"
        }
        for component in CAPTURE_COMPONENT_ORDER:
            if component in quiescent_components:
                continue
            checkpoint_name = f"drain_quiescent.{component}"
            evidence = session.effect(
                checkpoint_name,
                lambda component=component: require_digest(
                    self._adapter.await_quiescent(request, component),
                    "component quiescence evidence",
                ),
                outcome_uncertain=False,
                reserve_receipts=self._normal_effect_reserve(state),
            )
            state = self._record_progress(
                state,
                "drain_quiescent",
                {"component": component, "quiescenceEvidenceDigest": evidence},
                session,
            )
            quiescent_components[component] = evidence

        observed_revision = session.effect(
            "quiescent.root_reread",
            lambda: self._adapter.reread_root_revision(request),
            outcome_uncertain=False,
            reserve_receipts=self._normal_effect_reserve(state),
        )
        if observed_revision != request.root_revision:
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture Root changed before maintenance CAS"
            )
        return self._advance(
            state,
            "quiescent",
            {
                "observedRootRevision": observed_revision,
                "quiescenceDigest": _evidence_digest(
                    "component-quiescence",
                    [
                        [component, quiescent_components[component]]
                        for component in CAPTURE_COMPONENT_ORDER
                    ],
                ),
                "desktopEvidenceDigest": quiescent_components["desktop"],
                "gatewayEvidenceDigest": quiescent_components["gateway"],
                "gatewayAssetsEvidenceDigest": quiescent_components["gateway_assets"],
                "channelMediaEvidenceDigest": quiescent_components["channel_media"],
            },
            session,
        )

    def _drive_resuming(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        request = state.request
        receipts = self._operations.receipts(request.operation_digest)
        kinds = [receipt.checkpoint_kind for receipt in receipts]
        if "root_resumed" not in kinds:
            evidence = session.effect(
                "root_resumed.root",
                lambda: require_digest(
                    self._adapter.resume_root(request), "Root resume evidence"
                ),
                outcome_uncertain=True,
                reserve_receipts=self._normal_effect_reserve(state),
            )
            state = self._record_progress(
                state,
                "root_resumed",
                {"rootResumeEvidenceDigest": evidence},
                session,
            )

        receipts = self._operations.receipts(request.operation_digest)
        released = {
            str(receipt.checkpoint["component"])
            for receipt in receipts
            if receipt.checkpoint_kind == "component_released"
        }
        for component in reversed(CAPTURE_COMPONENT_ORDER):
            if component in released:
                continue
            evidence = session.effect(
                f"component_released.{component}",
                lambda component=component: require_digest(
                    self._adapter.release_component(request, component),
                    "component release evidence",
                ),
                outcome_uncertain=True,
                reserve_receipts=self._normal_effect_reserve(state),
            )
            state = self._record_progress(
                state,
                "component_released",
                {"component": component, "releaseEvidenceDigest": evidence},
                session,
            )

        receipts = self._operations.receipts(request.operation_digest)
        if not any(
            receipt.checkpoint_kind == "global_released" for receipt in receipts
        ):
            evidence = session.effect(
                "global_released.global",
                lambda: require_digest(
                    self._adapter.release_global(request), "global release evidence"
                ),
                outcome_uncertain=True,
                reserve_receipts=self._normal_effect_reserve(state),
            )
            state = self._record_progress(
                state,
                "global_released",
                {"globalReleaseEvidenceDigest": evidence},
                session,
            )
        release_receipts = [
            receipt.receipt_digest
            for receipt in self._operations.receipts(request.operation_digest)
            if receipt.checkpoint_kind
            in {"root_resumed", "component_released", "global_released"}
        ]
        self._assert_receipt_reserve(state, session, 1)
        return self._advance(
            state,
            "completed",
            {"resumeEvidenceDigest": _evidence_digest("resume-complete", release_receipts)},
            session,
        )

    def _resolve_recovery(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        failed_phase = self._recovery_failed_phase(state)
        decision = session.effect(
            "recovery_inspection",
            lambda: self._adapter.inspect_recovery(
                state.request,
                failed_phase=failed_phase,  # type: ignore[arg-type]
                journal_revision=state.revision,
                last_receipt_digest=state.last_receipt_digest,
            ),
            outcome_uncertain=False,
            reserve_receipts=1,
        )
        if not isinstance(decision, RestrictedCaptureRecoveryDecision):
            raise RestrictedCaptureCoordinatorUnavailable(
                "restricted capture recovery decision is invalid"
            )
        recovery_checkpoint = dict(decision.checkpoint)
        self._assert_receipt_reserve(
            state,
            session,
            self._recovery_target_reserve(state, decision.target_phase),
        )
        if decision.target_phase == "failed_clean":
            inspection_evidence = require_digest(
                recovery_checkpoint.get("cleanupEvidenceDigest"),
                "recovery cleanup inspection evidence",
            )
            artifact_cleanup_evidence: str | None = None
            if failed_phase in {
                "root_locked",
                "staging",
                "staged_verified",
            }:
                artifact_cleanup_evidence = session.effect(
                    f"cleanup_artifacts.{failed_phase}",
                    lambda: require_digest(
                        self._adapter.reconcile_artifacts_for_failed_clean(
                            state.request,
                            failed_phase=failed_phase,  # type: ignore[arg-type]
                            journal_revision=state.revision,
                            last_receipt_digest=state.last_receipt_digest,
                        ),
                        "recovery artifact cleanup evidence",
                    ),
                    outcome_uncertain=True,
                    reserve_receipts=self._cleanup_receipt_reserve(state),
                )
            state, uncertain_release_evidence = (
                self._reconcile_unjournaled_holds(
                    state,
                    session,
                    failed_phase=failed_phase,  # type: ignore[arg-type]
                )
            )
            state = self._cleanup_holds(state, session)
            cleanup_release_evidence: list[str] = []
            for receipt in self._operations.receipts(
                state.request.operation_digest
            ):
                if receipt.checkpoint_kind in {
                    "cleanup_root_resumed",
                    "cleanup_component_released",
                }:
                    cleanup_release_evidence.append(
                        str(receipt.checkpoint["releaseEvidenceDigest"])
                        if receipt.checkpoint_kind
                        == "cleanup_component_released"
                        else str(receipt.checkpoint["rootResumeEvidenceDigest"])
                    )
                elif receipt.checkpoint_kind == "cleanup_global_released":
                    cleanup_release_evidence.append(
                        str(receipt.checkpoint["globalReleaseEvidenceDigest"])
                    )
            recovery_checkpoint = {
                "cleanupEvidenceDigest": _evidence_digest(
                    "recovery-cleanup-complete",
                    {
                        "inspectionEvidenceDigest": inspection_evidence,
                        "artifactCleanupEvidenceDigest": (
                            artifact_cleanup_evidence
                        ),
                        "conservativeReleaseEvidenceDigests": (
                            uncertain_release_evidence
                        ),
                        "journaledReleaseEvidenceDigests": (
                            cleanup_release_evidence
                        ),
                        "lastReceiptDigest": state.last_receipt_digest,
                    },
                )
            }
        (
            recovery_authority_digest,
            authority_authorized_revision,
            authority_authorized_last_receipt_digest,
        ) = self._authorize_recovery_state(state)
        self._assert_receipt_reserve(state, session, 1)
        self._fault_injector(f"recovery.{decision.target_phase}.before_commit")
        resolved = self._operations.resolve_recovery(
            state.request.operation_digest,
            expected_revision=state.revision,
            to_phase=decision.target_phase,
            checkpoint=recovery_checkpoint,
            recovery_authority_digest=recovery_authority_digest,
            authority_authorized_revision=authority_authorized_revision,
            authority_authorized_last_receipt_digest=(
                authority_authorized_last_receipt_digest
            ),
            lease=session.token,
            now_ms=require_counter(
                session.clock_ms(), "restricted capture recovery lease clock"
            ),
        )
        self._fault_injector(f"recovery.{decision.target_phase}.after_commit")
        return resolved

    def _record_failure(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
        cause: Exception,
    ) -> RestrictedCaptureOperation:
        current = self._operations.get(state.request.operation_digest) or state
        if current.phase in _HALT_PHASES:
            return current
        step = cause if isinstance(cause, _StepFailure) else None
        outcome_uncertain = step.outcome_uncertain if step is not None else False
        failed_checkpoint = step.checkpoint if step is not None else current.phase
        # Once the journal has reached an effect-bearing phase, a later
        # pre-effect gate failure does not erase already materialized state
        # (for example a staged artifact awaiting verification).  Preserve it
        # for typed recovery even when the *next* effect never started.
        if (
            outcome_uncertain
            or current.phase in _RECOVERY_EFFECT_PHASES
            or self._hold_count(current) > 0
        ):
            return self._advance(
                current,
                "recovery_required",
                {
                    "failedPhase": current.phase,
                    "failureDigest": _evidence_digest(
                        "failure",
                        {
                            "checkpoint": failed_checkpoint,
                            "exceptionType": type(
                                step.cause if step is not None else cause
                            ).__name__,
                        },
                    ),
                },
                session,
            )
        current = self._cleanup_holds(current, session)
        self._assert_receipt_reserve(current, session, 1)
        return self._advance(
            current,
            "failed_clean",
            {
                "cleanupEvidenceDigest": _evidence_digest(
                    "clean-failure", current.last_receipt_digest
                )
            },
            session,
        )

    def _reconcile_unjournaled_holds(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
        *,
        failed_phase: CapturePhase,
    ) -> tuple[RestrictedCaptureOperation, list[str]]:
        """Replay the conservative hold superset that lacked an intent receipt.

        These adapter calls intentionally have no individual journal receipt
        when the hold was never journaled.  A crash simply repeats the fixed,
        idempotent superset; the eventual failed_clean receipt binds every
        returned digest together with the inspection decision.
        """

        request = state.request
        evidence: list[str] = []
        if failed_phase == "quiescent":
            root_evidence = session.effect(
                "cleanup_uncertain_root_resumed.root",
                lambda: require_digest(
                    self._adapter.resume_root(request),
                    "uncertain Root resume evidence",
                ),
                outcome_uncertain=True,
                reserve_receipts=self._cleanup_receipt_reserve(state),
            )
            evidence.append(root_evidence)

        if failed_phase == "fencing":
            for component in reversed(CAPTURE_COMPONENT_ORDER):
                component_evidence = session.effect(
                    f"cleanup_uncertain_component_released.{component}",
                    lambda component=component: require_digest(
                        self._adapter.release_component(request, component),
                        "uncertain component release evidence",
                    ),
                    outcome_uncertain=True,
                    reserve_receipts=self._cleanup_receipt_reserve(state),
                )
                evidence.append(component_evidence)
                receipts = self._operations.receipts(request.operation_digest)
                held: list[str] = []
                for receipt in receipts:
                    if receipt.checkpoint_kind == "drain_begun":
                        held_component = str(receipt.checkpoint["component"])
                        if held_component not in held:
                            held.append(held_component)
                    elif receipt.checkpoint_kind in {
                        "component_released",
                        "cleanup_component_released",
                    }:
                        held_component = str(receipt.checkpoint["component"])
                        if held_component in held:
                            held.remove(held_component)
                if component in held:
                    state = self._record_cleanup_progress(
                        state,
                        "cleanup_component_released",
                        {
                            "component": component,
                            "releaseEvidenceDigest": component_evidence,
                        },
                        session,
                    )

        if failed_phase in {"claimed", "fencing"}:
            global_evidence = session.effect(
                "cleanup_uncertain_global_released.global",
                lambda: require_digest(
                    self._adapter.release_global(request),
                    "uncertain global release evidence",
                ),
                outcome_uncertain=True,
                reserve_receipts=self._cleanup_receipt_reserve(state),
            )
            evidence.append(global_evidence)
            receipts = self._operations.receipts(request.operation_digest)
            global_held = any(
                receipt.to_phase == "fencing" for receipt in receipts
            ) and not any(
                receipt.checkpoint_kind
                in {"global_released", "cleanup_global_released"}
                for receipt in receipts
            )
            if global_held:
                state = self._record_cleanup_progress(
                    state,
                    "cleanup_global_released",
                    {"globalReleaseEvidenceDigest": global_evidence},
                    session,
                )
        return state, evidence

    def _cleanup_holds(
        self,
        state: RestrictedCaptureOperation,
        session: _LeaseSession,
    ) -> RestrictedCaptureOperation:
        request = state.request
        receipts = self._operations.receipts(request.operation_digest)
        root_held = any(receipt.to_phase == "root_locked" for receipt in receipts) and not any(
            receipt.checkpoint_kind in {"root_resumed", "cleanup_root_resumed"}
            for receipt in receipts
        )
        if root_held:
            evidence = session.effect(
                "cleanup_root_resumed.root",
                lambda: require_digest(
                    self._adapter.resume_root(request), "cleanup Root resume evidence"
                ),
                outcome_uncertain=True,
                reserve_receipts=self._cleanup_receipt_reserve(state),
            )
            state = self._record_cleanup_progress(
                state,
                "cleanup_root_resumed",
                {"rootResumeEvidenceDigest": evidence},
                session,
            )

        receipts = self._operations.receipts(request.operation_digest)
        held: list[str] = []
        for receipt in receipts:
            if receipt.checkpoint_kind == "drain_begun":
                component = str(receipt.checkpoint["component"])
                if component not in held:
                    held.append(component)
            elif receipt.checkpoint_kind in {
                "component_released",
                "cleanup_component_released",
            }:
                component = str(receipt.checkpoint["component"])
                if component in held:
                    held.remove(component)
        for component in reversed(held):
            evidence = session.effect(
                f"cleanup_component_released.{component}",
                lambda component=component: require_digest(
                    self._adapter.release_component(request, component),
                    "cleanup component release evidence",
                ),
                outcome_uncertain=True,
                reserve_receipts=self._cleanup_receipt_reserve(state),
            )
            state = self._record_cleanup_progress(
                state,
                "cleanup_component_released",
                {"component": component, "releaseEvidenceDigest": evidence},
                session,
            )

        receipts = self._operations.receipts(request.operation_digest)
        global_held = any(receipt.to_phase == "fencing" for receipt in receipts) and not any(
            receipt.checkpoint_kind in {"global_released", "cleanup_global_released"}
            for receipt in receipts
        )
        if global_held:
            evidence = session.effect(
                "cleanup_global_released.global",
                lambda: require_digest(
                    self._adapter.release_global(request),
                    "cleanup global release evidence",
                ),
                outcome_uncertain=True,
                reserve_receipts=self._cleanup_receipt_reserve(state),
            )
            state = self._record_cleanup_progress(
                state,
                "cleanup_global_released",
                {"globalReleaseEvidenceDigest": evidence},
                session,
            )
        return state

    def _phase_checkpoint(
        self,
        state: RestrictedCaptureOperation,
        phase: CapturePhase,
    ) -> dict[str, object]:
        for receipt in reversed(
            self._operations.receipts(state.request.operation_digest)
        ):
            if receipt.checkpoint_kind == phase:
                return receipt.checkpoint
        raise RestrictedCaptureCoordinatorUnavailable(
            "restricted capture phase checkpoint is missing"
        )

    def _staged_binding(self, state: RestrictedCaptureOperation) -> dict[str, object]:
        root = self._phase_checkpoint(state, "root_locked")
        quiescent = self._phase_checkpoint(state, "quiescent")
        return {
            "snapshotId": state.request.snapshot_id,
            "lockedRootRevision": root["lockedRootRevision"],
            "rootSnapshotDigest": root["rootSnapshotDigest"],
            "quiescenceDigest": root["quiescenceDigest"],
            "desktopEvidenceDigest": quiescent["desktopEvidenceDigest"],
        }


__all__ = [
    "RestrictedCaptureAuthorizationError",
    "RestrictedCaptureCoordinator",
    "RestrictedCaptureCoordinatorError",
    "RestrictedCaptureCoordinatorUnavailable",
]
