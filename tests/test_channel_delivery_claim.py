from __future__ import annotations

import threading
import time

import pytest


def _wait_until_monotonic(deadline: float) -> None:
    """Wait through early wakeups so deadline tests are deterministic on Windows."""

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        threading.Event().wait(remaining)


class _Storage:
    def __init__(
        self,
        *,
        renew_results: list[bool] | None = None,
        finish_effects: list[object] | None = None,
        confirmations: list[bool] | None = None,
    ) -> None:
        self.renew_results = list(renew_results or [True])
        self.finish_effects = list(finish_effects or [True])
        self.confirmations = list(confirmations or [False])
        self.renew_calls = 0
        self.finish_calls = 0
        self.confirm_calls = 0
        self.finish_deadlines: list[float] = []
        self.confirm_deadlines: list[float] = []

    def renew(self) -> bool:
        self.renew_calls += 1
        return self.renew_results.pop(0) if self.renew_results else True

    def owns(self) -> bool:
        return True

    def finish(self, outcome: object) -> bool:
        self.finish_calls += 1
        effect = self.finish_effects.pop(0) if self.finish_effects else True
        if isinstance(effect, BaseException):
            raise effect
        return bool(effect)

    def finish_before(
        self, outcome: object, *, deadline_monotonic: float
    ) -> bool:
        self.finish_deadlines.append(deadline_monotonic)
        return self.finish(outcome)

    def confirm_finish(self, outcome: object) -> bool:
        self.confirm_calls += 1
        return self.confirmations.pop(0) if self.confirmations else False

    def confirm_finish_before(
        self, outcome: object, *, deadline_monotonic: float
    ) -> bool:
        self.confirm_deadlines.append(deadline_monotonic)
        return self.confirm_finish(outcome)


class _Policy:
    def __init__(
        self,
        *,
        heartbeat_interval: float = 60.0,
        stop_timeout: float = 0.1,
        finish_timeout: float = 0.5,
        finish_retry_delays: tuple[float, ...] = (0.0,),
    ) -> None:
        self.heartbeat_interval = heartbeat_interval
        self.stop_timeout = stop_timeout
        self.finish_timeout = finish_timeout
        self.finish_retry_delays = finish_retry_delays
        self.faults: list[str] = []

    def is_retryable(self, error: BaseException) -> bool:
        return isinstance(error, OSError)

    def fault(self, code: str, error: BaseException | None = None) -> None:
        self.faults.append(code)


def test_legacy_storage_without_deadline_methods_is_rejected() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    class LegacyStorage:
        def renew(self) -> bool:
            return True

        def owns(self) -> bool:
            return True

        def finish(self, outcome: object) -> bool:
            return True

        def confirm_finish(self, outcome: object) -> bool:
            return True

    with pytest.raises(TypeError, match="does not implement ClaimLeaseStorage"):
        ClaimLeaseSession(storage=LegacyStorage(), policy=_Policy())  # type: ignore[arg-type]


def test_first_heartbeat_failure_never_enters_provider() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(renew_results=[False, True])
    session = ClaimLeaseSession(storage=storage, policy=_Policy())

    assert session.start() is False
    assert session.lost is True
    assert session.before_provider() is False
    assert storage.renew_calls == 1
    assert session.close() is False


def test_finish_confirms_commit_when_storage_response_is_lost() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(
        finish_effects=[OSError("response lost after commit")],
        confirmations=[True],
    )
    session = ClaimLeaseSession(storage=storage, policy=_Policy())
    assert session.start() is True

    assert session.finish("done") is True
    assert storage.finish_calls == 1
    assert storage.confirm_calls == 1
    assert session.lost is False
    assert session.before_provider() is False


def test_finish_and_confirmation_share_one_absolute_deadline() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(
        finish_effects=[OSError("response lost after commit")],
        confirmations=[True],
    )
    policy = _Policy(finish_timeout=0.25)
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is True

    assert len(storage.finish_deadlines) == 1
    assert storage.confirm_deadlines == storage.finish_deadlines
    assert started < storage.finish_deadlines[0] <= started + 0.30


def test_finish_retry_is_bounded_and_leaves_the_claim_processing() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(
        finish_effects=[OSError("locked")] * 3,
        confirmations=[False] * 3,
    )
    policy = _Policy(finish_retry_delays=(0.0, 0.05, 0.2))
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    assert session.finish("done") is False
    assert storage.finish_calls == 3
    assert storage.confirm_calls == 3
    assert policy.faults.count("finish_storage_retry") == 3
    assert policy.faults[-1] == "finish_retry_exhausted"
    # Exhausting the bounded finish attempts does not invent a durable terminal
    # state.  The worker still owns/heartbeats the processing row until close.
    assert session.before_provider() is True
    assert session.close() is True


def test_retry_delay_that_cannot_fit_never_enters_another_storage_call() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(
        finish_effects=[OSError("locked"), OSError("must not be called")],
        confirmations=[False, False],
    )
    policy = _Policy(
        finish_timeout=0.03,
        finish_retry_delays=(0.0, 0.20),
    )
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is False

    assert time.monotonic() - started < 0.12
    assert storage.finish_calls == 1
    assert storage.confirm_calls == 1
    assert "finish_retry_delay_timeout" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_deadline_aware_storage_keeps_finish_wallclock_bounded() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    class DeadlineStorage(_Storage):
        def finish_before(
            self, outcome: object, *, deadline_monotonic: float
        ) -> bool:
            self.finish_calls += 1
            self.finish_deadlines.append(deadline_monotonic)
            _wait_until_monotonic(deadline_monotonic)
            raise TimeoutError("storage deadline reached")

    storage = DeadlineStorage()
    policy = _Policy(finish_timeout=0.03)
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is False

    assert time.monotonic() - started < 0.12
    assert storage.finish_calls == 1
    assert storage.confirm_calls == 0
    assert "finish_storage_timeout" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_commit_returning_true_at_the_deadline_is_not_reported_healthy() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    class LateCommitStorage(_Storage):
        def finish_before(
            self, outcome: object, *, deadline_monotonic: float
        ) -> bool:
            self.finish_calls += 1
            self.finish_deadlines.append(deadline_monotonic)
            _wait_until_monotonic(deadline_monotonic)
            return True

    storage = LateCommitStorage()
    policy = _Policy(finish_timeout=0.03)
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is False

    assert time.monotonic() - started < 0.12
    assert storage.finish_calls == 1
    assert storage.confirm_calls == 0
    assert "finish_commit_after_deadline" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_confirmation_cannot_reset_or_run_past_the_finish_deadline() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    class ConfirmationDeadlineStorage(_Storage):
        def finish_before(
            self, outcome: object, *, deadline_monotonic: float
        ) -> bool:
            self.finish_calls += 1
            self.finish_deadlines.append(deadline_monotonic)
            raise OSError("finish response lost")

        def confirm_finish_before(
            self, outcome: object, *, deadline_monotonic: float
        ) -> bool:
            self.confirm_calls += 1
            self.confirm_deadlines.append(deadline_monotonic)
            _wait_until_monotonic(deadline_monotonic)
            raise TimeoutError("confirmation deadline reached")

    storage = ConfirmationDeadlineStorage()
    policy = _Policy(finish_timeout=0.03)
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is False

    assert time.monotonic() - started < 0.12
    assert storage.finish_deadlines == storage.confirm_deadlines
    assert "finish_confirmation_timeout" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_confirmation_returning_true_at_the_deadline_is_not_reported_healthy() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    class LateConfirmationStorage(_Storage):
        def finish_before(
            self, outcome: object, *, deadline_monotonic: float
        ) -> bool:
            self.finish_calls += 1
            self.finish_deadlines.append(deadline_monotonic)
            raise OSError("finish response lost")

        def confirm_finish_before(
            self, outcome: object, *, deadline_monotonic: float
        ) -> bool:
            self.confirm_calls += 1
            self.confirm_deadlines.append(deadline_monotonic)
            _wait_until_monotonic(deadline_monotonic)
            return True

    storage = LateConfirmationStorage()
    policy = _Policy(finish_timeout=0.03)
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is False

    assert time.monotonic() - started < 0.12
    assert storage.finish_deadlines == storage.confirm_deadlines
    assert "finish_confirmation_after_deadline" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_committed_finish_reports_stuck_heartbeat_without_a_second_close_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gateway.channel_delivery_claim as claim_module

    join_timeouts: list[float | None] = []

    class StuckHeartbeatThread:
        def __init__(self, **kwargs: object) -> None:
            self.alive = False

        def start(self) -> None:
            self.alive = True

        def join(self, timeout: float | None = None) -> None:
            join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return self.alive

    monkeypatch.setattr(claim_module.threading, "Thread", StuckHeartbeatThread)
    storage = _Storage(finish_effects=[True])
    policy = _Policy(stop_timeout=0.25, finish_timeout=0.03)
    session = claim_module.ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True

    assert session.finish("done") is False

    assert len(join_timeouts) == 1
    assert join_timeouts[0] is not None
    assert 0 < join_timeouts[0] <= 0.031
    assert "finish_heartbeat_stop_timeout" in policy.faults
    assert session.lost is True

    assert session.close() is False
    assert len(join_timeouts) == 1


def test_finish_cleanup_is_also_capped_by_the_frozen_stop_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gateway.channel_delivery_claim as claim_module

    join_timeouts: list[float | None] = []

    class StuckHeartbeatThread:
        def __init__(self, **kwargs: object) -> None:
            self.alive = False

        def start(self) -> None:
            self.alive = True

        def join(self, timeout: float | None = None) -> None:
            join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return self.alive

    monkeypatch.setattr(claim_module.threading, "Thread", StuckHeartbeatThread)
    policy = _Policy(stop_timeout=0.03, finish_timeout=0.50)
    session = claim_module.ClaimLeaseSession(
        storage=_Storage(finish_effects=[True]),
        policy=policy,
    )
    policy.stop_timeout = 9.0
    assert session.start() is True

    assert session.finish("done") is False

    assert len(join_timeouts) == 1
    assert join_timeouts[0] is not None
    assert 0 < join_timeouts[0] <= 0.031
    assert "finish_heartbeat_stop_timeout" in policy.faults


def test_finish_cannot_report_success_after_gate_release_crosses_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gateway.channel_delivery_claim as claim_module

    clock = {"now": 0.0}

    class AlreadyStoppedHeartbeatThread:
        def __init__(self, **kwargs: object) -> None:
            pass

        def start(self) -> None:
            pass

        def join(self, timeout: float | None = None) -> None:
            raise AssertionError("an already stopped heartbeat must not be joined")

        def is_alive(self) -> bool:
            return False

    class DeadlineCrossingGate:
        def acquire(self, timeout: float | None = None) -> bool:
            return True

        def release(self) -> None:
            clock["now"] = 0.02

    monkeypatch.setattr(claim_module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        claim_module.threading,
        "Thread",
        AlreadyStoppedHeartbeatThread,
    )
    policy = _Policy(stop_timeout=0.25, finish_timeout=0.02)
    session = claim_module.ClaimLeaseSession(
        storage=_Storage(finish_effects=[True]),
        policy=policy,
    )
    assert session.start() is True
    session._gate = DeadlineCrossingGate()  # type: ignore[assignment]

    assert session.finish("done") is False

    assert "finish_heartbeat_stop_after_deadline" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_finish_does_not_enter_storage_if_gate_acquire_crosses_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gateway.channel_delivery_claim as claim_module

    clock = {"now": 0.0}

    class DeadlineCrossingGate:
        def acquire(self, timeout: float | None = None) -> bool:
            clock["now"] = 0.02
            return True

        def release(self) -> None:
            pass

    monkeypatch.setattr(claim_module.time, "monotonic", lambda: clock["now"])
    storage = _Storage(finish_effects=[True])
    policy = _Policy(stop_timeout=0.25, finish_timeout=0.02)
    session = claim_module.ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True
    session._gate = DeadlineCrossingGate()  # type: ignore[assignment]

    assert session.finish("done") is False

    assert storage.finish_calls == 0
    assert "finish_gate_timeout" in policy.faults
    assert session.lost is True
    assert session.close() is False


def test_background_heartbeat_loss_is_sticky() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(renew_results=[True, False, True])
    session = ClaimLeaseSession(
        storage=storage,
        policy=_Policy(heartbeat_interval=0.005),
    )
    assert session.start() is True
    deadline = time.monotonic() + 1.0
    while not session.lost and time.monotonic() < deadline:
        time.sleep(0.005)

    assert session.lost is True
    assert session.before_provider() is False
    assert storage.renew_calls == 2
    assert session.close() is False


def test_commit_fence_failure_is_sticky() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseLost, ClaimLeaseSession

    storage = _Storage()
    storage.owns = lambda: False  # type: ignore[method-assign]
    session = ClaimLeaseSession(storage=storage, policy=_Policy())
    assert session.start() is True

    with pytest.raises(ClaimLeaseLost, match="no longer permits commit"):
        with session.commit_fence():
            raise AssertionError("must never enter a stale commit")

    storage.owns = lambda: True  # type: ignore[method-assign]
    assert session.lost is True
    assert session.before_provider() is False
    assert session.close() is False


def test_heartbeat_stop_timeout_fails_closed() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    entered = threading.Event()
    release = threading.Event()

    class BlockingStorage(_Storage):
        def renew(self) -> bool:
            self.renew_calls += 1
            if self.renew_calls == 1:
                return True
            entered.set()
            release.wait(1.0)
            return True

    storage = BlockingStorage()
    policy = _Policy(heartbeat_interval=0.005, stop_timeout=0.01)
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True
    assert entered.wait(1.0)

    assert session.close() is False
    assert session.lost is True
    assert "heartbeat_stop_timeout" in policy.faults
    release.set()


def test_finish_fails_closed_within_budget_when_renew_holds_the_gate() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    entered = threading.Event()
    release = threading.Event()

    class BlockingRenewStorage(_Storage):
        def renew(self) -> bool:
            self.renew_calls += 1
            if self.renew_calls == 1:
                return True
            entered.set()
            release.wait(0.25)
            return True

    storage = BlockingRenewStorage()
    policy = _Policy(
        heartbeat_interval=0.005,
        stop_timeout=0.25,
        finish_timeout=0.03,
    )
    session = ClaimLeaseSession(storage=storage, policy=policy)
    assert session.start() is True
    assert entered.wait(1.0)

    try:
        started = time.monotonic()
        assert session.finish("done") is False
        assert time.monotonic() - started < 0.12
        assert storage.finish_calls == 0
        assert session.lost is True
        assert "finish_gate_timeout" in policy.faults

        close_started = time.monotonic()
        assert session.close() is False
        assert time.monotonic() - close_started < 0.08
    finally:
        release.set()


def test_policy_mutation_cannot_change_the_validated_finish_budget() -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    storage = _Storage(
        finish_effects=[OSError("locked"), OSError("locked")],
        confirmations=[False, False],
    )
    policy = _Policy(finish_retry_delays=(0.0, 0.25))
    session = ClaimLeaseSession(storage=storage, policy=policy)
    policy.finish_retry_delays = (0.0,)
    policy.stop_timeout = 999.0
    policy.heartbeat_interval = 999.0
    policy.finish_timeout = 999.0
    assert session.start() is True

    started = time.monotonic()
    assert session.finish("done") is False
    assert storage.finish_calls == 2
    assert len(storage.finish_deadlines) == 2
    assert storage.finish_deadlines[0] == storage.finish_deadlines[1]
    assert started < storage.finish_deadlines[0] <= started + 0.51
    assert session.close() is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("heartbeat_interval", float("nan")),
        ("heartbeat_interval", float("inf")),
        ("stop_timeout", float("nan")),
        ("stop_timeout", float("inf")),
        ("finish_timeout", float("nan")),
        ("finish_timeout", float("inf")),
        ("finish_timeout", 0.0),
        ("finish_timeout", -1.0),
        ("finish_retry_delays", (0.0, float("nan"))),
        ("finish_retry_delays", (0.0, float("inf"))),
    ],
)
def test_nonfinite_policy_budget_is_rejected_before_thread_start(
    field: str, value: object
) -> None:
    from gateway.channel_delivery_claim import ClaimLeaseSession

    policy = _Policy()
    setattr(policy, field, value)

    with pytest.raises(ValueError, match="finite"):
        ClaimLeaseSession(storage=_Storage(), policy=policy)
