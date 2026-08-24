"""Channel-neutral claim lease lifecycle.

The storage adapter owns every durable comparison-and-swap.  This module only
coordinates the worker-local heartbeat, sticky loss fence, bounded finish, and
thread shutdown; it deliberately contains no channel identifiers or messages.
"""

from __future__ import annotations

import math
import threading
import time
from contextlib import contextmanager
from typing import Generic, Iterator, Protocol, TypeVar, runtime_checkable


OutcomeT = TypeVar("OutcomeT")


class ClaimLeaseLost(RuntimeError):
    """The worker can no longer prove that it owns the durable claim."""


@runtime_checkable
class ClaimLeaseStorage(Protocol[OutcomeT]):
    """Strict durable operations required by :class:`ClaimLeaseSession`.

    Deadline-aware methods must return before the supplied absolute deadline;
    Python cannot pre-empt a storage adapter that ignores this contract.
    """

    def renew(self) -> bool: ...

    def owns(self) -> bool: ...

    def finish_before(
        self, outcome: OutcomeT, *, deadline_monotonic: float
    ) -> bool: ...

    def confirm_finish_before(
        self, outcome: OutcomeT, *, deadline_monotonic: float
    ) -> bool: ...


@runtime_checkable
class ClaimLeasePolicy(Protocol):
    """Timing, retry classification, and health projection callbacks.

    ``is_retryable`` and ``fault`` run synchronously and must be constant-time,
    non-blocking in-memory operations. Durable or file-backed health work must
    be scheduled outside the lease finish path.
    """

    heartbeat_interval: float
    stop_timeout: float
    finish_timeout: float
    finish_retry_delays: tuple[float, ...]

    def is_retryable(self, error: BaseException) -> bool: ...

    def fault(self, code: str, error: BaseException | None = None) -> None: ...


class ClaimLeaseSession(Generic[OutcomeT]):
    """One worker's lease, from synchronous first pulse through durable finish."""

    def __init__(
        self,
        *,
        storage: ClaimLeaseStorage[OutcomeT],
        policy: ClaimLeasePolicy,
        thread_name: str = "claim-lease-heartbeat",
    ) -> None:
        if not isinstance(storage, ClaimLeaseStorage):
            raise TypeError("storage does not implement ClaimLeaseStorage")
        if not isinstance(policy, ClaimLeasePolicy):
            raise TypeError("policy does not implement ClaimLeasePolicy")
        interval = float(policy.heartbeat_interval)
        stop_timeout = float(policy.stop_timeout)
        finish_timeout = float(policy.finish_timeout)
        delays = tuple(float(value) for value in policy.finish_retry_delays)
        if (
            not math.isfinite(interval)
            or not math.isfinite(stop_timeout)
            or not math.isfinite(finish_timeout)
            or interval <= 0
            or stop_timeout <= 0
            or finish_timeout <= 0
        ):
            raise ValueError("claim lease timing must be finite and positive")
        if (
            not delays
            or any(not math.isfinite(value) or value < 0 for value in delays)
        ):
            raise ValueError(
                "finish retry delays must be finite, nonempty, and nonnegative"
            )
        self._storage = storage
        self._policy = policy
        self._heartbeat_interval = interval
        self._stop_timeout = stop_timeout
        self._finish_timeout = finish_timeout
        self._finish_retry_delays = delays
        self._thread_name = str(thread_name or "claim-lease-heartbeat")
        self._gate = threading.RLock()
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._started = False
        self._finished = False
        self._finish_deadline_failed = False
        self._thread: threading.Thread | None = None

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def _fault(self, code: str, error: BaseException | None = None) -> None:
        self._lost.set()
        self._notify(code, error)

    def _notify(self, code: str, error: BaseException | None = None) -> None:
        try:
            self._policy.fault(code, error)
        except Exception:
            # Health projection is deliberately unable to affect lease state.
            pass

    def _fail_finish_deadline(self, code: str) -> bool:
        """Make a finish timeout sticky without granting close a second budget."""

        self._finish_deadline_failed = True
        self._stop.set()
        self._fault(code)
        return False

    def _close_before(self, deadline_monotonic: float) -> bool:
        """Stop the heartbeat using only the finish deadline's remainder."""

        self._stop.set()
        if time.monotonic() >= deadline_monotonic:
            return self._fail_finish_deadline(
                "finish_heartbeat_stop_after_deadline"
            )
        thread = self._thread
        if thread is None or not thread.is_alive():
            if time.monotonic() >= deadline_monotonic:
                return self._fail_finish_deadline(
                    "finish_heartbeat_stop_after_deadline"
                )
            return not self.lost
        remaining = min(
            deadline_monotonic - time.monotonic(),
            self._stop_timeout,
        )
        if remaining > 0:
            thread.join(timeout=remaining)
        if thread.is_alive():
            self._finish_deadline_failed = True
            self._fault("finish_heartbeat_stop_timeout")
        elif time.monotonic() >= deadline_monotonic:
            return self._fail_finish_deadline(
                "finish_heartbeat_stop_after_deadline"
            )
        return not self.lost

    def _pulse_locked(self) -> bool:
        if self.lost or self._stop.is_set():
            return False
        try:
            renewed = bool(self._storage.renew())
        except Exception as error:
            self._fault("heartbeat_storage_error", error)
            return False
        if not renewed:
            self._fault("heartbeat_lost")
            return False
        return True

    def _run(self) -> None:
        while not self._stop.wait(self._heartbeat_interval):
            with self._gate:
                if not self._pulse_locked():
                    return

    def start(self) -> bool:
        """Synchronously renew once before allowing any handler/provider work."""

        with self._gate:
            if self._started or self._stop.is_set() or not self._pulse_locked():
                return False
            self._started = True
            try:
                thread = threading.Thread(
                    target=self._run,
                    name=self._thread_name,
                    daemon=True,
                )
                thread.start()
            except Exception as error:
                self._fault("heartbeat_start_error", error)
                self._stop.set()
                return False
            self._thread = thread
            return True

    def before_provider(self) -> bool:
        """Renew at a provider boundary; any uncertainty remains sticky."""

        with self._gate:
            if not self._started:
                self._fault("heartbeat_not_started")
                return False
            return self._pulse_locked()

    @contextmanager
    def commit_fence(self) -> Iterator[None]:
        """Serialize a local commit boundary against heartbeat loss."""

        with self._gate:
            if self.lost or self._stop.is_set() or not self._started:
                self._fault("commit_fence_lost")
                raise ClaimLeaseLost("claim lease no longer permits commit")
            try:
                owned = bool(self._storage.owns())
            except Exception as error:
                self._fault("commit_fence_storage_error", error)
                raise ClaimLeaseLost("claim lease ownership is uncertain") from error
            if not owned:
                self._fault("commit_fence_lost")
                raise ClaimLeaseLost("claim lease no longer permits commit")
            yield

    def finish(self, outcome: OutcomeT) -> bool:
        """Boundedly commit one outcome and confirm a lost success response."""

        deadline_monotonic = time.monotonic() + self._finish_timeout
        for index, delay in enumerate(self._finish_retry_delays):
            if index and delay:
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0 or delay >= remaining:
                    return self._fail_finish_deadline(
                        "finish_retry_delay_timeout"
                    )
                if self._stop.wait(delay):
                    self._fault("finish_fence_lost")
                    return False
                if time.monotonic() >= deadline_monotonic:
                    return self._fail_finish_deadline(
                        "finish_retry_delay_timeout"
                    )
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0 or not self._gate.acquire(timeout=remaining):
                return self._fail_finish_deadline("finish_gate_timeout")
            try:
                if time.monotonic() >= deadline_monotonic:
                    return self._fail_finish_deadline("finish_gate_timeout")
                if self.lost or self._stop.is_set() or not self._started:
                    self._fault("finish_fence_lost")
                    return False
                finish_error: BaseException | None = None
                try:
                    changed = bool(
                        self._storage.finish_before(
                            outcome,
                            deadline_monotonic=deadline_monotonic,
                        )
                    )
                except Exception as error:
                    changed = False
                    finish_error = error
                    try:
                        retryable = bool(self._policy.is_retryable(error))
                    except Exception as policy_error:
                        self._fault("finish_retry_policy_error", policy_error)
                        return False
                    if not retryable:
                        self._fault("finish_nonretryable_error", error)
                        return False

                finish_returned_at = time.monotonic()
                if changed and finish_returned_at >= deadline_monotonic:
                    self._finished = True
                    return self._fail_finish_deadline(
                        "finish_commit_after_deadline"
                    )
                if not changed and finish_returned_at >= deadline_monotonic:
                    return self._fail_finish_deadline(
                        "finish_storage_timeout"
                    )
                if changed:
                    self._finished = True
                    self._stop.set()
                else:
                    try:
                        confirmed = bool(
                            self._storage.confirm_finish_before(
                                outcome,
                                deadline_monotonic=deadline_monotonic,
                            )
                        )
                    except Exception as confirm_error:
                        try:
                            confirm_retryable = bool(
                                self._policy.is_retryable(confirm_error)
                            )
                        except Exception as policy_error:
                            self._fault("finish_retry_policy_error", policy_error)
                            return False
                        if not confirm_retryable:
                            self._fault("finish_confirmation_error", confirm_error)
                            return False
                        if time.monotonic() >= deadline_monotonic:
                            return self._fail_finish_deadline(
                                "finish_confirmation_timeout"
                            )
                        self._notify("finish_confirmation_retry", confirm_error)
                        continue
                    confirmation_returned_at = time.monotonic()
                    if confirmed and confirmation_returned_at >= deadline_monotonic:
                        self._finished = True
                        return self._fail_finish_deadline(
                            "finish_confirmation_after_deadline"
                        )
                    if confirmed:
                        self._finished = True
                        self._stop.set()
                    elif confirmation_returned_at >= deadline_monotonic:
                        return self._fail_finish_deadline(
                            "finish_confirmation_timeout"
                        )
                    elif finish_error is None:
                        # A clean CAS miss plus an exact negative receipt means
                        # another owner won; retrying this worker cannot be safe.
                        self._fault("finish_fence_lost")
                        return False
                    else:
                        self._notify("finish_storage_retry", finish_error)
                        continue
            finally:
                self._gate.release()
            if self._finished:
                # The stop signal is set only after the durable write or exact
                # receipt confirmation, so no heartbeat is stopped too early.
                return self._close_before(deadline_monotonic)

        self._notify("finish_retry_exhausted")
        return False

    def close(self) -> bool:
        """Boundedly stop the heartbeat; a stuck thread permanently loses trust."""

        self._stop.set()
        thread = self._thread
        if thread is not None:
            if self._finish_deadline_failed:
                return False
            thread.join(timeout=self._stop_timeout)
            if thread.is_alive():
                self._fault("heartbeat_stop_timeout")
        return not self.lost
