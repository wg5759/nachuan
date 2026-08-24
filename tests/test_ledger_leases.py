"""任务账本的并发 claim、租约恢复与幂等约束。"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import time as wall_time

import pytest

from orchestrator.ledger import TaskLedger, run_job

_ASYNC_DB_START_TIMEOUT = 15.0


def test_distinct_jobs_can_be_claimed_concurrently_without_sharing_a_transaction(tmp_path):
    """One Python connection cannot safely host concurrent thread transactions."""
    ledger = TaskLedger(tmp_path / "ledger.db")
    job_ids = [
        ledger.create_job(f"job-{idx}", [{"title": "step"}]) for idx in range(16)
    ]
    barrier = threading.Barrier(len(job_ids))

    def claim(job_id: str) -> int | None:
        barrier.wait(timeout=5)
        return ledger.claim_job(job_id, f"worker-{job_id}")

    try:
        with ThreadPoolExecutor(max_workers=len(job_ids)) as pool:
            claims = list(pool.map(claim, job_ids))
        assert all(epoch == 1 for epoch in claims)
    finally:
        close = getattr(ledger, "close", None)
        if close is not None:
            close()


def test_two_ledger_instances_atomically_compete_for_one_job(tmp_path):
    path = tmp_path / "ledger.db"
    first = TaskLedger(path)
    job_id = first.create_job("one owner", [{"title": "step"}])
    second = TaskLedger(path)
    barrier = threading.Barrier(2)

    def claim(args: tuple[TaskLedger, str]) -> int | None:
        ledger, owner = args
        barrier.wait(timeout=5)
        return ledger.claim_job(job_id, owner)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(claim, [(first, "worker-a"), (second, "worker-b")]))
        assert [epoch for epoch in claims if epoch is not None] == [1]
    finally:
        first.close()
        second.close()


def test_live_job_lease_cannot_be_reclaimed_by_the_same_owner(tmp_path, monkeypatch):
    from orchestrator import ledger as ledger_module

    clock = {"now": 1_000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("single live epoch", [{"title": "step"}])
        epoch = ledger.claim_job(job_id, "worker-a", lease_seconds=10)
        assert epoch == 1
        assert ledger.claim_job(job_id, "worker-a", lease_seconds=10) is None
        assert ledger.renew_job(job_id, "worker-a", epoch, lease_seconds=10)

        clock["now"] = 1_011.0
        assert not ledger.renew_job(job_id, "worker-a", epoch, lease_seconds=10)
        assert ledger.claim_job(job_id, "worker-a", lease_seconds=10) == epoch + 1
    finally:
        ledger.close()


def test_lease_api_rejects_empty_owner_and_nonfinite_duration(tmp_path):
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("validated fencing input", [{"title": "step"}])
        with pytest.raises(ValueError, match="owner"):
            ledger.claim_job(job_id, "", lease_seconds=60)
        with pytest.raises(ValueError, match="finite positive"):
            ledger.claim_job(job_id, "worker", lease_seconds=float("nan"))
        with pytest.raises(ValueError, match="finite positive"):
            ledger.claim_job(job_id, "worker", lease_seconds=float("inf"))
        assert ledger.to_dict(job_id)["status"] == "running"
    finally:
        ledger.close()


def test_expired_job_renewal_loses_to_reclaim_across_instances(tmp_path, monkeypatch):
    from orchestrator import ledger as ledger_module

    clock = {"now": 2_000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    path = tmp_path / "ledger.db"
    first = TaskLedger(path)
    job_id = first.create_job("renew versus reclaim", [{"title": "step"}])
    epoch = first.claim_job(job_id, "old-owner", lease_seconds=10)
    assert epoch == 1
    second = TaskLedger(path)
    clock["now"] = 2_011.0
    barrier = threading.Barrier(2)

    def renew() -> bool:
        barrier.wait(timeout=5)
        return first.renew_job(job_id, "old-owner", epoch, lease_seconds=10)

    def reclaim() -> int | None:
        barrier.wait(timeout=5)
        return second.claim_job(job_id, "new-owner", lease_seconds=10)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            renew_result = pool.submit(renew)
            reclaim_result = pool.submit(reclaim)
            assert renew_result.result(timeout=5) is False
            assert reclaim_result.result(timeout=5) == epoch + 1
    finally:
        first.close()
        second.close()


def test_expired_step_cannot_renew_or_finish_while_job_is_still_live(tmp_path, monkeypatch):
    from orchestrator import ledger as ledger_module

    clock = {"now": 3_000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("child lease expires first", [{"title": "step"}])
        owner = "worker-a"
        epoch = ledger.claim_job(job_id, owner, lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, owner, epoch, lease_seconds=10)
        assert step is not None

        clock["now"] = 3_011.0
        assert not ledger.renew_step(
            step["id"],
            step["claim_token"],
            owner=owner,
            epoch=epoch,
            lease_seconds=10,
        )
        assert not ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "failed",
            owner=owner,
            epoch=epoch,
            error="late failure",
        )
        current = ledger.to_dict(job_id)
        assert current["status"] == "running"
        assert current["steps"][0]["status"] == "running"
    finally:
        ledger.close()


def test_new_epoch_revokes_old_step_even_when_child_lease_is_longer(tmp_path, monkeypatch):
    from orchestrator import ledger as ledger_module

    clock = {"now": 4_000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("root epoch fences child", [{"title": "step"}])
        owner = "same-owner"
        epoch1 = ledger.claim_job(job_id, owner, lease_seconds=10)
        assert epoch1 == 1
        first = ledger.claim_next_step(job_id, owner, epoch1, lease_seconds=60)
        assert first is not None

        clock["now"] = 4_011.0
        epoch2 = ledger.claim_job(job_id, owner, lease_seconds=10)
        assert epoch2 == epoch1 + 1
        assert not ledger.finish_claimed_step(
            first["id"],
            first["claim_token"],
            "done",
            owner=owner,
            epoch=epoch1,
            output="stale",
        )
        second = ledger.claim_next_step(job_id, owner, epoch2, lease_seconds=10)
        assert second is not None
        assert second["idempotency_key"] == first["idempotency_key"]
        assert second["claim_token"] != first["claim_token"]
    finally:
        ledger.close()


def test_final_step_failure_and_job_failure_are_atomic(tmp_path, monkeypatch):
    from orchestrator import ledger as ledger_module

    clock = {"now": 5_000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        job_id = ledger.create_job("atomic failure", [{"title": "step"}])
        owner = "worker-a"
        epoch = ledger.claim_job(job_id, owner, lease_seconds=60)
        assert epoch == 1
        step = ledger.claim_next_step(job_id, owner, epoch, lease_seconds=60)
        assert step is not None
        assert ledger.finish_claimed_step(
            step["id"],
            step["claim_token"],
            "failed",
            owner=owner,
            epoch=epoch,
            error="terminal",
        )
        failed = ledger.to_dict(job_id)
        assert failed["status"] == "failed"
        assert failed["steps"][0]["status"] == "failed"
        assert not ledger.renew_job(job_id, owner, epoch, lease_seconds=60)
        assert ledger.claim_job(job_id, "worker-b", lease_seconds=60) is None

        assert ledger.release_job(job_id, owner, epoch)
        epoch2 = ledger.claim_job(job_id, "worker-b", lease_seconds=60)
        assert epoch2 == epoch + 1
        resumed = ledger.to_dict(job_id)
        assert resumed["status"] == "running"
        assert resumed["steps"][0]["status"] == "pending"
        assert resumed["steps"][0]["attempts"] == 0
    finally:
        ledger.close()


def test_only_an_unclaimed_job_can_use_the_startup_failure_transition(tmp_path):
    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        fresh = ledger.create_job("startup failure", [{"title": "step"}])
        assert ledger.fail_unclaimed_job(fresh)
        assert ledger.to_dict(fresh)["status"] == "failed"

        claimed = ledger.create_job("claimed", [{"title": "step"}])
        epoch = ledger.claim_job(claimed, "worker", lease_seconds=60)
        assert epoch == 1
        assert not ledger.fail_unclaimed_job(claimed)
        assert ledger.to_dict(claimed)["status"] == "running"
    finally:
        ledger.close()


def test_reads_see_only_committed_state_while_writer_transaction_is_open(tmp_path):
    """WAL readers use a separate snapshot and never observe writer-local state."""
    ledger = TaskLedger(tmp_path / "ledger.db")
    job_id = ledger.create_job("snapshot", [{"title": "step"}])
    try:
        ledger._db.execute("BEGIN IMMEDIATE")
        ledger._db.execute("UPDATE jobs SET status='paused' WHERE id=?", (job_id,))
        assert ledger.to_dict(job_id)["status"] == "running"
        ledger._db.rollback()
    finally:
        if ledger._db.in_transaction:
            ledger._db.rollback()
        close = getattr(ledger, "close", None)
        if close is not None:
            close()


def test_to_dict_pins_one_snapshot_across_job_and_step_reads(tmp_path, monkeypatch):
    """A concurrent atomic failure cannot be exposed as a mixed parent/child state."""
    path = tmp_path / "ledger.db"
    reader = TaskLedger(path)
    job_id = reader.create_job("consistent snapshot", [{"title": "step"}])
    owner = "worker-a"
    epoch = reader.claim_job(job_id, owner, lease_seconds=60)
    assert epoch == 1
    step = reader.claim_next_step(job_id, owner, epoch, lease_seconds=60)
    assert step is not None
    writer = TaskLedger(path)
    original_reader = reader._reader
    triggered = {"value": False}

    class ReaderProxy:
        def __init__(self):
            self.db = original_reader()

        def execute(self, sql, params=()):  # noqa: ANN001
            cursor = self.db.execute(sql, params)
            if sql.startswith("SELECT * FROM jobs") and not triggered["value"]:
                triggered["value"] = True
                assert writer.finish_claimed_step(
                    step["id"],
                    step["claim_token"],
                    "failed",
                    owner=owner,
                    epoch=epoch,
                    error="atomic failure",
                )
            return cursor

        def close(self):
            self.db.close()

    monkeypatch.setattr(reader, "_reader", ReaderProxy)
    try:
        observed = reader.to_dict(job_id)
        assert triggered["value"] is True
        assert observed["status"] == "running"
        assert observed["steps"][0]["status"] == "running"

        current = writer.to_dict(job_id)
        assert current["status"] == "failed"
        assert current["steps"][0]["status"] == "failed"
    finally:
        reader.close()
        writer.close()


@pytest.mark.parametrize("renewal", ["false", "error"])
async def test_run_job_cancels_executor_immediately_when_root_lease_is_lost(
    tmp_path, monkeypatch, renewal
):
    from orchestrator import ledger as ledger_module

    # Keep the lease policy clock fixed while asyncio's real scheduler drives
    # the heartbeat.  This tests lease-loss semantics without a 50 ms SQLite
    # operation racing the host/Defender load.
    monkeypatch.setattr(ledger_module.time, "time", lambda: 1_000.0)
    ledger = TaskLedger(tmp_path / "ledger.db")
    job_id = ledger.create_job("cancel stale side effect", [{"title": "step"}])
    started = asyncio.Event()
    cancelled = asyncio.Event()
    notifications: list[str] = []
    loss_observed_at: list[float] = []
    executor_cancelled_at: list[float] = []

    async def executor(_step: dict) -> str:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            executor_cancelled_at.append(wall_time.monotonic())
            cancelled.set()
            raise
        return "must not complete"

    original_renew = ledger.renew_job

    def lose_lease(*args, **kwargs):  # noqa: ANN002, ANN003
        # Under a loaded event loop the heartbeat may be scheduled before the
        # main task starts the executor.  Keep authority until the fixture has
        # positively observed an in-flight side effect, then lose it.
        if not started.is_set():
            return original_renew(*args, **kwargs)
        loss_observed_at.append(wall_time.monotonic())
        if renewal == "error":
            raise OSError("renewal store unavailable")
        return False

    monkeypatch.setattr(ledger, "renew_job", lose_lease)
    try:
        result = await asyncio.wait_for(
            run_job(
                ledger,
                job_id,
                executor,
                lease_seconds=0.05,
                on_step=lambda _step, status, _value: notifications.append(status),
            ),
            timeout=_ASYNC_DB_START_TIMEOUT,
        )
        assert started.is_set()
        assert cancelled.is_set()
        assert len(loss_observed_at) == 1
        assert len(executor_cancelled_at) == 1
        assert 0 <= executor_cancelled_at[0] - loss_observed_at[0] < 1
        assert notifications == []
        assert result["status"] == "running"
        assert result["steps"][0]["status"] == "running"
    finally:
        ledger.close()


def test_ledger_has_durable_wal_busy_and_hard_page_bounds(tmp_path):
    from orchestrator import ledger as ledger_module

    ledger = TaskLedger(tmp_path / "ledger.db")
    try:
        journal_mode = str(ledger._db.execute("PRAGMA journal_mode").fetchone()[0])
        synchronous = int(ledger._db.execute("PRAGMA synchronous").fetchone()[0])
        busy_timeout = int(ledger._db.execute("PRAGMA busy_timeout").fetchone()[0])
        page_size = int(ledger._db.execute("PRAGMA page_size").fetchone()[0])
        max_pages = int(ledger._db.execute("PRAGMA max_page_count").fetchone()[0])
        assert journal_mode.casefold() == "wal"
        assert synchronous == 2  # FULL: lease/result commits survive power loss.
        assert busy_timeout == 5_000
        assert max_pages * page_size <= ledger_module._MAX_LEDGER_BYTES
    finally:
        close = getattr(ledger, "close", None)
        if close is not None:
            close()


async def test_concurrent_resume_claims_exactly_one_worker(tmp_path):
    """两个同时到达的 resume 只能有一个执行同一逻辑步骤。"""
    ledger = TaskLedger(tmp_path / "ledger.db")
    job_id = ledger.create_job("只执行一次", [{"title": "有副作用的步骤"}])
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def executor(_step: dict) -> str:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return "ok"

    first = asyncio.create_task(run_job(ledger, job_id, executor))
    await asyncio.wait_for(started.wait(), timeout=_ASYNC_DB_START_TIMEOUT)
    second = asyncio.create_task(run_job(ledger, job_id, executor))
    try:
        # Await the losing claimant so the assertion cannot pass merely because
        # the event loop has not scheduled it yet.
        await asyncio.wait_for(second, timeout=_ASYNC_DB_START_TIMEOUT)
        assert calls == 1
    finally:
        release.set()
        results = await asyncio.gather(first, second, return_exceptions=True)

    assert not [result for result in results if isinstance(result, BaseException)]
    assert ledger.to_dict(job_id)["status"] == "done"


async def test_running_step_is_reclaimed_only_after_its_lease_expires(tmp_path, monkeypatch):
    """worker 消失后，running 步骤不能立刻重放；租约到期后才能恢复。"""
    from orchestrator import ledger as ledger_module

    clock = {"now": 1000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    ledger = TaskLedger(tmp_path / "ledger.db")
    job_id = ledger.create_job("崩溃后恢复", [{"title": "可能有副作用"}])
    started = asyncio.Event()

    async def crashed_executor(_step: dict) -> str:
        started.set()
        await asyncio.Event().wait()
        return "never"

    crashed = asyncio.create_task(
        run_job(ledger, job_id, crashed_executor, lease_seconds=10)
    )
    await asyncio.wait_for(started.wait(), timeout=_ASYNC_DB_START_TIMEOUT)
    crashed.cancel()
    with pytest.raises(asyncio.CancelledError):
        await crashed
    assert ledger.to_dict(job_id)["steps"][0]["status"] == "running"

    resumed_calls = 0

    async def resumed_executor(_step: dict) -> str:
        nonlocal resumed_calls
        resumed_calls += 1
        return "recovered"

    # 旧调用可能仍在外部进程里收尾；租约没过期时不得重复触发副作用。
    early = await run_job(ledger, job_id, resumed_executor, lease_seconds=10)
    assert early["status"] == "running"
    assert resumed_calls == 0

    clock["now"] += 11
    recovered = await run_job(ledger, job_id, resumed_executor, lease_seconds=10)
    assert recovered["status"] == "done"
    assert resumed_calls == 1


def test_reclaimed_step_keeps_idempotency_key_and_fences_late_completion(tmp_path, monkeypatch):
    """崩溃重试沿用逻辑幂等键，但旧 claim 的迟到结果不能覆盖新执行。"""
    from orchestrator import ledger as ledger_module

    clock = {"now": 2000.0}
    monkeypatch.setattr(ledger_module.time, "time", lambda: clock["now"])
    ledger = TaskLedger(tmp_path / "ledger.db")
    job_id = ledger.create_job("带 fencing 恢复", [{"title": "写外部系统"}])

    epoch1 = ledger.claim_job(job_id, "worker-1", lease_seconds=10)
    assert epoch1 is not None
    first = ledger.claim_next_step(job_id, "worker-1", epoch1, lease_seconds=10)
    assert first is not None

    clock["now"] += 11
    assert ledger.finish_claimed_step(
        first["id"],
        first["claim_token"],
        "done",
        owner="worker-1",
        epoch=epoch1,
        output="过期租约的结果",
    ) is False
    epoch2 = ledger.claim_job(job_id, "worker-2", lease_seconds=10)
    assert epoch2 is not None and epoch2 > epoch1
    second = ledger.claim_next_step(job_id, "worker-2", epoch2, lease_seconds=10)
    assert second is not None
    assert second["idempotency_key"] == first["idempotency_key"]
    assert second["claim_token"] != first["claim_token"]

    assert ledger.finish_claimed_step(
        first["id"],
        first["claim_token"],
        "done",
        owner="worker-1",
        epoch=epoch1,
        output="旧 worker 的迟到结果",
    ) is False
    assert ledger.finish_claimed_step(
        second["id"],
        second["claim_token"],
        "done",
        owner="worker-2",
        epoch=epoch2,
        output="新 worker 的结果",
    ) is True
    assert ledger.to_dict(job_id)["steps"][0]["output"] == "新 worker 的结果"
