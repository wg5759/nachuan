from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from orchestrator import inject


def test_injection_queue_is_bound_to_principal() -> None:
    inject.register("conv-a", "principal-a")
    token = inject.principal_var.set("principal-a")
    try:
        assert inject.push("conv-a", "from b", "principal-b") is False
        assert inject.push("conv-a", "approved supplement", "principal-a") is True
        assert inject.drain("conv-a") == ["approved supplement"]
    finally:
        inject.principal_var.reset(token)
        inject.unregister("conv-a", "principal-a")


def test_writable_run_rejects_steering_and_duplicate_registration() -> None:
    inject.register("conv-write", "principal-a", writable=True)
    try:
        assert inject.push("conv-write", "change the task", "principal-a") is False
        with pytest.raises(RuntimeError, match="已有运行"):
            inject.register("conv-write", "principal-a")
    finally:
        inject.unregister("conv-write", "principal-a")


def test_parallel_push_is_bounded_and_drained_without_loss_or_duplicates() -> None:
    inject.register("conv-threaded", "principal-a")
    token = inject.principal_var.set("principal-a")
    try:
        messages = [f"message-{idx}" for idx in range(64)]
        with ThreadPoolExecutor(max_workers=16) as pool:
            accepted = list(
                pool.map(
                    lambda message: inject.push(
                        "conv-threaded", message, "principal-a"
                    ),
                    messages,
                )
            )
        drained = inject.drain("conv-threaded")
        assert sum(accepted) == 16
        assert len(drained) == len(set(drained)) == 16
        assert set(drained) == {
            message for message, ok in zip(messages, accepted) if ok
        }
    finally:
        inject.principal_var.reset(token)
        inject.unregister("conv-threaded", "principal-a")


def test_multi_worker_deployment_is_rejected_explicitly(monkeypatch) -> None:
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    with pytest.raises(RuntimeError, match="single-process|\u5355进程"):
        inject.register("conv-multiprocess", "principal-a")
