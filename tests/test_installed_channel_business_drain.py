from __future__ import annotations

import asyncio
import json
import queue

import pytest

from gateway.admission import (
    BackgroundJobLeasePool,
    BackgroundJobLimitExceeded,
    InstalledDrainAdmissionMiddleware,
    configure_installed_drain_fence,
)
from gateway.installed_channel_drain import (
    InstalledChildDrainFence,
    InstalledDrainBinding,
    InstalledDrainCommand,
    InstalledDrainOperation,
    InstalledDrainProtocol,
)
from gateway.installed_channel_child_drain_runtime import (
    InstalledChannelChildDrainRuntime,
    InstalledChannelChildDrainRuntimeError,
)
from gateway.installed_channel_supervisor_status import InstalledChannelProcessReceipt
from gateway.windows_installed_drain_pipe import (
    WindowsInstalledDrainPipeChildEndpoint,
    WindowsInstalledDrainPipeParentEndpoint,
    WindowsInstalledDrainPipeTimeout,
)


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
        pid=5100 + offset,
        started_utc_ticks=133_000_000_000_000_000 + offset,
        command_line_sha256=str(offset) * 64,
    )


async def _call_asgi(app, path: str) -> list[dict]:
    messages: list[dict] = []
    consumed = False

    async def receive() -> dict:
        nonlocal consumed
        if consumed:
            return {"type": "http.disconnect"}
        consumed = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8080),
        },
        receive,
        send,
    )
    return messages


@pytest.mark.asyncio
async def test_gateway_drain_blocks_new_business_but_finishes_existing_request() -> None:
    fence = InstalledChildDrainFence(
        binding=_binding(),
        role="engine",
        process=_process("engine"),
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    paths: list[str] = []

    async def downstream(scope, _receive, send) -> None:
        paths.append(str(scope["path"]))
        if scope["path"] != "/health":
            entered.set()
            await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = InstalledDrainAdmissionMiddleware(
        downstream,
        fence_provider=lambda: fence,
    )
    existing = asyncio.create_task(_call_asgi(middleware, "/v1/chat/completions"))
    await asyncio.wait_for(entered.wait(), timeout=1)

    receipt = fence.apply_command(
        InstalledDrainCommand(operation=_operation(), action="close_admission")
    )
    assert receipt.phase == "admission_closed"
    assert receipt.active_requests == 1

    rejected = await _call_asgi(middleware, "/v1/chat/completions")
    assert rejected[0]["status"] == 503
    assert json.loads(rejected[1]["body"])["detail"] == "service draining"
    assert paths == ["/v1/chat/completions"]

    health = await _call_asgi(middleware, "/health")
    assert health[0]["status"] == 200
    assert paths == ["/v1/chat/completions", "/health"]

    release.set()
    completed = await asyncio.wait_for(existing, timeout=1)
    assert completed[0]["status"] == 200
    assert fence.snapshot(operation=_operation()).phase == "drained"


def test_gateway_drain_blocks_new_background_jobs_until_existing_lease_finishes() -> None:
    fence = InstalledChildDrainFence(
        binding=_binding(),
        role="engine",
        process=_process("engine"),
    )
    configure_installed_drain_fence(fence)
    try:
        pool = BackgroundJobLeasePool(
            max_global=4,
            max_per_key=2,
            lease_ttl_seconds=300,
        )
        existing = pool.try_acquire(kind="video", bucket_hash="f" * 64)
        assert existing is not None

        receipt = fence.apply_command(
            InstalledDrainCommand(operation=_operation(), action="close_admission")
        )
        assert receipt.phase == "admission_closed"
        assert receipt.active_background_jobs == 1
        assert pool.try_acquire(kind="video", bucket_hash="f" * 64) is None

        assert pool.release(existing) is True
        assert fence.snapshot(operation=_operation()).phase == "drained"
    finally:
        configure_installed_drain_fence(None)


def test_gateway_drain_counts_restored_jobs_and_rejects_new_restore() -> None:
    fence = InstalledChildDrainFence(
        binding=_binding(),
        role="engine",
        process=_process("engine"),
    )
    configure_installed_drain_fence(fence)
    try:
        pool = BackgroundJobLeasePool(
            max_global=4,
            max_per_key=2,
            lease_ttl_seconds=300,
        )
        existing = pool.restore(
            kind="remote-video",
            bucket_hash="e" * 64,
            external_ids=("job-existing",),
        )
        receipt = fence.apply_command(
            InstalledDrainCommand(operation=_operation(), action="close_admission")
        )
        assert receipt.active_background_jobs == 1

        with pytest.raises(BackgroundJobLimitExceeded, match="draining"):
            pool.restore(
                kind="remote-video",
                bucket_hash="e" * 64,
                external_ids=("job-new",),
            )

        assert pool.release(existing) is True
        assert fence.snapshot(operation=_operation()).phase == "drained"
    finally:
        configure_installed_drain_fence(None)


class _LoopbackConnection:
    bootstrap_complete = True

    def __init__(self, incoming: queue.Queue[bytes], outgoing: queue.Queue[bytes]) -> None:
        self._incoming = incoming
        self._outgoing = outgoing
        self.aborted = False

    def send(self, frame: bytes, *, timeout_ms: int) -> None:
        self._outgoing.put(frame, timeout=timeout_ms / 1000)

    def receive(self, *, timeout_ms: int) -> bytes:
        return self._incoming.get(timeout=timeout_ms / 1000)

    def abort(self) -> None:
        self.aborted = True


def test_parent_snapshot_reprompts_child_until_existing_claim_drains() -> None:
    binding = _binding()
    process = _process("weixin")
    role_key = b"r" * 32
    parent_in: queue.Queue[bytes] = queue.Queue()
    child_in: queue.Queue[bytes] = queue.Queue()
    parent_connection = _LoopbackConnection(parent_in, child_in)
    child_connection = _LoopbackConnection(child_in, parent_in)
    parent = WindowsInstalledDrainPipeParentEndpoint(
        connection=parent_connection,
        protocol=InstalledDrainProtocol(
            role_key=role_key,
            binding=binding,
            role="weixin",
            process=process,
        ),
        timeout_ms=500,
    )
    child = WindowsInstalledDrainPipeChildEndpoint(
        connection=child_connection,
        protocol=InstalledDrainProtocol(
            role_key=role_key,
            binding=binding,
            role="weixin",
            process=process,
        ),
        timeout_ms=500,
    )
    fence = InstalledChildDrainFence(
        binding=binding,
        role="weixin",
        process=process,
    )
    claim = fence.try_begin_claim()
    assert claim is not None and fence.commit_claim(claim)
    runtime = InstalledChannelChildDrainRuntime(endpoint=child, fence=fence)
    runtime.start()

    operation = _operation()
    parent.request(InstalledDrainCommand(operation=operation, action="close_claims"))
    assert parent.snapshot(operation).phase == "claims_closed"
    fence.finish_claim(claim)
    assert parent.snapshot(operation).phase == "drained"

    parent.request(InstalledDrainCommand(operation=operation, action="exit"))
    assert parent.snapshot(operation).phase == "exit_requested"
    assert runtime.wait(timeout=1)
    runtime.raise_if_failed()
    assert parent_connection.aborted is False
    assert child_connection.aborted is False


def test_child_control_transport_failure_is_terminal_and_sets_exit_event() -> None:
    class FailedEndpoint:
        calls = 0

        def receive_command(self):
            self.calls += 1
            raise RuntimeError("transport unavailable")

        def send_receipt(self, _receipt) -> None:
            raise AssertionError("no receipt after receive failure")

    endpoint = FailedEndpoint()
    runtime = InstalledChannelChildDrainRuntime(
        endpoint=endpoint,
        fence=InstalledChildDrainFence(
            binding=_binding(),
            role="feishu",
            process=_process("feishu"),
        ),
    )
    runtime.start()

    assert runtime.wait(timeout=1)
    assert runtime.exit_event.is_set()
    with pytest.raises(InstalledChannelChildDrainRuntimeError, match="control failed"):
        runtime.raise_if_failed()
    assert endpoint.calls == 1


def test_child_control_safe_idle_read_timeout_does_not_end_runtime() -> None:
    operation = _operation()

    class IdleThenExitEndpoint:
        calls = 0
        receipts = []

        def receive_command(self):
            self.calls += 1
            if self.calls == 1:
                raise WindowsInstalledDrainPipeTimeout(
                    "pipe read timed out",
                    retry_safe=True,
                )
            return InstalledDrainCommand(operation=operation, action="exit")

        def send_receipt(self, receipt) -> None:
            self.receipts.append(receipt)

    endpoint = IdleThenExitEndpoint()
    fence = InstalledChildDrainFence(
        binding=_binding(),
        role="engine",
        process=_process("engine"),
    )
    fence.apply_command(
        InstalledDrainCommand(operation=operation, action="close_admission")
    )
    runtime = InstalledChannelChildDrainRuntime(endpoint=endpoint, fence=fence)
    runtime.start()

    assert runtime.wait(timeout=1)
    runtime.raise_if_failed()
    assert endpoint.calls == 2
    assert endpoint.receipts[-1].phase == "exit_requested"
