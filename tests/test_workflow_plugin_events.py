from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.provider_plugins import build_builtin_provider_kernel
from orchestrator.durable_event_log import (
    DurableWorkflowEventLog,
    DurableWorkflowEventUnavailable,
)
from orchestrator.plugin_kernel import (
    EventContractError,
    PluginInUseError,
    PluginKernel,
)
from orchestrator.workflow_plugins import (
    BUILTIN_PIPELINE_WORKFLOW_MANIFEST,
    PIPELINE_WORKFLOW_SERVICE,
)
from orchestrator.workflows import pipeline


@pytest.mark.asyncio
async def test_durable_event_without_sink_fails_before_listener() -> None:
    kernel = PluginKernel()
    kernel.events.define(pipeline.PIPELINE_TURN_EVENT)
    seen: list[object] = []

    with pytest.raises(EventContractError, match="sink"):
        await kernel.events.emit(
            pipeline.PIPELINE_TURN_EVENT.name,
            {
                "workflow_id": "a" * 32,
                "phase": "started",
                "prompt_sha256": "b" * 64,
                "step_count": 1,
            },
        )
    assert seen == []


def test_durable_event_log_reopens_and_verifies_hash_chain(tmp_path) -> None:
    path = tmp_path / "workflow-events.db"
    first = DurableWorkflowEventLog(path)
    first.append_sync(
        pipeline.PIPELINE_TURN_EVENT.name,
        {
            "workflow_id": "a" * 32,
            "phase": "started",
            "prompt_sha256": "b" * 64,
            "step_count": 2,
        },
    )
    first.append_sync(
        pipeline.PIPELINE_RESULT_EVENT.name,
        {
            "workflow_id": "a" * 32,
            "phase": "completed",
            "outcome": "completed_unverified",
            "result_sha256": "c" * 64,
            "result_chars": 12,
        },
    )
    assert first.verify_chain() == 2
    first.close()

    reopened = DurableWorkflowEventLog(path)
    events = reopened.list_events("a" * 32)
    assert [item["event_name"] for item in events] == [
        pipeline.PIPELINE_TURN_EVENT.name,
        pipeline.PIPELINE_RESULT_EVENT.name,
    ]
    assert reopened.verify_chain() == 2
    reopened.close()


def test_durable_event_log_rejects_foreign_database_without_rewriting(tmp_path) -> None:
    path = tmp_path / "foreign.db"
    with sqlite3.connect(path) as foreign:
        foreign.execute("CREATE TABLE alien(value TEXT NOT NULL)")
        foreign.execute("INSERT INTO alien VALUES('preserve-me')")
        foreign.commit()
    before = path.read_bytes()

    with pytest.raises(DurableWorkflowEventUnavailable, match="initialize"):
        DurableWorkflowEventLog(path)

    assert path.read_bytes() == before
    assert not Path(f"{path}-wal").exists()
    assert not Path(f"{path}-shm").exists()
    with sqlite3.connect(path) as foreign:
        assert foreign.execute("SELECT value FROM alien").fetchone() == ("preserve-me",)


def test_durable_event_log_concurrent_append_keeps_one_valid_chain(tmp_path) -> None:
    log = DurableWorkflowEventLog(tmp_path / "concurrent.db")

    def append(index: int) -> None:
        log.append_sync(
            pipeline.PIPELINE_STEP_EVENT.name,
            {
                "workflow_id": "a" * 32,
                "phase": "completed",
                "step_index": index,
                "result_sha256": hashlib.sha256(str(index).encode()).hexdigest(),
                "result_chars": len(str(index)),
            },
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(32)))
    assert log.verify_chain() == 32
    assert len(log.list_events("a" * 32)) == 32
    log.close()


@pytest.mark.parametrize("forbidden", ["prompt", "instruction", "output", "content"])
def test_durable_event_log_rejects_raw_model_visible_fields(tmp_path, forbidden) -> None:
    log = DurableWorkflowEventLog(tmp_path / f"{forbidden}.db")
    with pytest.raises(DurableWorkflowEventUnavailable, match="payload"):
        log.append_sync(
            pipeline.PIPELINE_TURN_EVENT.name,
            {
                "workflow_id": "a" * 32,
                "phase": "started",
                forbidden: "raw customer text",
            },
        )
    log.close()


@pytest.mark.asyncio
async def test_pipeline_plugin_emits_durable_summary_events_and_holds_lease(
    monkeypatch,
) -> None:
    persisted: list[tuple[str, dict[str, object]]] = []

    async def sink(name: str, payload: object) -> None:
        assert isinstance(payload, dict)
        persisted.append((name, dict(payload)))

    kernel = build_builtin_provider_kernel(durable_event_sink=sink)
    assert BUILTIN_PIPELINE_WORKFLOW_MANIFEST.plugin_id in kernel.active_plugin_ids()
    lease = kernel.borrow_service(PIPELINE_WORKFLOW_SERVICE)

    class Provider:
        name = "fake-provider"

    route = SimpleNamespace(
        virtual_model="m1",
        provider=Provider(),
        upstream_model="upstream-1",
        tier="cheap",
        flagship=False,
        independence_domain="fake-domain",
    )
    calls = 0

    async def fake_ask(_router, requested_model, _messages, **_kwargs):
        nonlocal calls
        calls += 1
        route.virtual_model = requested_model
        response = {
            "model": requested_model,
            "choices": [{"message": {"content": f"result-{calls}"}}],
        }
        return response, requested_model, route

    monkeypatch.setattr(pipeline, "_ask_observed", fake_ask)
    service = lease.value
    result = await service(
        object(),
        prompt="private prompt",
        steps=[
            {"model": "m1", "instruction": "private instruction one"},
            {"model": "m2", "instruction": "private instruction two"},
        ],
    )
    assert result["final"] == "result-2"
    assert calls == 2
    assert [name for name, _payload in persisted] == [
        pipeline.PIPELINE_TURN_EVENT.name,
        pipeline.PIPELINE_STEP_EVENT.name,
        pipeline.PIPELINE_MODEL_EVENT.name,
        pipeline.PIPELINE_MODEL_EVENT.name,
        pipeline.PIPELINE_STEP_EVENT.name,
        pipeline.PIPELINE_STEP_EVENT.name,
        pipeline.PIPELINE_MODEL_EVENT.name,
        pipeline.PIPELINE_MODEL_EVENT.name,
        pipeline.PIPELINE_STEP_EVENT.name,
        pipeline.PIPELINE_RESULT_EVENT.name,
        pipeline.PIPELINE_TURN_EVENT.name,
    ]
    blob = str(persisted)
    assert "private prompt" not in blob
    assert "private instruction" not in blob
    assert "result-1" not in blob
    assert "result-2" not in blob
    assert hashlib.sha256(b"private prompt").hexdigest() in blob

    with pytest.raises(PluginInUseError):
        await kernel.unmount(BUILTIN_PIPELINE_WORKFLOW_MANIFEST.plugin_id)
    lease.release()
    await kernel.aclose()


@pytest.mark.asyncio
async def test_pipeline_plugin_durable_start_failure_prevents_model_call(
    monkeypatch,
) -> None:
    async def broken_sink(_name: str, _payload: object) -> None:
        raise DurableWorkflowEventUnavailable("simulated durable outage")

    calls = 0

    async def forbidden_model(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("model must not run before the durable start event")

    monkeypatch.setattr(pipeline, "_ask_observed", forbidden_model)
    kernel = build_builtin_provider_kernel(durable_event_sink=broken_sink)
    lease = kernel.borrow_service(PIPELINE_WORKFLOW_SERVICE)
    try:
        with pytest.raises(DurableWorkflowEventUnavailable, match="outage"):
            await lease.value(
                object(),
                prompt="private prompt",
                steps=[{"model": "m1", "instruction": "draft"}],
            )
    finally:
        lease.release()
        await kernel.aclose()
    assert calls == 0


def test_builtin_pipeline_manifest_binds_exact_workflow_plugin_source() -> None:
    source = Path(__file__).parents[1] / "orchestrator" / "workflows" / "pipeline.py"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == (
        BUILTIN_PIPELINE_WORKFLOW_MANIFEST.artifact_sha256
    )
