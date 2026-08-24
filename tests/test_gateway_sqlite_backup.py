from __future__ import annotations

import asyncio
import ast
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

import gateway.app as gateway_app


def _test_app():
    return SimpleNamespace(
        state=SimpleNamespace(
            sqlite_backup_health=gateway_app._new_sqlite_backup_health()
        )
    )


@pytest.mark.asyncio
async def test_online_backup_captures_every_top_level_database_and_updates_health(
    tmp_path,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    first = sqlite3.connect(data_dir / "usage.db")
    first.execute("CREATE TABLE proof (value TEXT NOT NULL)")
    first.execute("INSERT INTO proof VALUES ('live')")
    first.commit()
    with closing(sqlite3.connect(data_dir / "memory.db")) as second:
        second.execute("CREATE TABLE proof (value TEXT NOT NULL)")
        second.execute("INSERT INTO proof VALUES ('second')")
        second.commit()
    nested = data_dir / "nested"
    nested.mkdir()
    with closing(sqlite3.connect(nested / "ignored.db")) as ignored:
        ignored.execute("CREATE TABLE proof (value TEXT NOT NULL)")

    target_app = _test_app()
    await gateway_app._run_sqlite_backup_once(target_app, data_dir)
    first.close()

    health = target_app.state.sqlite_backup_health
    snapshot = Path(health["snapshot_path"])
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    assert health["status"] == "ok"
    assert health["last_success_at"].endswith("Z")
    assert health["last_error"] is None
    assert health["database_count"] == 2
    assert snapshot.parent == data_dir / "backup" / "sqlite"
    assert {item["name"] for item in manifest["databases"]} == {
        "memory.db",
        "usage.db",
    }
    assert not (snapshot / "ignored.db").exists()


@pytest.mark.asyncio
async def test_online_backup_health_and_logs_redact_exception_message(tmp_path, caplog):
    secret = "sk-must-never-appear"

    def broken_backup(*_args, **_kwargs):
        raise RuntimeError(f"backup rejected {secret}")

    target_app = _test_app()
    await gateway_app._run_sqlite_backup_once(
        target_app,
        tmp_path,
        backup_fn=broken_backup,
    )

    raw = json.dumps(target_app.state.sqlite_backup_health)
    assert target_app.state.sqlite_backup_health["status"] == "degraded"
    assert target_app.state.sqlite_backup_health["last_error"] == "RuntimeError"
    assert secret not in raw
    assert secret not in caplog.text


def test_health_projection_exposes_snapshot_name_without_parent_path(monkeypatch, tmp_path):
    snapshot = tmp_path / "private-parent" / "snapshot-20260716T010203.000000Z-deadbeef"
    monkeypatch.setattr(
        gateway_app.app.state,
        "sqlite_backup_health",
        {
            "status": "ok",
            "last_attempt_at": "2026-07-16T01:02:03Z",
            "last_success_at": "2026-07-16T01:02:04Z",
            "last_error": None,
            "snapshot_path": str(snapshot),
            "database_count": 9,
        },
        raising=False,
    )

    projected = gateway_app._sqlite_backup_readiness()

    assert projected == {
        "ready": True,
        "status": "ok",
        "last_attempt_at": "2026-07-16T01:02:03Z",
        "last_success_at": "2026-07-16T01:02:04Z",
        "last_error": None,
        "snapshot": snapshot.name,
        "database_count": 9,
    }
    assert str(tmp_path) not in json.dumps(projected)


@pytest.mark.asyncio
async def test_backup_loop_uses_short_initial_delay_then_is_cancellable(tmp_path):
    delays: list[float] = []
    backed_up = asyncio.Event()
    parked = asyncio.Event()
    second_sleep = asyncio.Event()
    loop = asyncio.get_running_loop()

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)
        if len(delays) > 1:
            second_sleep.set()
            await parked.wait()

    def fake_backup(_data_dir, backup_root, *, keep):
        loop.call_soon_threadsafe(backed_up.set)
        return SimpleNamespace(
            snapshot_dir=Path(backup_root) / "snapshot-test",
            databases=(object(),),
        )

    target_app = _test_app()
    task = asyncio.create_task(
        gateway_app._sqlite_backup_loop(
            target_app,
            tmp_path,
            initial_delay_sec=0.25,
            interval_sec=99,
            backup_fn=fake_backup,
            sleep_fn=fake_sleep,
        )
    )
    await asyncio.wait_for(backed_up.wait(), timeout=2)
    await asyncio.wait_for(second_sleep.wait(), timeout=2)
    assert delays == [0.25, 99.0]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_frozen_build_has_static_sqlite_backup_import_and_hidden_import():
    project_root = Path(__file__).resolve().parents[1]
    tree = ast.parse((project_root / "gateway" / "app.py").read_text(encoding="utf-8"))
    assert any(
        isinstance(node, ast.ImportFrom)
        and node.module == "scripts.sqlite_backup"
        and any(alias.name == "backup_databases" for alias in node.names)
        for node in ast.walk(tree)
    )
    assert (project_root / "scripts" / "__init__.py").is_file()
    spec = (project_root / "engine.spec").read_text(encoding="utf-8")
    assert "'scripts.sqlite_backup'" in spec
