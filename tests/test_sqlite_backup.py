from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

import scripts.sqlite_backup as sqlite_backup_module
from scripts.sqlite_backup import BackupError, backup_databases, main, restore_databases


def _create_database(path, value: str) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE state (value TEXT NOT NULL)")
    connection.execute("INSERT INTO state VALUES (?)", (value,))
    connection.commit()
    return connection


def _read_value(path) -> str:
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute("SELECT value FROM state").fetchone()
    assert row is not None
    return str(row[0])


def _set_value(path, value: str) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("UPDATE state SET value = ?", (value,))
        connection.commit()


def test_backup_creates_verified_snapshot_from_open_database(tmp_path):
    data_dir = tmp_path / "data"
    backup_root = tmp_path / "backups"
    data_dir.mkdir()
    live_connection = _create_database(data_dir / "conversations.db", "before")

    result = backup_databases(data_dir, backup_root, keep=3)

    snapshot = result.snapshot_dir
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    assert _read_value(snapshot / "conversations.db") == "before"
    assert manifest["schema_version"] == 1
    assert manifest["database_count"] == 1
    assert manifest["databases"] == [
        {
            "name": "conversations.db",
            "size": (snapshot / "conversations.db").stat().st_size,
            "sha256": result.databases[0].sha256,
            "quick_check": "ok",
        }
    ]
    assert str(data_dir) not in (snapshot / "manifest.json").read_text(encoding="utf-8")
    assert not list(backup_root.glob(".*.tmp"))

    live_connection.close()


def test_backup_retention_removes_only_old_committed_snapshots(tmp_path):
    data_dir = tmp_path / "data"
    backup_root = tmp_path / "backups"
    data_dir.mkdir()
    connection = _create_database(data_dir / "memory.db", "one")

    first = backup_databases(data_dir, backup_root, keep=2)
    unmanaged = backup_root / "snapshot-manual-note"
    unmanaged.mkdir()
    (unmanaged / "README.txt").write_text("not managed by this tool", encoding="utf-8")
    second = backup_databases(data_dir, backup_root, keep=2)
    third = backup_databases(data_dir, backup_root, keep=2)

    committed = sorted(
        path for path in backup_root.iterdir() if (path / "manifest.json").is_file()
    )
    assert committed == sorted([second.snapshot_dir, third.snapshot_dir])
    assert third.removed_snapshots == (first.snapshot_dir,)
    assert (unmanaged / "README.txt").is_file()
    connection.close()


def test_restore_is_dry_run_by_default_and_safety_backs_up_apply(tmp_path):
    data_dir = tmp_path / "data"
    backup_root = tmp_path / "backups"
    safety_root = tmp_path / "pre-restore"
    data_dir.mkdir()
    connection = _create_database(data_dir / "ledger.db", "before")
    connection.close()
    snapshot = backup_databases(data_dir, backup_root)
    _set_value(data_dir / "ledger.db", "after")
    extra_connection = _create_database(data_dir / "newer.db", "newer")
    extra_connection.close()

    dry_run = restore_databases(snapshot.snapshot_dir, data_dir)

    assert dry_run.applied is False
    assert dry_run.safety_backup_dir is None
    assert dry_run.removed_databases == ("newer.db",)
    assert _read_value(data_dir / "ledger.db") == "after"
    assert _read_value(data_dir / "newer.db") == "newer"

    applied = restore_databases(
        snapshot.snapshot_dir,
        data_dir,
        apply=True,
        safety_backup_root=safety_root,
    )

    assert applied.applied is True
    assert _read_value(data_dir / "ledger.db") == "before"
    assert applied.safety_backup_dir is not None
    assert _read_value(applied.safety_backup_dir / "ledger.db") == "after"
    assert _read_value(applied.safety_backup_dir / "newer.db") == "newer"
    assert applied.removed_databases == ("newer.db",)
    assert not (data_dir / "newer.db").exists()


def test_restore_rejects_snapshot_whose_hash_was_tampered(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "usage.db", "trusted")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    with (snapshot.snapshot_dir / "usage.db").open("ab") as stream:
        stream.write(b"tampered")

    with pytest.raises(BackupError, match="(size|SHA-256) mismatch"):
        restore_databases(snapshot.snapshot_dir, data_dir)

    assert _read_value(data_dir / "usage.db") == "trusted"


def test_restore_rejects_manifest_path_traversal(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "cases.db", "current")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    manifest_path = snapshot.snapshot_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["databases"][0]["name"] = "../outside.db"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(BackupError, match="unsafe database name"):
        restore_databases(snapshot.snapshot_dir, data_dir, apply=True)

    assert _read_value(data_dir / "cases.db") == "current"
    assert not (tmp_path / "outside.db").exists()


def test_restore_rejects_symbolic_snapshot_path(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "knowledge.db", "current")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    linked_snapshot = tmp_path / "linked-snapshot"
    try:
        os.symlink(snapshot.snapshot_dir, linked_snapshot, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"this Windows account cannot create symlinks: {exc}")

    with pytest.raises(BackupError, match="symbolic links"):
        restore_databases(linked_snapshot, data_dir)

    assert _read_value(data_dir / "knowledge.db") == "current"


def test_cli_restore_defaults_to_verification_only(tmp_path, capsys):
    data_dir = tmp_path / "data"
    backup_root = tmp_path / "backups"
    data_dir.mkdir()
    connection = _create_database(data_dir / "scoreboard.db", "before")
    connection.close()

    assert main(["backup", "--data-dir", str(data_dir), "--backup-root", str(backup_root)]) == 0
    backup_output = json.loads(capsys.readouterr().out)
    _set_value(data_dir / "scoreboard.db", "after")

    assert main(["restore", backup_output["snapshot_dir"], "--data-dir", str(data_dir)]) == 0
    restore_output = json.loads(capsys.readouterr().out)
    assert restore_output["status"] == "verified"
    assert restore_output["applied"] is False
    assert _read_value(data_dir / "scoreboard.db") == "after"


def test_cli_verify_reports_recomputed_snapshot_evidence(tmp_path, capsys):
    data_dir = tmp_path / "data"
    backup_root = tmp_path / "backups"
    data_dir.mkdir()
    connection = _create_database(data_dir / "memory.db", "verified")
    connection.close()
    snapshot = backup_databases(data_dir, backup_root)

    assert main(["verify", str(snapshot.snapshot_dir)]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output == {
        "status": "verified",
        "snapshot_dir": str(snapshot.snapshot_dir),
        "snapshot_id": snapshot.snapshot_dir.name,
        "created_at": output["created_at"],
        "database_count": 1,
        "databases": ["memory.db"],
    }
    assert output["created_at"].endswith("Z")


def test_restore_recomputes_quick_check_after_hash_validation(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "approvals.db", "current")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    snapshot_database = snapshot.snapshot_dir / "approvals.db"
    corrupt_bytes = b"not a sqlite database"
    snapshot_database.write_bytes(corrupt_bytes)
    manifest_path = snapshot.snapshot_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["databases"][0]["size"] = len(corrupt_bytes)
    manifest["databases"][0]["sha256"] = hashlib.sha256(corrupt_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(BackupError, match="quick_check"):
        restore_databases(snapshot.snapshot_dir, data_dir)

    assert _read_value(data_dir / "approvals.db") == "current"


def test_apply_rolls_back_every_database_when_replace_fails(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    first = _create_database(data_dir / "a.db", "before-a")
    second = _create_database(data_dir / "b.db", "before-b")
    first.close()
    second.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    _set_value(data_dir / "a.db", "after-a")
    _set_value(data_dir / "b.db", "after-b")
    real_replace = os.replace

    def fail_second_install(source, destination):
        source_path = os.fspath(source)
        if source_path.endswith("b.db") and ".stage" in source_path:
            raise OSError("injected replace failure")
        return real_replace(source, destination)

    monkeypatch.setattr(sqlite_backup_module.os, "replace", fail_second_install)

    with pytest.raises(OSError, match="injected replace failure"):
        restore_databases(
            snapshot.snapshot_dir,
            data_dir,
            apply=True,
            safety_backup_root=tmp_path / "pre-restore",
        )

    assert _read_value(data_dir / "a.db") == "after-a"
    assert _read_value(data_dir / "b.db") == "after-b"
    residual_names = {path.name for path in data_dir.glob(".sqlite-restore-*")}
    assert any(name.endswith(".stage") for name in residual_names)
    assert any(name.endswith(".rollback") for name in residual_names)
    with pytest.raises(BackupError, match="incomplete restore state"):
        restore_databases(
            snapshot.snapshot_dir,
            data_dir,
            apply=True,
            safety_backup_root=tmp_path / "second-pre-restore",
        )
    assert {path.name for path in data_dir.glob(".sqlite-restore-*")} == residual_names


def test_restore_apply_rejects_residual_lock_but_dry_run_verifies(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "ledger.db", "before")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    _set_value(data_dir / "ledger.db", "after")
    lock_path = data_dir / ".sqlite-restore.lock"
    stale_contents = "pid=crashed\n"
    lock_path.write_text(stale_contents, encoding="utf-8")

    dry_run = restore_databases(snapshot.snapshot_dir, data_dir)

    assert dry_run.applied is False
    assert _read_value(data_dir / "ledger.db") == "after"
    with pytest.raises(BackupError, match="restore.*lock|lock.*restore"):
        restore_databases(
            snapshot.snapshot_dir,
            data_dir,
            apply=True,
            safety_backup_root=tmp_path / "pre-restore",
        )
    assert lock_path.read_text(encoding="utf-8") == stale_contents
    assert not (tmp_path / "pre-restore").exists()
    assert _read_value(data_dir / "ledger.db") == "after"


@pytest.mark.parametrize("suffix", ["rollback", "stage"])
def test_restore_apply_fails_closed_on_residual_artifact(tmp_path, suffix):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "ledger.db", "before")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    _set_value(data_dir / "ledger.db", "after")
    artifact = data_dir / f".sqlite-restore-abandoned.{suffix}"
    artifact.mkdir()
    marker = artifact / "operator-review-required.txt"
    marker.write_text("do not delete", encoding="utf-8")

    with pytest.raises(BackupError, match="incomplete restore state"):
        restore_databases(
            snapshot.snapshot_dir,
            data_dir,
            apply=True,
            safety_backup_root=tmp_path / "pre-restore",
        )

    assert marker.read_text(encoding="utf-8") == "do not delete"
    assert not (tmp_path / "pre-restore").exists()
    assert _read_value(data_dir / "ledger.db") == "after"
    assert not (data_dir / ".sqlite-restore.lock").exists()


def test_restore_lock_is_global_across_processes(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    connection = _create_database(data_dir / "ledger.db", "before")
    connection.close()
    snapshot = backup_databases(data_dir, tmp_path / "backups")
    _set_value(data_dir / "ledger.db", "after")
    project_root = Path(__file__).resolve().parents[1]
    child_code = """
import sys
from pathlib import Path
from scripts.sqlite_backup import _acquire_restore_lock, _release_restore_lock

lock = _acquire_restore_lock(Path(sys.argv[1]))
print("READY", flush=True)
sys.stdin.readline()
_release_restore_lock(*lock)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", child_code, str(data_dir)],
        cwd=project_root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "READY"
        with pytest.raises(BackupError, match="restore.*lock|lock.*restore"):
            restore_databases(
                snapshot.snapshot_dir,
                data_dir,
                apply=True,
                safety_backup_root=tmp_path / "pre-restore",
            )
        assert _read_value(data_dir / "ledger.db") == "after"
    finally:
        if process.stdin is not None:
            process.stdin.write("release\n")
            process.stdin.flush()
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    assert process.returncode == 0, process.stderr.read() if process.stderr else ""
    assert not (data_dir / ".sqlite-restore.lock").exists()
