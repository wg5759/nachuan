"""Consistent, verifiable backups for Nachuan's top-level SQLite databases.

This module deliberately has no dependency on the gateway process so operators can
run it while diagnosing or recovering a failed installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import unicodedata
import uuid
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence


MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1
_SNAPSHOT_ID_PATTERN = re.compile(r"snapshot-\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{8}")
_RESTORE_TRANSACTION_PATTERN = re.compile(r"\.sqlite-restore-.*\.(?:rollback|stage)")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class BackupError(RuntimeError):
    """The requested backup or restore operation could not be completed safely."""


@dataclass(frozen=True)
class DatabaseRecord:
    name: str
    size: int
    sha256: str
    quick_check: str


@dataclass(frozen=True)
class BackupResult:
    snapshot_dir: Path
    databases: tuple[DatabaseRecord, ...]
    removed_snapshots: tuple[Path, ...] = ()


@dataclass(frozen=True)
class SnapshotValidation:
    snapshot_dir: Path
    snapshot_id: str
    created_at: str
    databases: tuple[DatabaseRecord, ...]


@dataclass(frozen=True)
class RestoreResult:
    snapshot_dir: Path
    applied: bool
    databases: tuple[DatabaseRecord, ...]
    safety_backup_dir: Path | None = None
    removed_databases: tuple[str, ...] = ()


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _assert_path_has_no_links(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if _is_link(current):
            raise BackupError(f"symbolic links and junctions are not allowed: {current}")


def _assert_descendant(path: Path, root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if resolved_path == resolved_root or not resolved_path.is_relative_to(resolved_root):
        raise BackupError(f"path escapes managed backup root: {path}")


def _assert_tree_has_no_symlinks(path: Path) -> None:
    if _is_link(path):
        raise BackupError(f"symbolic links are not allowed: {path}")
    pending = [path]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                child = Path(entry.path)
                if _is_link(child):
                    raise BackupError(f"symbolic links are not allowed: {child}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(child)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prune_snapshots(root: Path, keep: int) -> tuple[Path, ...]:
    committed: list[Path] = []
    for child in root.iterdir():
        if not _SNAPSHOT_ID_PATTERN.fullmatch(child.name):
            continue
        if _is_link(child):
            raise BackupError(f"symbolic snapshot is not allowed: {child}")
        manifest = child / MANIFEST_NAME
        if child.is_dir():
            _assert_tree_has_no_symlinks(child)
        if child.is_dir() and manifest.is_file() and not _is_link(manifest):
            _assert_descendant(child, root)
            committed.append(child)
    committed.sort(key=lambda path: path.name)
    removed: list[Path] = []
    for old_snapshot in committed[:-keep]:
        shutil.rmtree(old_snapshot)
        removed.append(old_snapshot)
    return tuple(removed)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _quick_check(path: Path) -> str:
    # Snapshots are immutable inputs.  This prevents SQLite from creating WAL
    # shared-memory sidecars merely while validating a backup.
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=30)) as connection:
            rows = connection.execute("PRAGMA quick_check").fetchall()
    except sqlite3.Error as exc:
        raise BackupError(f"SQLite quick_check failed for {path.name}: {exc}") from exc
    result = "\n".join(str(row[0]) for row in rows)
    if result != "ok":
        raise BackupError(f"SQLite quick_check rejected {path.name}: {result}")
    return result


def _backup_one(source_path: Path, destination_path: Path) -> DatabaseRecord:
    source_uri = source_path.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as source:
            with closing(sqlite3.connect(destination_path, timeout=30)) as destination:
                source.backup(destination)
                journal_mode = destination.execute("PRAGMA journal_mode=DELETE").fetchone()
                if not journal_mode or str(journal_mode[0]).lower() != "delete":
                    raise BackupError(f"could not close WAL mode in snapshot {source_path.name}")
    except sqlite3.Error as exc:
        raise BackupError(f"SQLite backup failed for {source_path.name}: {exc}") from exc

    quick_check = _quick_check(destination_path)
    with destination_path.open("rb+") as stream:
        os.fsync(stream.fileno())
    return DatabaseRecord(
        name=source_path.name,
        size=destination_path.stat().st_size,
        sha256=_sha256(destination_path),
        quick_check=quick_check,
    )


def backup_databases(
    data_dir: str | os.PathLike[str],
    backup_root: str | os.PathLike[str],
    *,
    keep: int = 14,
) -> BackupResult:
    """Back up every top-level ``*.db`` with SQLite's online backup API."""

    if keep < 1:
        raise ValueError("keep must be at least 1")
    source_dir = Path(data_dir)
    root = Path(backup_root)
    _assert_path_has_no_links(source_dir)
    _assert_path_has_no_links(root)
    if not source_dir.is_dir():
        raise BackupError(f"data directory does not exist: {source_dir}")
    databases = sorted(source_dir.glob("*.db"), key=lambda path: path.name.casefold())
    if not databases:
        raise BackupError(f"no top-level SQLite databases found in {source_dir}")
    for database in databases:
        if _is_link(database) or not database.is_file():
            raise BackupError(f"database must be a regular non-link file: {database}")

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_path_has_no_links(root)
    created_at = datetime.now(UTC)
    snapshot_id = f"snapshot-{created_at:%Y%m%dT%H%M%S.%fZ}-{uuid.uuid4().hex[:8]}"
    final_dir = root / snapshot_id
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{snapshot_id}.", suffix=".tmp", dir=root))
    try:
        records = tuple(_backup_one(path, staging_dir / path.name) for path in databases)
        final_source_names = {path.name for path in source_dir.glob("*.db")}
        if final_source_names != {path.name for path in databases}:
            raise BackupError("database set changed during backup; retry the snapshot")
        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "snapshot_id": snapshot_id,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "database_count": len(records),
            "databases": [asdict(record) for record in records],
        }
        manifest_path = staging_dir / MANIFEST_NAME
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with manifest_path.open("rb+") as stream:
            os.fsync(stream.fileno())
        _fsync_directory(staging_dir)
        # Destination is unique and must not exist.  ``rename`` is an atomic
        # same-volume directory commit; unlike ``os.replace`` it also works for
        # directories on Windows.
        os.rename(staging_dir, final_dir)
        _fsync_directory(root)
    except Exception:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise

    removed = _prune_snapshots(root, keep)
    return BackupResult(snapshot_dir=final_dir, databases=records, removed_snapshots=removed)


def _json_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError(f"duplicate JSON key in manifest: {key}")
        result[key] = value
    return result


def _validate_database_name(name: object) -> str:
    if not isinstance(name, str) or not name.endswith(".db"):
        raise BackupError("manifest database name must end in .db")
    if not name or Path(name).name != name or "/" in name or "\\" in name:
        raise BackupError(f"manifest contains an unsafe database name: {name!r}")
    if name in {".", ".."} or "\x00" in name:
        raise BackupError(f"manifest contains an unsafe database name: {name!r}")
    if name.endswith((" ", ".")) or ":" in name or any(ord(character) < 32 for character in name):
        raise BackupError(f"manifest contains an unsafe database name: {name!r}")
    if name.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        raise BackupError(f"manifest contains a reserved database name: {name!r}")
    return name


def _record_from_manifest(raw: object) -> DatabaseRecord:
    if not isinstance(raw, dict):
        raise BackupError("manifest database entry must be an object")
    expected_keys = {"name", "size", "sha256", "quick_check"}
    if set(raw) != expected_keys:
        raise BackupError("manifest database entry has missing or unexpected fields")
    name = _validate_database_name(raw["name"])
    size = raw["size"]
    sha256 = raw["sha256"]
    quick_check = raw["quick_check"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise BackupError(f"manifest has an invalid size for {name}")
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise BackupError(f"manifest has an invalid SHA-256 for {name}")
    if quick_check != "ok":
        raise BackupError(f"manifest records a failed quick_check for {name}")
    return DatabaseRecord(name=name, size=size, sha256=sha256, quick_check=quick_check)


def _validate_database_file(path: Path, record: DatabaseRecord) -> None:
    if _is_link(path) or not path.is_file():
        raise BackupError(f"snapshot database must be a regular non-link file: {record.name}")
    if path.stat().st_size != record.size:
        raise BackupError(f"size mismatch for snapshot database {record.name}")
    if _sha256(path) != record.sha256:
        raise BackupError(f"SHA-256 mismatch for snapshot database {record.name}")
    _quick_check(path)


def validate_snapshot(snapshot_dir: str | os.PathLike[str]) -> SnapshotValidation:
    """Validate a snapshot's closed manifest, hashes, and SQLite quick checks."""

    snapshot = Path(snapshot_dir)
    _assert_path_has_no_links(snapshot)
    if not snapshot.is_dir():
        raise BackupError(f"snapshot directory does not exist: {snapshot}")
    _assert_tree_has_no_symlinks(snapshot)
    manifest_path = snapshot / MANIFEST_NAME
    if not manifest_path.is_file() or _is_link(manifest_path):
        raise BackupError("snapshot manifest is missing or is not a regular file")
    if manifest_path.stat().st_size > 1024 * 1024:
        raise BackupError("snapshot manifest exceeds the 1 MiB safety limit")
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_json_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BackupError(f"invalid snapshot manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BackupError("snapshot manifest root must be an object")
    expected_keys = {"schema_version", "snapshot_id", "created_at", "database_count", "databases"}
    if set(manifest) != expected_keys:
        raise BackupError("snapshot manifest has missing or unexpected fields")
    if manifest["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise BackupError(f"unsupported manifest schema: {manifest['schema_version']!r}")
    snapshot_id = manifest["snapshot_id"]
    created_at = manifest["created_at"]
    if not isinstance(snapshot_id, str) or not _SNAPSHOT_ID_PATTERN.fullmatch(snapshot_id):
        raise BackupError("snapshot manifest has an invalid snapshot_id")
    if not isinstance(created_at, str) or not created_at.endswith("Z"):
        raise BackupError("snapshot manifest has an invalid created_at")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BackupError("snapshot manifest has an invalid created_at") from exc
    raw_databases = manifest["databases"]
    if not isinstance(raw_databases, list) or not raw_databases:
        raise BackupError("snapshot manifest must contain at least one database")
    records = tuple(_record_from_manifest(raw) for raw in raw_databases)
    database_count = manifest["database_count"]
    if isinstance(database_count, bool) or not isinstance(database_count, int):
        raise BackupError("snapshot database_count must be an integer")
    if database_count != len(records):
        raise BackupError("snapshot database_count does not match its entries")
    names = [unicodedata.normalize("NFC", record.name).casefold() for record in records]
    if len(names) != len(set(names)):
        raise BackupError("snapshot manifest contains duplicate database names")

    allowed_files = {MANIFEST_NAME, *(record.name for record in records)}
    actual_files = {child.name for child in snapshot.iterdir()}
    if actual_files != allowed_files:
        raise BackupError("snapshot contains missing or unexpected files")
    for record in records:
        _validate_database_file(snapshot / record.name, record)
    return SnapshotValidation(
        snapshot_dir=snapshot,
        snapshot_id=snapshot_id,
        created_at=created_at,
        databases=records,
    )


def _assert_no_sqlite_sidecars(data_dir: Path, names: set[str]) -> None:
    sidecars: set[Path] = set()
    for name in names:
        database = data_dir / name
        for suffix in ("-wal", "-shm", "-journal"):
            sidecars.add(Path(f"{database}{suffix}"))
    for pattern in ("*.db-wal", "*.db-shm", "*.db-journal"):
        sidecars.update(data_dir.glob(pattern))
    for sidecar in sorted(sidecars, key=lambda path: path.name.casefold()):
        if sidecar.exists() or _is_link(sidecar):
            raise BackupError(
                f"refusing restore while SQLite sidecar exists ({sidecar.name}); stop the engine first"
            )


def _assert_databases_quiescent(databases: list[Path]) -> None:
    for database in databases:
        try:
            with closing(sqlite3.connect(database, timeout=0.1, isolation_level=None)) as connection:
                connection.execute("BEGIN EXCLUSIVE")
                connection.execute("ROLLBACK")
        except sqlite3.Error as exc:
            raise BackupError(f"database is busy; stop the engine before restore: {database.name}") from exc


def _checkpoint_for_replace(databases: list[Path]) -> None:
    """Fold any committed WAL into the current file after its safety backup."""

    for database in databases:
        try:
            with closing(sqlite3.connect(database, timeout=0.1, isolation_level=None)) as connection:
                checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if checkpoint and int(checkpoint[0]) != 0:
                    raise BackupError(f"database WAL is busy: {database.name}")
                mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
                if not mode or str(mode[0]).lower() != "delete":
                    raise BackupError(f"could not close WAL mode for {database.name}")
        except sqlite3.Error as exc:
            raise BackupError(f"could not prepare database for restore: {database.name}") from exc


def _assert_no_incomplete_restore_state(data_dir: Path, *, include_lock: bool) -> None:
    """Fail closed when a previous restore left operator-reviewable evidence.

    These artifacts can contain the only recoverable copy of a database after a
    power loss.  Never delete them or infer which side of the transaction won.
    """

    artifacts: list[Path] = []
    lock_path = data_dir / ".sqlite-restore.lock"
    if include_lock and (lock_path.exists() or _is_link(lock_path)):
        artifacts.append(lock_path)
    for child in data_dir.iterdir():
        if _RESTORE_TRANSACTION_PATTERN.fullmatch(child.name):
            artifacts.append(child)
    if artifacts:
        names = ", ".join(
            repr(path.name) for path in sorted(artifacts, key=lambda path: path.name)
        )
        raise BackupError(
            "incomplete restore state detected; manual inspection is required and no artifacts "
            f"were removed: {names}"
        )


def _acquire_restore_lock(data_dir: Path) -> tuple[int, Path]:
    """Acquire a crash-persistent, filesystem-global restore lock.

    ``O_EXCL`` makes acquisition atomic across processes and Windows sessions.
    Keeping the sentinel on disk also turns a crashed owner into an explicit
    fail-closed state instead of guessing that an old PID is safe to ignore.
    """

    _assert_no_incomplete_restore_state(data_dir, include_lock=True)
    lock_path = data_dir / ".sqlite-restore.lock"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise BackupError(f"another restore may be running; lock exists: {lock_path}") from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        _fsync_directory(data_dir)
        # Close the race between the first preflight scan and atomic lock
        # creation.  Cooperative restore processes cannot create artifacts now;
        # anything found here is abandoned or from an unsafe external writer.
        _assert_no_incomplete_restore_state(data_dir, include_lock=False)
    except Exception:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)
        _fsync_directory(data_dir)
        raise
    return descriptor, lock_path


def _release_restore_lock(descriptor: int, lock_path: Path) -> None:
    os.close(descriptor)
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass
    _fsync_directory(lock_path.parent)


def _stage_restore(validation: SnapshotValidation, stage_dir: Path) -> None:
    for record in validation.databases:
        source = validation.snapshot_dir / record.name
        destination = stage_dir / record.name
        shutil.copyfile(source, destination)
        with destination.open("rb+") as stream:
            os.fsync(stream.fileno())
        _validate_database_file(destination, record)


def _replace_databases(
    data_dir: Path,
    validation: SnapshotValidation,
    stage_dir: Path,
    rollback_dir: Path,
) -> tuple[str, ...]:
    current = sorted(data_dir.glob("*.db"), key=lambda path: path.name.casefold())
    current_names = {path.name for path in current}
    restored_names = {record.name for record in validation.databases}
    moved: list[Path] = []
    installed: list[Path] = []
    try:
        rollback_dir.mkdir(mode=0o700)
        for database in current:
            if _is_link(database) or not database.is_file():
                raise BackupError(f"target database is not a regular file: {database.name}")
            os.replace(database, rollback_dir / database.name)
            moved.append(database)
        for record in validation.databases:
            destination = data_dir / record.name
            if destination.exists() or _is_link(destination):
                raise BackupError(f"target appeared during restore: {record.name}")
            os.replace(stage_dir / record.name, destination)
            installed.append(destination)
        for record in validation.databases:
            _validate_database_file(data_dir / record.name, record)
        _fsync_directory(data_dir)
    except Exception as original_error:
        rollback_errors: list[str] = []
        for destination in reversed(installed):
            try:
                if destination.exists():
                    os.replace(destination, stage_dir / f"failed-{destination.name}")
            except OSError as exc:
                rollback_errors.append(f"remove {destination.name}: {exc}")
        for destination in reversed(moved):
            try:
                saved = rollback_dir / destination.name
                if saved.exists():
                    if destination.exists() or _is_link(destination):
                        os.replace(destination, stage_dir / f"conflict-{destination.name}")
                    os.replace(saved, destination)
            except OSError as exc:
                rollback_errors.append(f"restore {destination.name}: {exc}")
        if rollback_errors:
            raise BackupError(
                f"restore failed and rollback was incomplete: {'; '.join(rollback_errors)}"
            ) from original_error
        _fsync_directory(data_dir)
        raise
    return tuple(sorted(current_names - restored_names, key=str.casefold))


def restore_databases(
    snapshot_dir: str | os.PathLike[str],
    data_dir: str | os.PathLike[str],
    *,
    apply: bool = False,
    safety_backup_root: str | os.PathLike[str] | None = None,
    safety_keep: int = 14,
) -> RestoreResult:
    """Verify a full snapshot and optionally replace the target database set.

    The default is a verification-only dry run.  Applying a restore requires an
    explicit flag and always creates a full safety snapshot of the current state.
    """

    target_dir = Path(data_dir)
    _assert_path_has_no_links(target_dir)
    if not target_dir.is_dir():
        raise BackupError(f"data directory does not exist: {target_dir}")
    if target_dir.resolve() == Path(snapshot_dir).resolve():
        raise BackupError("snapshot directory and target data directory must be different")

    if not apply:
        # Verification is deliberately independent from target restore locks and
        # abandoned transactions because it has no side effects on the target.
        validation = validate_snapshot(snapshot_dir)
        current = sorted(target_dir.glob("*.db"), key=lambda path: path.name.casefold())
        for database in current:
            if _is_link(database) or not database.is_file():
                raise BackupError(
                    f"target database must be a regular non-link file: {database}"
                )
        planned_removed = tuple(
            sorted(
                {path.name for path in current} - {record.name for record in validation.databases},
                key=str.casefold,
            )
        )
        return RestoreResult(
            snapshot_dir=validation.snapshot_dir,
            applied=False,
            databases=validation.databases,
            removed_databases=planned_removed,
        )
    if safety_keep < 1:
        raise ValueError("safety_keep must be at least 1")

    descriptor, lock_path = _acquire_restore_lock(target_dir)
    try:
        validation = validate_snapshot(snapshot_dir)
        current = sorted(target_dir.glob("*.db"), key=lambda path: path.name.casefold())
        for database in current:
            if _is_link(database) or not database.is_file():
                raise BackupError(
                    f"target database must be a regular non-link file: {database}"
                )
        if not current:
            raise BackupError(
                "refusing applied restore without a current database set to safety-backup"
            )

        safety_root = (
            Path(safety_backup_root)
            if safety_backup_root
            else target_dir / "backup" / "pre-restore"
        )
        _assert_path_has_no_links(safety_root)
        resolved_safety_root = safety_root.resolve()
        resolved_snapshot = validation.snapshot_dir.resolve()
        if resolved_safety_root == resolved_snapshot.parent:
            raise BackupError("safety backups must use a different root from the restore snapshot")
        if resolved_safety_root == resolved_snapshot or resolved_safety_root.is_relative_to(
            resolved_snapshot
        ):
            raise BackupError("safety backup root must not be inside the restore snapshot")

        all_names = {path.name for path in current} | {
            record.name for record in validation.databases
        }
        _assert_databases_quiescent(current)
        safety = backup_databases(target_dir, safety_root, keep=safety_keep)
        if {path.name for path in target_dir.glob("*.db")} != {path.name for path in current}:
            raise BackupError("database set changed while preparing restore")
        _assert_databases_quiescent(current)
        _checkpoint_for_replace(current)
        _assert_no_sqlite_sidecars(target_dir, all_names)

        transaction_id = uuid.uuid4().hex
        stage_dir = Path(
            tempfile.mkdtemp(
                prefix=f".sqlite-restore-{transaction_id}-",
                suffix=".stage",
                dir=target_dir,
            )
        )
        rollback_dir = target_dir / f".sqlite-restore-{transaction_id}.rollback"
        _stage_restore(validation, stage_dir)
        removed = _replace_databases(target_dir, validation, stage_dir, rollback_dir)
        shutil.rmtree(rollback_dir)
        shutil.rmtree(stage_dir)
        return RestoreResult(
            snapshot_dir=validation.snapshot_dir,
            applied=True,
            databases=validation.databases,
            safety_backup_dir=safety.snapshot_dir,
            removed_databases=removed,
        )
    finally:
        # Transaction directories are removed only on a confirmed successful
        # restore above.  On any exception they are recovery evidence and must
        # survive for explicit operator inspection.
        _release_restore_lock(descriptor, lock_path)


def _build_parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    default_data_dir = project_root / "data"
    parser = argparse.ArgumentParser(
        description="Create and restore verified full SQLite snapshots for Nachuan.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup", help="back up every top-level data/*.db")
    backup_parser.add_argument("--data-dir", type=Path, default=default_data_dir)
    backup_parser.add_argument("--backup-root", type=Path)
    backup_parser.add_argument("--keep", type=int, default=14)

    verify_parser = subparsers.add_parser(
        "verify",
        help="recompute a snapshot's manifest, hashes, and SQLite quick checks",
    )
    verify_parser.add_argument("snapshot_dir", type=Path)

    restore_parser = subparsers.add_parser(
        "restore",
        help="verify a snapshot; add --apply only after stopping the engine",
    )
    restore_parser.add_argument("snapshot_dir", type=Path)
    restore_parser.add_argument("--data-dir", type=Path, default=default_data_dir)
    restore_parser.add_argument(
        "--apply",
        action="store_true",
        help="replace databases after first creating a pre-restore safety snapshot",
    )
    restore_parser.add_argument("--safety-backup-root", type=Path)
    restore_parser.add_argument("--safety-keep", type=int, default=14)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "backup":
            backup_root = args.backup_root or args.data_dir / "backup" / "sqlite"
            result = backup_databases(args.data_dir, backup_root, keep=args.keep)
            output = {
                "status": "backed_up",
                "snapshot_dir": str(result.snapshot_dir),
                "database_count": len(result.databases),
                "databases": [record.name for record in result.databases],
                "removed_snapshots": [str(path) for path in result.removed_snapshots],
            }
        elif args.command == "verify":
            validation = validate_snapshot(args.snapshot_dir)
            output = {
                "status": "verified",
                "snapshot_dir": str(validation.snapshot_dir),
                "snapshot_id": validation.snapshot_id,
                "created_at": validation.created_at,
                "database_count": len(validation.databases),
                "databases": [record.name for record in validation.databases],
            }
        else:
            result = restore_databases(
                args.snapshot_dir,
                args.data_dir,
                apply=args.apply,
                safety_backup_root=args.safety_backup_root,
                safety_keep=args.safety_keep,
            )
            output = {
                "status": "restored" if result.applied else "verified",
                "applied": result.applied,
                "snapshot_dir": str(result.snapshot_dir),
                "database_count": len(result.databases),
                "databases": [record.name for record in result.databases],
                "safety_backup_dir": str(result.safety_backup_dir) if result.safety_backup_dir else None,
                "removed_databases": list(result.removed_databases),
            }
    except (BackupError, OSError, ValueError) as exc:
        import sys

        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
