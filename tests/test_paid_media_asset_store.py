from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

import gateway.paid_media_asset_store as paid_media_asset_store
from gateway.paid_media_asset_protocol import (
    ACK_SCHEMA,
    PaidMediaAssetProtocolError,
    PaidMediaAssetResult,
    asset_token_hash,
    asset_result_document,
)
from gateway.paid_media_asset_store import (
    OPERATION_RESERVATION_BYTES,
    PaidMediaAssetAuthorizationError,
    PaidMediaAssetCapacityError,
    PaidMediaAssetConflictError,
    PaidMediaAssetRootCommitPending,
    PaidMediaAssetStore,
    PaidMediaAssetStoreDependencies,
    PaidMediaAssetStoreError,
)
from gateway.trusted_media_probe import TrustedMediaProbeResult


INSTALLATION_ID = "1" * 64
DATABASE_IDENTITY = "d" * 64
PRINCIPAL = "2" * 64
TURN = "3" * 64


def _database_family(path: Path) -> dict[str, bytes | None]:
    return {
        suffix: candidate.read_bytes() if candidate.exists() else None
        for suffix in ("", "-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
    }


def _run_isolated_python(script: str, path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script, os.fspath(path)],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _create_abandoned_foreign_hot_wal(path: Path) -> None:
    created = _run_isolated_python(
        """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
connection.execute('BEGIN IMMEDIATE')
connection.execute('CREATE TABLE alien(value TEXT NOT NULL)')
connection.execute("INSERT INTO alien(value) VALUES('foreign-hot-wal')")
connection.commit()
os._exit(0)
""",
        path,
    )
    assert created.returncode == 0, (created.stdout, created.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def _create_abandoned_current_hot_wal(path: Path) -> None:
    created = _run_isolated_python(
        """
import os, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
assert connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() == 'wal'
connection.execute('PRAGMA wal_autocheckpoint=0')
assert connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0
connection.execute('BEGIN IMMEDIATE')
connection.execute(
    'UPDATE asset_store_meta SET max_capacity_bytes=max_capacity_bytes WHERE singleton=1'
)
connection.commit()
os._exit(0)
""",
        path,
    )
    assert created.returncode == 0, (created.stdout, created.stderr)
    assert path.is_file()
    assert Path(f"{path}-wal").is_file()
    assert Path(f"{path}-shm").is_file()


def _inject_reserved_prefix_view(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "INSERT INTO sqlite_master(type,name,tbl_name,rootpage,sql) "
            "VALUES('view','sqlite_nachuan_unauthorized',"
            "'sqlite_nachuan_unauthorized',0,"
            "'CREATE VIEW sqlite_nachuan_unauthorized AS SELECT 1 AS injected_value')"
        )
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")


def _tamper_internal_tbl_name(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        name, original = connection.execute(
            "SELECT name,tbl_name FROM sqlite_master "
            "WHERE name LIKE 'sqlite_autoindex_%' ORDER BY name LIMIT 1"
        ).fetchone()
        replacement = "asset_store_meta" if original != "asset_store_meta" else "asset_reservations"
        schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET tbl_name=? WHERE name=?",
            (replacement, name),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")


def _dependencies(
    *,
    capacity: int | None = None,
    clock=lambda: time.time(),  # noqa: B008
    after_object_replace=lambda _path: None,  # noqa: B008
) -> PaidMediaAssetStoreDependencies:
    def harden(path: Path, directory: bool) -> None:
        os.chmod(path, 0o700 if directory else 0o600)

    def assert_acl(path: Path, directory: bool) -> None:
        info = os.lstat(path)
        assert directory == Path(path).is_dir()
        if os.name != "nt":
            assert info.st_mode & 0o077 == 0

    return PaidMediaAssetStoreDependencies(
        assert_acl=assert_acl,
        harden_acl=harden,
        disk_free=lambda _path: capacity
        if capacity is not None
        else 16 * 1024 * 1024 * 1024,
        clock=clock,
        after_object_replace=after_object_replace,
    )


def _store(tmp_path: Path, *, max_capacity: int | None = None) -> PaidMediaAssetStore:
    return PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=max_capacity or 2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )


def _probe(
    path: str | os.PathLike[str],
    *,
    expected_media_type: str,
    expected_byte_length: int,
    expected_sha256: str,
    **_kwargs: object,
) -> TrustedMediaProbeResult:
    assert Path(path).stat().st_size == expected_byte_length
    assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected_sha256
    return TrustedMediaProbeResult(
        media_type=expected_media_type,
        detected_kind="image" if expected_media_type.startswith("image/") else "video",
        byte_length=expected_byte_length,
        sha256=expected_sha256,
        codec_name="png",
        audio_codec_name=None,
        video_stream_count=1,
        audio_stream_count=0,
        format_name="png_pipe",
        width=1,
        height=1,
        duration_ms=None,
        decoded_frames=1,
        ffmpeg_sha256="4" * 64,
        ffprobe_sha256="5" * 64,
    )


def _reserve(store: PaidMediaAssetStore, *, turn: str = TURN) -> None:
    store.reserve(
        turn_id=turn,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )


def _write_abandoned_probe_cache(
    store: PaidMediaAssetStore,
    *,
    installation_id: str,
    epoch: int,
    database_identity: str,
    generation: str,
    leaf: str = "nachuan-media-cache-deadbeef",
) -> Path:
    directory = store.staging_directory / leaf
    directory.mkdir(mode=0o700)
    store.dependencies.harden_acl(directory, True)
    marker = directory / ".nachuan-media-cache-owner.v1.json"
    marker.write_text(
        json.dumps(
            {
                "database_identity": database_identity,
                "epoch": epoch,
                "generation": generation,
                "installation_id": installation_id,
                "schema": "nachuan.trusted-media-cache-owner.v1",
            },
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    store.dependencies.harden_acl(marker, False)
    cache_file = directory / "ffcache.bin"
    cache_file.write_bytes(b"abandoned-paid-media-cache")
    store.dependencies.harden_acl(cache_file, False)
    return directory


def _committed(
    store: PaidMediaAssetStore,
    *,
    payload: bytes = b"strict-file-backed-image",
) -> tuple[dict[str, object], object]:
    _reserve(store)
    encoded = base64.b64encode(payload).decode("ascii")
    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(encoded[:3], encoded[3:9], encoded[9:]),
        probe=_probe,
    )
    result = PaidMediaAssetResult(
        kind="image",
        created=1_784_200_000,
        turn_id=TURN,
        assets=(descriptor,),
    )
    store.finalize_result(result)
    return asset_result_document(result), descriptor


def _ack(document: dict[str, object], receipt: str = "6" * 64) -> dict[str, object]:
    assets = document["assets"]
    assert isinstance(assets, list)
    return {
        "schema": ACK_SCHEMA,
        "turnId": TURN,
        "tokens": [asset["token"] for asset in assets],
        "archiveReceiptSha256": receipt,
    }


def test_schema_v2_provision_binds_identity_and_exposes_frozen_root_state(
    tmp_path: Path,
) -> None:
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )

    state = store.inspect_root_state()
    assert state.database_identity == DATABASE_IDENTITY
    assert state.installation_id == INSTALLATION_ID
    assert state.epoch == 7


    assert state.mutation_sequence == 0
    assert state.authority_mode == "normal"
    assert state.recovery_floor is None
    assert state.recovery_state_digest is None
    assert len(state.state_digest) == 64
    assert state.state_digest != "0" * 64
    with pytest.raises(FrozenInstanceError):
        state.epoch = 8  # type: ignore[misc]

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        assert connection.execute(
            "SELECT schema,database_identity,mutation_sequence,"
            "authority_state_digest,authority_mode,recovery_floor,"
            "recovery_state_digest FROM asset_store_meta WHERE singleton=1"
        ).fetchone() == (
            "nachuan.paid-media-asset-store.v2",
            DATABASE_IDENTITY,
            0,
            state.state_digest,
            "normal",
            None,
            None,
        )
    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    assert reopened.inspect_root_state() == state
    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            store.root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            expected_database_identity="e" * 64,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )


def test_root_reconcile_removes_only_an_identity_matched_old_probe_cache_generation(
    tmp_path: Path,
) -> None:
    dependencies = _dependencies()
    root = tmp_path / "paid-media-assets"
    provisioned = PaidMediaAssetStore.provision(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    abandoned = _write_abandoned_probe_cache(
        provisioned,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity=DATABASE_IDENTITY,
        generation="a" * 64,
    )
    provisioned.close()
    hook_calls: list[None] = []

    reopened = PaidMediaAssetStore.open_bound(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
        pre_mutation_hook=lambda: hook_calls.append(None),
    )
    proof = reopened.inspect_root_state()
    assert reopened.resume_after_root_reconcile(proof) == proof

    assert not abandoned.exists()
    assert hook_calls == []
    assert reopened.inspect_root_state().database_identity == DATABASE_IDENTITY


def test_development_root_reconcile_never_inferrs_exclusive_cache_cleanup(
    tmp_path: Path,
) -> None:
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    abandoned = _write_abandoned_probe_cache(
        store,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity=DATABASE_IDENTITY,
        generation="a" * 64,
    )
    proof = store.inspect_root_state()

    assert store.resume_after_root_reconcile(proof) == proof
    assert abandoned.is_dir()


def test_root_reconcile_preserves_the_current_probe_cache_generation(
    tmp_path: Path,
) -> None:
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
        pre_mutation_hook=lambda: None,
    )
    owner = store._probe_cache_owner
    assert owner is not None
    current = _write_abandoned_probe_cache(
        store,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity=DATABASE_IDENTITY,
        generation=owner.generation,
    )
    proof = store.inspect_root_state()

    assert store.resume_after_root_reconcile(proof) == proof
    assert current.is_dir()


def test_root_reconcile_preflights_all_cache_owners_before_deleting_any(
    tmp_path: Path,
) -> None:
    dependencies = _dependencies()
    root = tmp_path / "paid-media-assets"
    provisioned = PaidMediaAssetStore.provision(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    valid = _write_abandoned_probe_cache(
        provisioned,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity=DATABASE_IDENTITY,
        generation="a" * 64,
        leaf="nachuan-media-cache-aaaaaaaa",
    )
    conflicting = _write_abandoned_probe_cache(
        provisioned,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity="e" * 64,
        generation="b" * 64,
        leaf="nachuan-media-cache-zzzzzzzz",
    )
    provisioned.close()
    reopened = PaidMediaAssetStore.open_bound(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
        pre_mutation_hook=lambda: None,
    )
    proof = reopened.inspect_root_state()

    with pytest.raises(PaidMediaAssetStoreError, match="authority does not match"):
        reopened.resume_after_root_reconcile(proof)

    assert valid.is_dir()
    assert conflicting.is_dir()


def test_root_reconcile_never_unlinks_a_hardlinked_cache_file(
    tmp_path: Path,
) -> None:
    dependencies = _dependencies()
    root = tmp_path / "paid-media-assets"
    provisioned = PaidMediaAssetStore.provision(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    abandoned = _write_abandoned_probe_cache(
        provisioned,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity=DATABASE_IDENTITY,
        generation="a" * 64,
    )
    (abandoned / "ffcache.bin").unlink()
    outside = tmp_path / "outside-canary.bin"
    outside.write_bytes(b"must-not-be-touched")
    dependencies.harden_acl(outside, False)
    os.link(outside, abandoned / "ffcache-hardlink.bin")
    provisioned.close()
    reopened = PaidMediaAssetStore.open_bound(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
        pre_mutation_hook=lambda: None,
    )

    with pytest.raises(PaidMediaAssetStoreError):
        reopened.resume_after_root_reconcile(reopened.inspect_root_state())

    assert outside.read_bytes() == b"must-not-be-touched"
    assert (abandoned / "ffcache-hardlink.bin").exists()


def test_root_reconcile_never_follows_a_cache_reparse_child(
    tmp_path: Path,
) -> None:
    dependencies = _dependencies()
    root = tmp_path / "paid-media-assets"
    provisioned = PaidMediaAssetStore.provision(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    abandoned = _write_abandoned_probe_cache(
        provisioned,
        installation_id=INSTALLATION_ID,
        epoch=7,
        database_identity=DATABASE_IDENTITY,
        generation="a" * 64,
    )
    outside = tmp_path / "outside-directory"
    outside.mkdir()
    canary = outside / "canary.bin"
    canary.write_bytes(b"must-not-be-touched")
    redirect = abandoned / "redirect"
    try:
        os.symlink(outside, redirect, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink creation is unavailable: {exc}")
    provisioned.close()
    reopened = PaidMediaAssetStore.open_bound(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
        pre_mutation_hook=lambda: None,
    )

    with pytest.raises(PaidMediaAssetStoreError):
        reopened.resume_after_root_reconcile(reopened.inspect_root_state())

    assert redirect.is_symlink()
    assert canary.read_bytes() == b"must-not-be-touched"


def test_staging_passes_the_bound_store_generation_to_the_trusted_probe(
    tmp_path: Path,
) -> None:
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    _reserve(store)
    observed: list[object] = []

    def recording_probe(path: Path, *, scratch_owner: object, **kwargs: object):
        observed.append(scratch_owner)
        return _probe(path, **kwargs)

    store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(base64.b64encode(b"marker-owner").decode("ascii"),),
        probe=recording_probe,
    )

    assert len(observed) == 1
    owner = observed[0]
    assert getattr(owner, "installation_id") == INSTALLATION_ID
    assert getattr(owner, "epoch") == 7
    assert getattr(owner, "database_identity") == DATABASE_IDENTITY
    assert re.fullmatch(r"[0-9a-f]{64}", getattr(owner, "generation")) is not None


def test_schema_v2_enforces_hard_database_and_logical_capacity_limits(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized"
    with pytest.raises(ValueError, match="capacity"):
        PaidMediaAssetStore.provision(
            oversized,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=(1 << 40) + 1,
            dependencies=_dependencies(),
        )
    assert not oversized.exists()

    store = _store(tmp_path)
    with store._connect() as connection:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        assert connection.execute("PRAGMA max_page_count").fetchone() == (
            (64 * 1024 * 1024) // page_size,
        )


def test_development_provision_generates_a_stable_nonzero_database_identity(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    state = store.inspect_root_state()
    assert len(state.database_identity) == 64
    assert state.database_identity != "0" * 64
    assert all(character in "0123456789abcdef" for character in state.database_identity)
    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    assert reopened.inspect_root_state() == state


def test_authoritative_projection_advances_once_and_is_content_deterministic(
    tmp_path: Path,
) -> None:
    dependencies = _dependencies(clock=lambda: 123.0)

    def provision(name: str) -> PaidMediaAssetStore:
        return PaidMediaAssetStore.provision(
            tmp_path / name,
            installation_id=INSTALLATION_ID,
            epoch=7,
            expected_database_identity=DATABASE_IDENTITY,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=dependencies,
        )

    first = provision("first")
    second = provision("second")
    different = provision("different")
    assert first.inspect_root_state() == second.inspect_root_state()

    for store in (first, second):
        _reserve(store)
    first_state = first.inspect_root_state()
    assert first_state.mutation_sequence == 1
    assert first_state == second.inspect_root_state()

    _reserve(first)
    assert first.inspect_root_state() == first_state

    different.reserve(
        turn_id="e" * 64,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    different_state = different.inspect_root_state()
    assert different_state.mutation_sequence == 1
    assert different_state.state_digest != first_state.state_digest


def test_reads_and_asset_read_lease_lifecycle_do_not_advance_authority(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    before = store.inspect_root_state()

    assert store.locate_token(descriptor.token).turn_id == TURN
    assert store.inspect_root_state() == before
    pinned = store.pin_authorized(
        token=descriptor.token,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
    )
    assert store.inspect_root_state() == before
    pinned.close()
    assert store.inspect_root_state() == before


def test_complete_asset_lifecycle_has_six_authoritative_transitions(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    assert store.inspect_root_state().mutation_sequence == 4
    store.finalize_result(document)
    assert store.inspect_root_state().mutation_sequence == 4

    pinned = store.pin_authorized(
        token=descriptor.token,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
    )
    pinned.close()
    assert store.inspect_root_state().mutation_sequence == 4

    first = store.ack(
        ack=_ack(document),
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    assert first.replayed is False and first.cleanup_complete is True
    terminal = store.inspect_root_state()
    assert terminal.mutation_sequence == 6

    second = store.ack(
        ack=_ack(document),
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    assert second.replayed is True and second.cleanup_complete is True
    assert store.inspect_root_state() == terminal


def test_reservation_release_advances_once_and_absent_replay_does_not(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    assert store.inspect_root_state().mutation_sequence == 1
    assert store.release_pre_provider(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
    ) is True
    released = store.inspect_root_state()
    assert released.mutation_sequence == 2
    assert store.release_pre_provider(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
    ) is True
    assert store.inspect_root_state() == released


def test_adjacent_rollback_anchor_is_closed_canonical_and_tracks_root_state(
    tmp_path: Path,
) -> None:
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
    )

    def assert_anchor() -> None:
        state = store.inspect_root_state()
        anchor_path = Path(f"{store.database_path}.rollback-anchor")
        raw = anchor_path.read_bytes()
        decoded = json.loads(raw.decode("ascii"))
        assert set(decoded) == {
            "authority_mode",
            "authority_state_digest",
            "database_identity",
            "epoch",
            "format",
            "installation_id",
            "mutation_sequence",
            "recovery_floor",
            "recovery_state_digest",
        }
        assert decoded == {
            "authority_mode": "normal",
            "authority_state_digest": state.state_digest,
            "database_identity": DATABASE_IDENTITY,
            "epoch": "0000000000000007",
            "format": 1,
            "installation_id": INSTALLATION_ID,
            "mutation_sequence": f"{state.mutation_sequence:016x}",
            "recovery_floor": "-" * 16,
            "recovery_state_digest": "-" * 64,
        }
        assert raw == json.dumps(
            decoded,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    assert_anchor()
    _reserve(store)
    assert store.inspect_root_state().mutation_sequence == 1
    assert_anchor()


def test_reader_waits_for_the_single_anchor_first_successor_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _store(tmp_path)
    reader = PaidMediaAssetStore.open_bound(
        writer.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    anchor_written = threading.Event()
    release_writer = threading.Event()
    original_write_anchor = writer._write_anchor

    def pause_after_anchor(state: object, *, create_only: bool = False) -> None:
        original_write_anchor(state, create_only=create_only)  # type: ignore[arg-type]
        if not create_only:
            anchor_written.set()
            assert release_writer.wait(5.0)

    monkeypatch.setattr(writer, "_write_anchor", pause_after_anchor)
    writer_outcome: list[object] = []
    reader_outcome: list[object] = []

    def mutate() -> None:
        try:
            writer_outcome.append(
                writer.reserve(
                    turn_id=TURN,
                    principal_hash=PRINCIPAL,
                    epoch=7,
                    operation="images.create",
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            writer_outcome.append(exc)

    def inspect() -> None:
        try:
            reader_outcome.append(reader.inspect_root_state())
        except BaseException as exc:  # pragma: no cover - asserted below
            reader_outcome.append(exc)

    writer_thread = threading.Thread(target=mutate)
    reader_thread = threading.Thread(target=inspect)
    writer_thread.start()
    assert anchor_written.wait(5.0)
    reader_thread.start()
    time.sleep(0.1)
    reader_waited = reader_thread.is_alive()
    release_writer.set()
    writer_thread.join(5.0)
    reader_thread.join(5.0)

    assert reader_waited is True
    assert not writer_thread.is_alive() and not reader_thread.is_alive()
    assert len(writer_outcome) == 1
    assert not isinstance(writer_outcome[0], BaseException)
    assert len(reader_outcome) == 1
    assert reader_outcome[0] == writer.inspect_root_state()
    assert reader_outcome[0].mutation_sequence == 1


def test_orphaned_anchor_first_successor_fails_closed_without_a_writer(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    before = store.inspect_root_state()
    anchor = json.loads(store.anchor_path.read_text(encoding="ascii"))
    anchor["mutation_sequence"] = "0000000000000001"
    anchor["authority_state_digest"] = "e" * 64
    store.anchor_path.write_text(
        json.dumps(
            anchor,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT mutation_sequence,authority_state_digest "
            "FROM asset_store_meta WHERE singleton=1"
        ).fetchone() == (before.mutation_sequence, before.state_digest)


def test_database_or_anchor_rollback_and_anchor_fork_fail_closed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    initial_database = store.database_path.read_bytes()
    initial_anchor = store.anchor_path.read_bytes()
    _reserve(store)
    current_database = store.database_path.read_bytes()
    current_anchor = store.anchor_path.read_bytes()

    store.database_path.write_bytes(initial_database)
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()
    store.database_path.write_bytes(current_database)

    store.anchor_path.write_bytes(initial_anchor)
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()
    store.anchor_path.write_bytes(current_anchor)

    fork = json.loads(current_anchor.decode("ascii"))
    fork["authority_state_digest"] = "e" * 64
    store.anchor_path.write_bytes(
        json.dumps(
            fork,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()


def test_manual_only_database_anchor_rollback_or_receipt_fork_fails_closed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    normal_database = store.database_path.read_bytes()
    normal_anchor = store.anchor_path.read_bytes()
    recovery = store.inspect_root_state()
    store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )
    manual_database = store.database_path.read_bytes()
    manual_anchor = store.anchor_path.read_bytes()

    store.database_path.write_bytes(normal_database)
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()
    store.database_path.write_bytes(manual_database)

    store.anchor_path.write_bytes(normal_anchor)
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()
    store.anchor_path.write_bytes(manual_anchor)

    fork = json.loads(manual_anchor.decode("ascii"))
    fork["recovery_state_digest"] = "e" * 64
    store.anchor_path.write_bytes(
        json.dumps(
            fork,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()


def test_missing_oversized_or_noncanonical_anchor_fails_closed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    canonical = store.anchor_path.read_bytes()

    store.anchor_path.unlink()
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()
    store.anchor_path.write_bytes(canonical)
    store.dependencies.harden_acl(store.anchor_path, False)

    decoded = json.loads(canonical.decode("ascii"))
    decoded["unexpected"] = True
    store.anchor_path.write_text(
        json.dumps(decoded, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()

    store.anchor_path.write_bytes(b"x" * 1025)
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()


def test_crash_after_anchor_fsync_rolls_back_database_and_locks_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    before = store.inspect_root_state()
    original_write_anchor = store._write_anchor

    def crash_after_anchor(state: object, *, create_only: bool = False) -> None:
        original_write_anchor(state, create_only=create_only)  # type: ignore[arg-type]
        if not create_only:
            raise RuntimeError("simulated crash after anchor fsync")

    monkeypatch.setattr(store, "_write_anchor", crash_after_anchor)
    with pytest.raises(RuntimeError, match="after anchor fsync"):
        _reserve(store)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT mutation_sequence,authority_state_digest "
            "FROM asset_store_meta WHERE singleton=1"
        ).fetchone() == (before.mutation_sequence, before.state_digest)
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_reservations"
        ).fetchone() == (0,)
    with pytest.raises(PaidMediaAssetStoreError):
        store.inspect_root_state()


def test_root_hook_observes_committed_transition_once_and_skips_replay(
    tmp_path: Path,
) -> None:
    transitions: list[object] = []
    root = tmp_path / "paid-media-assets"

    def confirm_root(transition: object) -> None:
        after = transition.after  # type: ignore[attr-defined]
        anchor = json.loads(
            Path(f"{root / 'asset-store.db'}.rollback-anchor").read_text(
                encoding="ascii"
            )
        )
        with sqlite3.connect(root / "asset-store.db") as connection:
            committed = connection.execute(
                "SELECT mutation_sequence,authority_state_digest "
                "FROM asset_store_meta WHERE singleton=1"
            ).fetchone()
        assert committed == (after.mutation_sequence, after.state_digest)
        assert int(anchor["mutation_sequence"], 16) == after.mutation_sequence
        assert anchor["authority_state_digest"] == after.state_digest
        transitions.append(transition)

    store = PaidMediaAssetStore.provision(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        root_commit_hook=confirm_root,
    )
    before = store.inspect_root_state()
    _reserve(store)
    after = store.inspect_root_state()
    assert len(transitions) == 1
    assert transitions[0].before == before  # type: ignore[attr-defined]
    assert transitions[0].after == after  # type: ignore[attr-defined]

    _reserve(store)
    assert len(transitions) == 1
    assert store.inspect_root_state() == after


def test_root_hook_failure_keeps_commit_blocks_writes_and_resumes_explicitly(
    tmp_path: Path,
) -> None:
    fail = True
    transitions: list[object] = []

    def confirm_root(transition: object) -> None:
        transitions.append(transition)
        if fail:
            raise RuntimeError("simulated root response loss")

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        root_commit_hook=confirm_root,
    )
    with pytest.raises(PaidMediaAssetRootCommitPending, match="confirmation"):
        _reserve(store)
    committed = store.inspect_root_state()
    assert committed.mutation_sequence == 1
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_reservations"
        ).fetchone() == (1,)

    with pytest.raises(PaidMediaAssetRootCommitPending):
        store.reserve(
            turn_id="e" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )
    assert len(transitions) == 1
    assert store.inspect_root_state() == committed

    with pytest.raises(PaidMediaAssetStoreError, match="does not match"):
        store.resume_after_root_reconcile(
            replace(committed, mutation_sequence=0)
        )
    assert store.resume_after_root_reconcile(committed) == committed
    fail = False
    store.reserve(
        turn_id="e" * 64,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    assert store.inspect_root_state().mutation_sequence == 2
    assert len(transitions) == 2


def test_enter_manual_only_advances_exact_recovery_fence_and_binds_anchor(
    tmp_path: Path,
) -> None:
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
    )
    _reserve(store)
    recovery = store.inspect_root_state()

    transition = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )

    assert transition.before == recovery
    assert transition.after == store.inspect_root_state()
    assert transition.after.mutation_sequence == recovery.mutation_sequence + 1
    assert transition.after.authority_mode == "manual_only"
    assert transition.after.installation_id == INSTALLATION_ID
    assert transition.after.epoch == 7
    assert transition.after.recovery_floor == recovery.mutation_sequence
    assert transition.after.recovery_state_digest == recovery.state_digest
    anchor = json.loads(store.anchor_path.read_text(encoding="ascii"))
    assert anchor["authority_mode"] == "manual"
    assert anchor["recovery_floor"] == f"{recovery.mutation_sequence:016x}"
    assert anchor["recovery_state_digest"] == recovery.state_digest


def test_manual_only_exact_retry_is_idempotent_and_persists_across_reopen(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    recovery = store.inspect_root_state()
    transition = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )
    anchor = store.anchor_path.read_bytes()

    assert store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    ) == transition
    assert store.inspect_root_state() == transition.after
    assert store.anchor_path.read_bytes() == anchor
    store.close()

    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=transition.after.database_identity,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    assert reopened.inspect_root_state() == transition.after
    assert reopened.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    ) == transition
    assert reopened.inspect_root_state() == transition.after


@pytest.mark.parametrize(
    ("installation_id", "epoch", "floor_offset", "digest"),
    [
        ("e" * 64, 7, 0, None),
        (INSTALLATION_ID, 8, 0, None),
        (INSTALLATION_ID, 7, 1, None),
        (INSTALLATION_ID, 7, 0, "f" * 64),
    ],
)
def test_manual_only_conflicting_fence_fails_without_changing_authority(
    tmp_path: Path,
    installation_id: str,
    epoch: int,
    floor_offset: int,
    digest: str | None,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    recovery = store.inspect_root_state()
    before_anchor = store.anchor_path.read_bytes()
    requested_digest = digest or recovery.state_digest

    with pytest.raises(PaidMediaAssetStoreError, match="does not match"):
        store.enter_authority_manual_only(
            installation_id=installation_id,
            epoch=epoch,
            recovery_floor=recovery.mutation_sequence + floor_offset,
            recovery_state_digest=requested_digest,
        )
    assert store.inspect_root_state() == recovery
    assert store.anchor_path.read_bytes() == before_anchor

    transition = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )
    manual_anchor = store.anchor_path.read_bytes()
    with pytest.raises(PaidMediaAssetStoreError, match="conflicts"):
        store.enter_authority_manual_only(
            installation_id=installation_id,
            epoch=epoch,
            recovery_floor=recovery.mutation_sequence + floor_offset,
            recovery_state_digest=requested_digest,
        )
    assert store.inspect_root_state() == transition.after
    assert store.anchor_path.read_bytes() == manual_anchor


def test_manual_only_bypasses_normal_hooks_and_rejects_authority_write(
    tmp_path: Path,
) -> None:
    pre_calls = 0
    root_calls: list[object] = []

    def pre_mutation() -> None:
        nonlocal pre_calls
        pre_calls += 1

    def confirm_root(transition: object) -> None:
        root_calls.append(transition)

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        pre_mutation_hook=pre_mutation,
        root_commit_hook=confirm_root,
    )
    _reserve(store)
    assert pre_calls == 1
    assert len(root_calls) == 1
    recovery = store.inspect_root_state()
    transition = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )
    anchor = store.anchor_path.read_bytes()
    assert pre_calls == 1
    assert len(root_calls) == 1

    with pytest.raises(PaidMediaAssetStoreError, match="manual recovery"):
        store.release_pre_provider(turn_id=TURN, principal_hash=PRINCIPAL)

    assert store.inspect_root_state() == transition.after
    assert store.anchor_path.read_bytes() == anchor
    assert pre_calls == 1
    assert len(root_calls) == 1
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT state FROM asset_reservations WHERE turn_id=?",
            (TURN,),
        ).fetchone() == ("active",)


def test_manual_only_rejects_stage_before_provider_or_input_bytes(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    recovery = store.inspect_root_state()
    manual = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    ).after
    downloader_called = False
    chunks_consumed = False

    def forbidden_downloader(*_args: object, **_kwargs: object) -> object:
        nonlocal downloader_called
        downloader_called = True
        raise AssertionError("manual-only stage must not call the provider")

    def forbidden_chunks() -> object:
        nonlocal chunks_consumed
        chunks_consumed = True
        yield base64.b64encode(b"must-not-be-written").decode("ascii")

    with pytest.raises(PaidMediaAssetStoreError, match="manual recovery"):
        store.stage_url(
            turn_id=TURN,
            ordinal=0,
            url="https://example.invalid/forbidden.png",
            downloader=forbidden_downloader,
            probe=_probe,
        )
    with pytest.raises(PaidMediaAssetStoreError, match="manual recovery"):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=forbidden_chunks(),  # type: ignore[arg-type]
            probe=_probe,
        )

    assert downloader_called is False
    assert chunks_consumed is False
    assert list(store.staging_directory.iterdir()) == []
    assert list(store.object_directory.iterdir()) == []
    assert store.inspect_root_state() == manual


def test_manual_only_preserves_inspection_token_lookup_pin_and_read_leases(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    recovery = store.inspect_root_state()
    manual = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    ).after

    assert store.locate_token(descriptor.token).turn_id == TURN
    pinned = store.pin_authorized(
        token=descriptor.token,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
    )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_read_leases"
        ).fetchone() == (1,)
    assert store.inspect_root_state() == manual
    assert b"".join(pinned.iter_chunks()) == b"strict-file-backed-image"
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_read_leases"
        ).fetchone() == (0,)
    assert store.inspect_root_state() == manual
    assert store.resume_after_root_reconcile(manual) == manual
    assert store.inspect_root_state().authority_mode == "manual_only"


def test_manual_only_privileged_receipt_recovers_pending_without_hooks(
    tmp_path: Path,
) -> None:
    root_calls: list[object] = []

    def unavailable_root(transition: object) -> None:
        root_calls.append(transition)
        raise RuntimeError("root response was lost")

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        root_commit_hook=unavailable_root,
    )
    with pytest.raises(PaidMediaAssetRootCommitPending):
        _reserve(store)
    recovery = store.inspect_root_state()
    assert recovery.authority_mode == "normal"
    assert len(root_calls) == 1

    manual = store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    ).after
    assert manual.authority_mode == "manual_only"
    assert len(root_calls) == 1
    assert store.resume_after_root_reconcile(manual) == manual
    with pytest.raises(PaidMediaAssetStoreError, match="manual recovery"):
        store.reserve(
            turn_id="e" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )
    assert len(root_calls) == 1
    assert store.inspect_root_state() == manual


def test_root_hook_failure_after_object_promotion_keeps_committed_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transitions: list[object] = []
    object_unlink_attempts: list[Path] = []

    def confirm_root(transition: object) -> None:
        transitions.append(transition)
        if transition.after.mutation_sequence == 3:  # type: ignore[attr-defined]
            raise RuntimeError("simulated promotion root response loss")

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        root_commit_hook=confirm_root,
    )
    real_unlink = Path.unlink

    def track_object_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path.parent == store.object_directory:
            object_unlink_attempts.append(path)
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", track_object_unlink)
    _reserve(store)
    encoded = base64.b64encode(b"root-pending-promoted-object").decode("ascii")

    with pytest.raises(PaidMediaAssetRootCommitPending, match="confirmation"):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=(encoded,),
            probe=_probe,
        )

    committed = store.inspect_root_state()
    assert committed.mutation_sequence == 3
    assert len(transitions) == 3
    with sqlite3.connect(store.database_path) as connection:
        row = connection.execute(
            "SELECT object_leaf FROM paid_media_assets WHERE turn_id=?",
            (TURN,),
        ).fetchone()
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits WHERE turn_id=?",
            (TURN,),
        ).fetchone() == (0,)
    assert row is not None
    committed_object = store.object_directory / str(row[0])
    assert object_unlink_attempts == []
    assert committed_object.read_bytes() == b"root-pending-promoted-object"


def test_pre_mutation_hook_rejects_before_database_or_anchor_change(
    tmp_path: Path,
) -> None:
    allowed = False
    calls = 0

    def gate() -> None:
        nonlocal calls
        calls += 1
        if not allowed:
            raise PaidMediaAssetStoreError("asset authority is not ready")

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        pre_mutation_hook=gate,
    )
    before = store.inspect_root_state()
    anchor_before = store.anchor_path.read_bytes()
    with pytest.raises(PaidMediaAssetStoreError, match="not ready"):
        _reserve(store)
    assert calls == 1
    assert store.inspect_root_state() == before
    assert store.anchor_path.read_bytes() == anchor_before
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_reservations"
        ).fetchone() == (0,)

    allowed = True
    _reserve(store)
    assert store.inspect_root_state().mutation_sequence == 1


def test_close_waits_for_inflight_root_hook_then_fences_the_instance(
    tmp_path: Path,
) -> None:
    hook_entered = threading.Event()
    hook_release = threading.Event()
    close_started = threading.Event()
    close_finished = threading.Event()
    writer_outcome: list[object] = []

    def blocking_root(_transition: object) -> None:
        hook_entered.set()
        assert hook_release.wait(5.0)

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: 123.0),
        root_commit_hook=blocking_root,
    )

    def mutate() -> None:
        try:
            _reserve(store)
            writer_outcome.append("committed")
        except BaseException as exc:  # pragma: no cover - asserted below
            writer_outcome.append(exc)

    def close_store() -> None:
        close_started.set()
        store.close()
        close_finished.set()

    writer = threading.Thread(target=mutate)
    closer = threading.Thread(target=close_store)
    writer.start()
    assert hook_entered.wait(5.0)
    closer.start()
    assert close_started.wait(1.0)
    close_waited = not close_finished.wait(0.1)
    hook_release.set()
    writer.join(5.0)
    closer.join(5.0)

    assert close_waited is True
    assert writer_outcome == ["committed"]
    assert close_finished.is_set()
    with pytest.raises(PaidMediaAssetStoreError, match="closed"):
        store.inspect_root_state()
    with pytest.raises(PaidMediaAssetStoreError, match="closed"):
        store.reserve(
            turn_id="e" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT mutation_sequence FROM asset_store_meta WHERE singleton=1"
        ).fetchone() == (1,)


def test_close_waits_for_inflight_manual_receipt_then_fences_instance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    recovery = store.inspect_root_state()
    anchor_written = threading.Event()
    release_anchor = threading.Event()
    close_started = threading.Event()
    close_finished = threading.Event()
    manual_outcome: list[object] = []
    original_write_anchor = store._write_anchor

    def blocking_anchor(state: object, *, create_only: bool = False) -> None:
        original_write_anchor(state, create_only=create_only)  # type: ignore[arg-type]
        if not create_only:
            anchor_written.set()
            assert release_anchor.wait(5.0)

    monkeypatch.setattr(store, "_write_anchor", blocking_anchor)

    def enter_manual() -> None:
        try:
            manual_outcome.append(
                store.enter_authority_manual_only(
                    installation_id=INSTALLATION_ID,
                    epoch=7,
                    recovery_floor=recovery.mutation_sequence,
                    recovery_state_digest=recovery.state_digest,
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            manual_outcome.append(exc)

    def close_store() -> None:
        close_started.set()
        store.close()
        close_finished.set()

    writer = threading.Thread(target=enter_manual)
    writer.start()
    assert anchor_written.wait(5.0)
    closer = threading.Thread(target=close_store)
    closer.start()
    assert close_started.wait(5.0)
    assert not close_finished.wait(0.1)
    release_anchor.set()
    writer.join(5.0)
    closer.join(5.0)
    assert not writer.is_alive()
    assert not closer.is_alive()
    assert close_finished.is_set()
    assert len(manual_outcome) == 1
    transition = manual_outcome[0]
    assert not isinstance(transition, BaseException)
    assert transition.after.authority_mode == "manual_only"  # type: ignore[attr-defined]
    with pytest.raises(PaidMediaAssetStoreError, match="closed"):
        store.inspect_root_state()

    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    assert reopened.inspect_root_state() == transition.after  # type: ignore[attr-defined]


def test_two_instances_converge_on_one_manual_only_receipt(
    tmp_path: Path,
) -> None:
    first = _store(tmp_path)
    second = PaidMediaAssetStore.open_bound(
        first.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    recovery = first.inspect_root_state()
    start = threading.Barrier(3)
    outcomes: list[object] = []

    def enter(store: PaidMediaAssetStore) -> None:
        start.wait()
        try:
            outcomes.append(
                store.enter_authority_manual_only(
                    installation_id=INSTALLATION_ID,
                    epoch=7,
                    recovery_floor=recovery.mutation_sequence,
                    recovery_state_digest=recovery.state_digest,
                )
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            outcomes.append(exc)

    threads = [
        threading.Thread(target=enter, args=(first,)),
        threading.Thread(target=enter, args=(second,)),
    ]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(15.0)
        assert not thread.is_alive()

    assert len(outcomes) == 2
    assert all(not isinstance(outcome, BaseException) for outcome in outcomes)
    assert outcomes[0] == outcomes[1]
    assert first.inspect_root_state() == second.inspect_root_state()
    assert first.inspect_root_state().authority_mode == "manual_only"
    assert first.inspect_root_state().mutation_sequence == 1


@pytest.mark.parametrize(
    "assignment",
    [
        "authority_mode='normal'",
        "recovery_floor=recovery_floor+1",
        f"recovery_state_digest='{'e' * 64}'",
    ],
)
def test_manual_only_closed_receipt_rejects_schema_or_projection_tamper(
    tmp_path: Path,
    assignment: str,
) -> None:
    store = _store(tmp_path)
    recovery = store.inspect_root_state()
    store.enter_authority_manual_only(
        installation_id=INSTALLATION_ID,
        epoch=7,
        recovery_floor=recovery.mutation_sequence,
        recovery_state_digest=recovery.state_digest,
    )
    store.close()

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            f"UPDATE asset_store_meta SET {assignment} WHERE singleton=1"
        )
        connection.commit()

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            store.root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )


def test_incremental_base64_commit_stores_only_token_hash_and_streams(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    token = descriptor.token

    database_bytes = store.database_path.read_bytes()
    assert token.encode("ascii") not in database_bytes
    assert store.locate_token(token).turn_id == TURN

    pinned = store.pin_authorized(
        token=token,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
    )
    assert b"".join(pinned.iter_chunks()) == b"strict-file-backed-image"


def test_url_stage_uses_pinned_public_downloader_and_full_probe(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)
    payload = b"downloaded-through-public-media"
    observed: dict[str, object] = {}

    @dataclass(frozen=True)
    class Result:
        path: str
        content_type: str
        size: int

    def downloader(url: str, **kwargs: object) -> Result:
        observed.update(url=url, **kwargs)
        target = Path(str(kwargs["temp_dir"])) / "download.stage"
        target.write_bytes(payload)
        return Result(str(target), "image/png", len(payload))

    descriptor = store.stage_url(
        turn_id=TURN,
        ordinal=0,
        url="https://public.example.invalid/image.png",
        downloader=downloader,
        probe=_probe,
    )

    assert observed["max_bytes"] == 24 * 1024 * 1024
    assert observed["temp_dir"] == store.staging_directory
    utf8_guard = observed["utf8_identity_url_guard"]
    assert callable(utf8_guard)
    assert utf8_guard(
        "https://platform-outputs.agnes-ai.space/images/t2i/result.png"
    )
    assert utf8_guard(
        "https://platform-outputs.agnes-ai.space/videos/agnes-video-v2.0/result.mp4"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space/video/result.mp4"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space.evil.invalid/images/result.png"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space:444/images/result.png"
    )
    assert not utf8_guard(
        "https://user@platform-outputs.agnes-ai.space/images/result.png"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space/images/../videos/result.mp4"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space/images/%2e%2e/videos/result.mp4"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space/images%2f..%2fvideos/result.mp4"
    )
    assert not utf8_guard(
        "https://platform-outputs.agnes-ai.space/images\\..\\videos\\result.mp4"
    )
    assert descriptor.sha256 == hashlib.sha256(payload).hexdigest()
    assert not (store.staging_directory / "download.stage").exists()


def test_url_stage_uses_the_validated_prepared_token(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "B" * 43
    payload = b"prepared-url-token-image"

    @dataclass(frozen=True)
    class Result:
        path: str
        content_type: str
        size: int

    def downloader(_url: str, **kwargs: object) -> Result:
        target = Path(str(kwargs["temp_dir"])) / "prepared-url.stage"
        target.write_bytes(payload)
        return Result(str(target), "image/png", len(payload))

    descriptor = store.stage_url(
        turn_id=TURN,
        ordinal=0,
        url="https://public.example.invalid/prepared.png",
        downloader=downloader,
        prepared_token=prepared_token,
        probe=_probe,
    )

    assert descriptor.token == prepared_token


def test_invalid_prepared_token_is_rejected_before_url_download(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)
    called = False

    def downloader(*_args: object, **_kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("invalid prepared token reached the downloader")

    with pytest.raises(PaidMediaAssetProtocolError):
        store.stage_url(
            turn_id=TURN,
            ordinal=0,
            url="https://public.example.invalid/never-download.png",
            downloader=downloader,
            prepared_token="stale-token",
            probe=_probe,
        )

    assert called is False


def test_url_stage_rejecting_probe_leaves_no_asset_pending_commit_or_ack(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    payload = b"not-a-real-png"

    @dataclass(frozen=True)
    class Result:
        path: str
        content_type: str
        size: int

    def downloader(_url: str, **kwargs: object) -> Result:
        target = Path(str(kwargs["temp_dir"])) / "invalid-image.stage"
        target.write_bytes(payload)
        return Result(str(target), "image/png", len(payload))

    def rejecting_probe(*_args: object, **_kwargs: object) -> TrustedMediaProbeResult:
        raise ValueError("full media decode rejected the provider bytes")

    with pytest.raises(ValueError, match="full media decode"):
        store.stage_url(
            turn_id=TURN,
            ordinal=0,
            url="https://platform-outputs.agnes-ai.space/images/t2i/invalid.png",
            downloader=downloader,
            probe=rejecting_probe,
        )

    assert list(store.staging_directory.iterdir()) == []
    assert list(store.object_directory.iterdir()) == []
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT state,actual_bytes FROM asset_reservations WHERE turn_id=?",
            (TURN,),
        ).fetchone() == ("active", 0)
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM paid_media_assets"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_ack_receipts"
        ).fetchone() == (0,)


def test_capacity_is_persistently_reserved_before_a_second_provider_slot(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, max_capacity=OPERATION_RESERVATION_BYTES)
    _reserve(store)

    with pytest.raises(PaidMediaAssetCapacityError):
        store.reserve(
            turn_id="7" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )

    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    with pytest.raises(PaidMediaAssetCapacityError):
        reopened.reserve(
            turn_id="8" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )


def test_corrupt_or_noncanonical_base64_never_commits_a_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)

    for chunks in (("YW Jj",), ("YWJj=trailing",), ("YWJ",), ("Zh==",)):
        with pytest.raises(PaidMediaAssetStoreError):
            store.stage_base64_chunks(
                turn_id=TURN,
                ordinal=0,
                media_type="image/png",
                chunks=chunks,
                probe=_probe,
            )
    assert list(store.object_directory.iterdir()) == []


def test_one_huge_base64_chunk_is_consumed_in_bounded_decode_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import gateway.paid_media_asset_store as asset_module

    store = _store(tmp_path)
    _reserve(store)
    payload = b"x" * (2 * 1024 * 1024)
    encoded = base64.b64encode(payload).decode("ascii")
    original = asset_module.base64.b64decode
    observed: list[int] = []

    def bounded(value: bytes, *args: object, **kwargs: object) -> bytes:
        observed.append(len(value))
        return original(value, *args, **kwargs)

    monkeypatch.setattr(asset_module.base64, "b64decode", bounded)
    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(encoded,),
        probe=_probe,
    )
    assert descriptor.byte_length == len(payload)
    assert observed and max(observed) <= 64 * 1024 + 4


def test_base64_stage_uses_the_validated_prepared_token(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "A" * 43
    payload = b"prepared-token-image"

    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(base64.b64encode(payload).decode("ascii"),),
        prepared_token=prepared_token,
        probe=_probe,
    )

    assert descriptor.token == prepared_token


def test_prepared_token_cannot_be_reused_for_another_asset(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "C" * 43
    encoded = base64.b64encode(b"first-prepared-image").decode("ascii")
    store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(encoded,),
        prepared_token=prepared_token,
        probe=_probe,
    )

    with pytest.raises(PaidMediaAssetConflictError, match="token already exists"):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=1,
            media_type="image/png",
            chunks=(encoded,),
            prepared_token=prepared_token,
            probe=_probe,
        )


def test_describe_prepared_asset_returns_none_then_the_exact_paid_descriptor(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "D" * 43

    assert (
        store.describe_prepared_asset(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
            token=prepared_token,
        )
        is None
    )

    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(base64.b64encode(b"described-prepared-image").decode("ascii"),),
        prepared_token=prepared_token,
        probe=_probe,
    )

    assert (
        store.describe_prepared_asset(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
            token=prepared_token,
        )
        == descriptor
    )


def test_describe_prepared_asset_rejects_wrong_principal_and_old_token(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "K" * 43
    store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(base64.b64encode(b"authority-bound-prepared").decode("ascii"),),
        prepared_token=prepared_token,
        probe=_probe,
    )

    with pytest.raises(PaidMediaAssetAuthorizationError, match="authority"):
        store.describe_prepared_asset(
            turn_id=TURN,
            principal_hash="9" * 64,
            epoch=7,
            operation="images.create",
            token=prepared_token,
        )

    later_turn = "4" * 64
    _reserve(store, turn=later_turn)
    with pytest.raises(PaidMediaAssetConflictError, match="another reservation"):
        store.describe_prepared_asset(
            turn_id=later_turn,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
            token=prepared_token,
        )


def test_describe_prepared_asset_recovers_the_exact_registered_object(
    tmp_path: Path,
) -> None:
    prepared_token = "nma1_" + "E" * 43

    def crash_after_replace(_path: Path) -> None:
        raise RuntimeError("simulated crash after prepared object replace")

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(after_object_replace=crash_after_replace),
    )
    _reserve(store)
    payload = b"recoverable-prepared-object"
    with pytest.raises(RuntimeError, match="prepared object replace"):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )

    descriptor = store.describe_prepared_asset(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
        token=prepared_token,
    )

    assert descriptor is not None
    assert descriptor.token == prepared_token
    assert descriptor.byte_length == len(payload)
    assert descriptor.sha256 == hashlib.sha256(payload).hexdigest()
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits WHERE turn_id=?", (TURN,)
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM paid_media_assets WHERE turn_id=?", (TURN,)
        ).fetchone() == (1,)


def test_describe_prepared_asset_does_not_blindly_accept_a_changed_object(
    tmp_path: Path,
) -> None:
    prepared_token = "nma1_" + "M" * 43

    def crash_after_replace(_path: Path) -> None:
        raise RuntimeError("simulated crash before prepared receipt commit")

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(after_object_replace=crash_after_replace),
    )
    _reserve(store)
    payload = b"registered-object-before-change"
    with pytest.raises(RuntimeError, match="prepared receipt commit"):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=(base64.b64encode(payload).decode("ascii"),),
            prepared_token=prepared_token,
            probe=_probe,
        )
    object_path = next(store.object_directory.iterdir())
    object_path.write_bytes(b"x" * len(payload))

    with pytest.raises(PaidMediaAssetAuthorizationError, match="digest"):
        store.describe_prepared_asset(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
            token=prepared_token,
        )

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits WHERE turn_id=?", (TURN,)
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM paid_media_assets WHERE turn_id=?", (TURN,)
        ).fetchone() == (0,)


def test_describe_prepared_asset_recovers_the_exact_registered_staging_file(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "L" * 43
    payload = b"recoverable-prepared-staging"
    staging_leaf = "registered-prepared.stage"
    object_leaf = "e" * 64 + ".asset"
    staging_path = store.staging_directory / staging_leaf
    staging_path.write_bytes(payload)
    store._harden_file(staging_path)
    with store._write() as connection:
        connection.execute(
            "INSERT INTO asset_pending_commits "
            "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
            "validation_receipt_sha256,staging_leaf,object_leaf,lease_expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                asset_token_hash(prepared_token),
                TURN,
                0,
                "image/png",
                len(payload),
                hashlib.sha256(payload).hexdigest(),
                "c" * 64,
                staging_leaf,
                object_leaf,
                time.time() + 900,
            ),
        )

    descriptor = store.describe_prepared_asset(
        turn_id=TURN,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
        token=prepared_token,
    )

    assert descriptor is not None
    assert descriptor.token == prepared_token
    assert not staging_path.exists()
    assert (store.object_directory / object_leaf).read_bytes() == payload


def test_committed_finalize_replay_rejects_changed_descriptor_fields(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    changed = PaidMediaAssetResult(
        kind="image",
        created=int(document["created"]),
        turn_id=TURN,
        assets=(replace(descriptor, byte_length=descriptor.byte_length + 1),),
    )

    with pytest.raises(
        PaidMediaAssetConflictError,
        match="private committed files",
    ):
        store.finalize_result(changed)


def test_finalize_prepared_result_commits_and_exactly_replays(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _reserve(store)
    prepared_token = "nma1_" + "F" * 43
    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(base64.b64encode(b"prepared-final-result").decode("ascii"),),
        prepared_token=prepared_token,
        probe=_probe,
    )
    result = PaidMediaAssetResult(
        kind="image",
        created=1_784_200_001,
        turn_id=TURN,
        assets=(descriptor,),
    )

    committed = store.finalize_prepared_result(
        result,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    replayed = store.finalize_prepared_result(
        result,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )

    assert committed == result
    assert replayed == result
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT state FROM asset_reservations WHERE turn_id=?", (TURN,)
        ).fetchone() == ("committed",)


def test_finalize_prepared_result_rejects_the_wrong_principal_while_active(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(base64.b64encode(b"principal-bound-result").decode("ascii"),),
        prepared_token="nma1_" + "G" * 43,
        probe=_probe,
    )
    result = PaidMediaAssetResult(
        kind="image",
        created=1_784_200_002,
        turn_id=TURN,
        assets=(descriptor,),
    )

    with pytest.raises(PaidMediaAssetAuthorizationError, match="authority"):
        store.finalize_prepared_result(
            result,
            principal_hash="9" * 64,
            epoch=7,
            operation="images.create",
        )

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT state FROM asset_reservations WHERE turn_id=?", (TURN,)
        ).fetchone() == ("active",)


def test_committed_prepared_replay_checks_every_descriptor_field_and_ordinal(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    descriptors = tuple(
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=ordinal,
            media_type="image/png",
            chunks=(
                base64.b64encode(f"prepared-field-{ordinal}".encode()).decode(
                    "ascii"
                ),
            ),
            prepared_token="nma1_" + character * 43,
            probe=_probe,
        )
        for ordinal, character in enumerate(("H", "I"))
    )
    result = PaidMediaAssetResult(
        kind="image",
        created=1_784_200_003,
        turn_id=TURN,
        assets=descriptors,
    )
    store.finalize_prepared_result(
        result,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    first, second = descriptors
    changed_assets = (
        (replace(first, token="nma1_" + "J" * 43), second),
        (second, first),
        (replace(first, media_type="image/jpeg"), second),
        (replace(first, byte_length=first.byte_length + 1), second),
        (replace(first, sha256="a" * 64), second),
        (replace(first, validation_receipt_sha256="b" * 64), second),
    )

    for assets in changed_assets:
        changed = replace(result, assets=assets)
        with pytest.raises(
            PaidMediaAssetConflictError,
            match="private committed files",
        ):
            store.finalize_prepared_result(
                changed,
                principal_hash=PRINCIPAL,
                epoch=7,
                operation="images.create",
            )


def test_dataclass_instances_are_reparsed_not_trusted_by_isinstance(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    parsed = PaidMediaAssetResult(
        kind="image",
        created=int(document["created"]),
        turn_id=TURN,
        assets=(replace(descriptor, media_type="text/plain"),),
    )
    with pytest.raises(Exception):  # closed protocol error, never a trusted dataclass
        store.finalize_result(parsed)


def test_physical_admission_accounts_for_existing_persistent_reservations(
    tmp_path: Path,
) -> None:
    physical = 2 * OPERATION_RESERVATION_BYTES + 32 * 1024 * 1024 - 1
    dependencies = _dependencies(capacity=physical)
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    _reserve(store)
    with pytest.raises(PaidMediaAssetCapacityError):
        store.reserve(
            turn_id="7" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )


def test_schema_tamper_after_open_is_revalidated_before_next_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("CREATE TABLE rogue(payload TEXT)")
    real_connect = sqlite3.connect
    read_write_attempts: list[str] = []

    def guarded_connect(
        database: object, *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        target = (
            os.fspath(database)
            if isinstance(database, (str, os.PathLike))
            else str(database)
        )
        if not (kwargs.get("uri") is True and "mode=ro" in target):
            read_write_attempts.append(target)
            raise AssertionError("drifted schema reached a read-write SQLite open")
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(paid_media_asset_store.sqlite3, "connect", guarded_connect)
    with pytest.raises(PaidMediaAssetStoreError):
        store.reserve(
            turn_id=TURN,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )
    assert read_write_attempts == []


def test_crash_after_object_replace_has_expiring_tombstone_and_converges(
    tmp_path: Path,
) -> None:
    now = [0.0]

    def crash_after_replace(_path: Path) -> None:
        raise RuntimeError("simulated crash after object replace")

    dependencies = _dependencies(
        clock=lambda: now[0],
        after_object_replace=crash_after_replace,
    )
    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=dependencies,
    )
    _reserve(store)
    encoded = base64.b64encode(b"charged-provider-result").decode("ascii")
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=(encoded,),
            probe=_probe,
        )
    assert store.inspect_root_state().mutation_sequence == 2
    assert len(list(store.object_directory.iterdir())) == 1
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits"
        ).fetchone() == (1,)

    now[0] = 901.0
    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: now[0]),
    )
    assert reopened.inspect_root_state().mutation_sequence == 2
    assert reopened.reconcile_expired_pending() == 1
    assert reopened.inspect_root_state().mutation_sequence == 3
    assert list(reopened.object_directory.iterdir()) == []
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits"
        ).fetchone() == (0,)
        # Provider outcome is still ambiguous: tombstone cleanup never releases
        # the operation reservation or authorizes an automatic retry.
        assert connection.execute(
            "SELECT state FROM asset_reservations WHERE turn_id=?", (TURN,)
        ).fetchone() == ("active",)


def test_open_bound_is_read_only_until_explicit_reconcile_after_attach(
    tmp_path: Path,
) -> None:
    now = [0.0]

    def crash_after_replace(_path: Path) -> None:
        raise RuntimeError("simulated crash after object replace")

    source = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(
            clock=lambda: now[0],
            after_object_replace=crash_after_replace,
        ),
    )
    _reserve(source)
    encoded = base64.b64encode(b"charged-provider-result").decode("ascii")
    with pytest.raises(RuntimeError, match="simulated crash"):
        source.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=(encoded,),
            probe=_probe,
        )
    before = source.inspect_root_state()
    assert before.mutation_sequence == 2
    now[0] = 901.0
    attached = False
    gate_calls = 0

    def attached_gate() -> None:
        nonlocal gate_calls
        gate_calls += 1
        if not attached:
            raise PaidMediaAssetStoreError("asset controller is detached")

    reopened = PaidMediaAssetStore.open_bound(
        source.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        expected_database_identity=DATABASE_IDENTITY,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(clock=lambda: now[0]),
        pre_mutation_hook=attached_gate,
    )
    assert gate_calls == 0
    assert reopened.inspect_root_state() == before
    assert len(list(reopened.object_directory.iterdir())) == 1

    attached = True
    assert reopened.reconcile_expired_pending() == 1
    assert gate_calls == 1
    assert reopened.inspect_root_state().mutation_sequence == 3
    assert list(reopened.object_directory.iterdir()) == []


def test_pending_reconciler_cannot_delete_object_after_concurrent_finalize(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _reserve(store)
    producer = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    token_hash = "a" * 64
    object_leaf = f"{'b' * 64}.asset"
    object_path = store.object_directory / object_leaf
    object_path.write_bytes(b"x")
    store.dependencies.harden_acl(object_path, False)
    with store._write() as connection:
        connection.execute(
            "INSERT INTO asset_pending_commits "
            "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
            "validation_receipt_sha256,staging_leaf,object_leaf,lease_expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,0)",
            (
                token_hash,
                TURN,
                0,
                "image/png",
                1,
                "c" * 64,
                "d" * 64,
                "gone.stage",
                object_leaf,
            ),
        )
    producer_started = threading.Event()
    producer_release = threading.Event()
    producer_outcome: list[object] = []

    def finalize() -> None:
        try:
            with producer._write() as connection:
                connection.execute(
                    "INSERT INTO paid_media_assets "
                    "(token_hash,turn_id,ordinal,media_type,byte_length,sha256,"
                    "validation_receipt_sha256,object_leaf) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (
                        token_hash,
                        TURN,
                        0,
                        "image/png",
                        1,
                        "c" * 64,
                        "d" * 64,
                        object_leaf,
                    ),
                )
                connection.execute(
                    "DELETE FROM asset_pending_commits WHERE token_hash=?",
                    (token_hash,),
                )
                connection.execute(
                    "UPDATE asset_reservations SET actual_bytes=1 WHERE turn_id=?",
                    (TURN,),
                )
                producer_started.set()
                assert producer_release.wait(5.0)
            producer_outcome.append("committed")
        except BaseException as exc:  # pragma: no cover - asserted below
            producer_outcome.append(exc)

    producer_thread = threading.Thread(target=finalize)
    producer_thread.start()
    assert producer_started.wait(5.0)

    started = threading.Event()
    outcome: list[object] = []

    def reconcile() -> None:
        started.set()
        try:
            outcome.append(store.reconcile_expired_pending())
        except BaseException as exc:  # pragma: no cover - asserted below
            outcome.append(exc)

    worker = threading.Thread(target=reconcile)
    worker.start()
    assert started.wait(1.0)
    # With the old snapshot/unlink/write sequence this window deleted the
    # object while the producer's promotion remained uncommitted.
    time.sleep(0.1)
    producer_release.set()
    producer_thread.join(timeout=5.0)
    worker.join(timeout=5.0)

    assert not producer_thread.is_alive()
    assert producer_outcome == ["committed"]
    assert not worker.is_alive()
    assert outcome == [0]
    assert object_path.read_bytes() == b"x"
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT object_leaf FROM paid_media_assets WHERE token_hash=?",
            (token_hash,),
        ).fetchone() == (object_leaf,)


def test_finalizer_rejects_missing_object_even_when_pending_tuple_survives(
    tmp_path: Path,
) -> None:
    def unlink_after_replace(path: Path) -> None:
        path.unlink()

    store = PaidMediaAssetStore.provision(
        tmp_path / "paid-media-assets",
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(after_object_replace=unlink_after_replace),
    )
    _reserve(store)
    encoded = base64.b64encode(b"provider-result-that-was-cleaned").decode("ascii")

    with pytest.raises(PaidMediaAssetAuthorizationError):
        store.stage_base64_chunks(
            turn_id=TURN,
            ordinal=0,
            media_type="image/png",
            chunks=(encoded,),
            probe=_probe,
        )

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM paid_media_assets"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM asset_pending_commits"
        ).fetchone() == (1,)


def test_sidecar_or_cross_principal_cannot_authorize_without_exact_success(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)

    with pytest.raises(PaidMediaAssetAuthorizationError):
        store.pin_authorized(
            token=descriptor.token,
            durable_result={**document, "turnId": "9" * 64},
            principal_hash=PRINCIPAL,
            epoch=7,
        )
    with pytest.raises(PaidMediaAssetAuthorizationError):
        store.pin_authorized(
            token=descriptor.token,
            durable_result=document,
            principal_hash="a" * 64,
            epoch=7,
        )


def test_ack_cas_rejects_subset_conflict_and_exact_repeat_is_idempotent(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    ack = _ack(document)

    conflict = dict(ack)
    conflict["tokens"] = ["nma1_" + "A" * 43]
    with pytest.raises(PaidMediaAssetConflictError):
        store.ack(
            ack=conflict,
            durable_result=document,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )

    first = store.ack(
        ack=ack,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    second = store.ack(
        ack=ack,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
        operation="images.create",
    )
    assert first.replayed is False and first.cleanup_complete is True
    assert second.replayed is True and second.cleanup_complete is True
    with pytest.raises(PaidMediaAssetAuthorizationError):
        store.locate_token(descriptor.token)

    changed = _ack(document, receipt="b" * 64)
    with pytest.raises(PaidMediaAssetConflictError):
        store.ack(
            ack=changed,
            durable_result=document,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )


def test_ack_blocks_new_get_then_waits_for_an_existing_pinned_lease(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, descriptor = _committed(store)
    pinned = store.pin_authorized(
        token=descriptor.token,
        durable_result=document,
        principal_hash=PRINCIPAL,
        epoch=7,
    )
    outcome: list[object] = []

    def acknowledge() -> None:
        outcome.append(
            store.ack(
                ack=_ack(document),
                durable_result=document,
                principal_hash=PRINCIPAL,
                epoch=7,
                operation="images.create",
                wait_timeout_seconds=2.0,
            )
        )

    thread = threading.Thread(target=acknowledge)
    thread.start()
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            store.locate_token(descriptor.token)
        except PaidMediaAssetAuthorizationError:
            break
        time.sleep(0.01)
    else:
        pytest.fail("ACK did not close new GET authority")
    assert thread.is_alive()
    assert b"".join(pinned.iter_chunks()) == b"strict-file-backed-image"
    thread.join(2.0)
    assert not thread.is_alive()
    assert outcome and outcome[0].cleanup_complete is True


def test_crash_before_success_keeps_reservation_and_never_authorizes_token(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, max_capacity=OPERATION_RESERVATION_BYTES)
    _reserve(store)
    encoded = base64.b64encode(b"provider-returned-but-not-success").decode()
    descriptor = store.stage_base64_chunks(
        turn_id=TURN,
        ordinal=0,
        media_type="image/png",
        chunks=(encoded,),
        probe=_probe,
    )

    reopened = PaidMediaAssetStore.open_bound(
        store.root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    with pytest.raises(PaidMediaAssetAuthorizationError):
        reopened.locate_token(descriptor.token)
    with pytest.raises(PaidMediaAssetCapacityError):
        reopened.reserve(
            turn_id="c" * 64,
            principal_hash=PRINCIPAL,
            epoch=7,
            operation="images.create",
        )


def test_open_rejects_epoch_and_runtime_v1_schema(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            store.root,
            installation_id=INSTALLATION_ID,
            epoch=8,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("PRAGMA user_version=1")
    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            store.root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )


def test_open_rejects_foreign_schema_only_in_abandoned_wal_without_recovery(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()
    database_path.unlink()
    _create_abandoned_foreign_hot_wal(database_path)
    before = _database_family(database_path)

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )

    after = _database_family(database_path)
    assert after[""] == before[""]
    assert after["-wal"] == before["-wal"]
    assert after["-journal"] == before["-journal"]
    assert after["-shm"] is not None


def test_open_rejects_orphan_wal_family_without_recreating_main(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()
    database_path.unlink()
    _create_abandoned_foreign_hot_wal(database_path)
    database_path.unlink()
    before = _database_family(database_path)

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )

    assert _database_family(database_path) == before


@pytest.mark.parametrize("missing_suffix", ["-wal", "-shm"])
def test_open_rejects_incomplete_wal_pair_without_mutation(
    tmp_path: Path, missing_suffix: str
) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()
    database_path.unlink()
    _create_abandoned_foreign_hot_wal(database_path)
    Path(f"{database_path}{missing_suffix}").unlink()
    before = _database_family(database_path)

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )

    assert _database_family(database_path) == before


def test_open_recovers_exact_current_wal_and_restores_delete_mode(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()
    _create_abandoned_current_hot_wal(database_path)

    reopened = PaidMediaAssetStore.open_bound(
        root,
        installation_id=INSTALLATION_ID,
        epoch=7,
        max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
        dependencies=_dependencies(),
    )
    reopened.close()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)


def test_open_rejects_unexpected_view_in_closed_schema(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "CREATE VIEW unexpected_asset_authority AS "
            "SELECT turn_id FROM asset_reservations"
        )

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            store.root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )


def test_open_rejects_reserved_prefix_schema_object_without_read_write_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()
    _inject_reserved_prefix_view(database_path)
    before = database_path.read_bytes()
    real_connect = sqlite3.connect
    read_write_attempts: list[str] = []

    def guarded_connect(
        database: object, *args: object, **kwargs: object
    ) -> sqlite3.Connection:
        target = (
            os.fspath(database)
            if isinstance(database, (str, os.PathLike))
            else str(database)
        )
        if not (kwargs.get("uri") is True and "mode=ro" in target):
            read_write_attempts.append(target)
            raise AssertionError("foreign schema reached a read-write SQLite open")
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(paid_media_asset_store.sqlite3, "connect", guarded_connect)

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )
    assert read_write_attempts == []
    assert database_path.read_bytes() == before


def test_open_rejects_internal_tbl_name_drift_without_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()
    _tamper_internal_tbl_name(database_path)
    before = database_path.read_bytes()

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )
    assert database_path.read_bytes() == before


def test_open_rejects_quoted_schema_literal_case_collision(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = store.root
    database_path = store.database_path
    store.close()

    with sqlite3.connect(database_path) as connection:
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        connection.execute("PRAGMA writable_schema=ON")
        cursor = connection.execute(
            "UPDATE sqlite_master SET sql=replace(sql,?,?) "
            "WHERE type='table' AND name='asset_store_meta'",
            ("'manual_only'", "'MANUAL_ONLY'"),
        )
        assert cursor.rowcount == 1
        connection.execute("PRAGMA writable_schema=OFF")
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.commit()

    with pytest.raises(PaidMediaAssetStoreError):
        PaidMediaAssetStore.open_bound(
            root,
            installation_id=INSTALLATION_ID,
            epoch=7,
            max_capacity_bytes=2 * OPERATION_RESERVATION_BYTES,
            dependencies=_dependencies(),
        )


def test_schema_authority_preserves_sql_token_boundaries() -> None:
    assert paid_media_asset_store._canonical_sql(
        "CHECK(a IS NULL)"
    ) != paid_media_asset_store._canonical_sql("CHECK(aisnull)")
