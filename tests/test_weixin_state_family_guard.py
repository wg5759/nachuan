from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, asdict
import json
import math
import os
from pathlib import Path
import subprocess

import pytest

from gateway.weixin_state_family_guard import (
    FamilyKind,
    FamilyGuardSeams,
    MAX_JOURNAL_BYTES,
    MAX_LOCK_BYTES,
    MAX_MAIN_BYTES,
    MAX_SHM_BYTES,
    MAX_WAL_BYTES,
    MemberRole,
    ORIGINAL_RECOVERY_SUPPORTED,
    WeixinStateFamilyGuardError,
    clone_rollback_candidate,
    recover_original,
    snapshot_family,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_original_recovery_is_explicitly_unsupported(tmp_path: Path) -> None:
    assert ORIGINAL_RECOVERY_SUPPORTED is False

    with pytest.raises(
        WeixinStateFamilyGuardError,
        match="original recovery is not supported",
    ):
        recover_original(tmp_path / "state.sqlite")


def test_clone_rollback_candidate_copies_without_mutating_original(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    stage_dir = tmp_path / "stage"
    source_dir.mkdir()
    stage_dir.mkdir()
    main = source_dir / "state.sqlite"
    journal = source_dir / "state.sqlite-journal"
    main_bytes = b"SQLite format 3\x00" + b"m" * 128
    journal_bytes = b"journal-candidate" + b"j" * 64
    main.write_bytes(main_bytes)
    journal.write_bytes(journal_bytes)

    receipt = clone_rollback_candidate(main, stage_dir)

    assert ORIGINAL_RECOVERY_SUPPORTED is False
    assert receipt.outcome == "rollback_candidate_cloned"
    assert receipt.original_recovery_supported is False
    assert receipt.main.sha256 == _sha256(main_bytes)
    assert receipt.journal.sha256 == _sha256(journal_bytes)
    assert (stage_dir / "state.sqlite").read_bytes() == main_bytes
    assert (stage_dir / "state.sqlite-journal").read_bytes() == journal_bytes
    assert main.read_bytes() == main_bytes
    assert journal.read_bytes() == journal_bytes


@pytest.mark.parametrize(
    "unsafe",
    (
        Path("relative") / "state.sqlite",
        r"\\server\share\state.sqlite",
    ),
)
def test_snapshot_rejects_non_local_or_non_absolute_source_paths(
    unsafe: str | Path,
) -> None:
    with pytest.raises(
        WeixinStateFamilyGuardError,
        match="absolute local fixed-volume path",
    ):
        snapshot_family(unsafe)


def test_snapshot_rejects_alternate_data_stream_syntax(tmp_path: Path) -> None:
    unsafe = f"{tmp_path / 'state.sqlite'}:payload"

    with pytest.raises(
        WeixinStateFamilyGuardError,
        match="alternate data stream",
    ):
        snapshot_family(unsafe)


@pytest.mark.skipif(os.name != "nt", reason="NTFS alternate stream coverage")
def test_snapshot_rejects_named_stream_attached_to_family_leaf(
    tmp_path: Path,
) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")
    try:
        with open(f"{main}:hidden", "wb") as stream:
            stream.write(b"hidden")
    except OSError as exc:
        pytest.skip(f"named streams are unavailable on this volume: {exc}")

    with pytest.raises(WeixinStateFamilyGuardError, match="alternate data stream"):
        snapshot_family(main)


def test_snapshot_records_closed_family_presence_and_parent_digest(
    tmp_path: Path,
) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}-journal").write_bytes(b"journal")
    Path(f"{main}.bridge.lock").write_bytes(b"lock")

    snapshot = snapshot_family(main)

    assert snapshot.kind is FamilyKind.ROLLBACK_CANDIDATE
    assert len(snapshot.parent_enumeration_sha256) == 64
    assert tuple(member.role for member in snapshot.members) == tuple(MemberRole)
    by_role = {member.role: member for member in snapshot.members}
    assert by_role[MemberRole.MAIN].present is True
    assert by_role[MemberRole.JOURNAL].present is True
    assert by_role[MemberRole.WAL].present is False
    assert by_role[MemberRole.SHM].present is False
    assert by_role[MemberRole.LOCK].present is True
    assert by_role[MemberRole.MAIN].sha256 == _sha256(b"main")
    assert by_role[MemberRole.JOURNAL].sha256 == _sha256(b"journal")


@pytest.mark.parametrize(
    "present_suffixes",
    (
        ("-journal",),
        ("", "-journal", "-wal", "-shm"),
        ("", "-wal"),
        ("", "-shm"),
    ),
)
def test_snapshot_rejects_invalid_sidecar_combinations(
    tmp_path: Path,
    present_suffixes: tuple[str, ...],
) -> None:
    main = tmp_path / "state.sqlite"
    for suffix in present_suffixes:
        Path(f"{main}{suffix}").write_bytes(suffix.encode("ascii") or b"main")

    with pytest.raises(WeixinStateFamilyGuardError, match="SQLite family"):
        snapshot_family(main)


@pytest.mark.parametrize(
    "unknown_suffix",
    ("-mj H123456789", ".unexpected", ".bridge.lock.backup"),
)
def test_snapshot_rejects_unknown_same_prefix_sibling(
    tmp_path: Path,
    unknown_suffix: str,
) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}{unknown_suffix}").write_bytes(b"unknown")

    with pytest.raises(WeixinStateFamilyGuardError, match="unknown SQLite sibling"):
        snapshot_family(main)


def test_snapshot_rejects_case_variant_of_a_known_sidecar(tmp_path: Path) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")
    (tmp_path / "STATE.SQLITE-journal").write_bytes(b"case-variant")

    with pytest.raises(WeixinStateFamilyGuardError, match="unknown SQLite sibling"):
        snapshot_family(main)


def _symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")


def test_snapshot_rejects_reparse_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    (real_parent / "state.sqlite").write_bytes(b"main")
    alias = tmp_path / "alias"
    _symlink_or_skip(alias, real_parent, directory=True)

    with pytest.raises(WeixinStateFamilyGuardError, match="non-reparse directory"):
        snapshot_family(alias / "state.sqlite")


def test_snapshot_rejects_reparse_leaf(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite"
    target.write_bytes(b"main")
    main = tmp_path / "state.sqlite"
    _symlink_or_skip(main, target)

    with pytest.raises(WeixinStateFamilyGuardError, match="non-reparse file"):
        snapshot_family(main)


@pytest.mark.parametrize(
    "reparse_role",
    (MemberRole.JOURNAL, MemberRole.WAL, MemberRole.SHM, MemberRole.LOCK),
)
def test_snapshot_rejects_each_reparse_sidecar_leaf(
    tmp_path: Path,
    reparse_role: MemberRole,
) -> None:
    main = tmp_path / "state.sqlite"
    if reparse_role in {MemberRole.WAL, MemberRole.SHM}:
        suffixes = ("", "-wal", "-shm")
    else:
        suffixes = ("", "-journal")
    if reparse_role is MemberRole.LOCK:
        suffixes += (".bridge.lock",)
    for suffix in suffixes:
        Path(f"{main}{suffix}").write_bytes(suffix.encode("ascii") or b"main")
    suffix = {
        MemberRole.JOURNAL: "-journal",
        MemberRole.WAL: "-wal",
        MemberRole.SHM: "-shm",
        MemberRole.LOCK: ".bridge.lock",
    }[reparse_role]
    leaf = Path(f"{main}{suffix}")
    leaf.unlink()
    target = tmp_path / f"target-{reparse_role.value}"
    target.write_bytes(b"target")
    _symlink_or_skip(leaf, target)

    with pytest.raises(WeixinStateFamilyGuardError, match="non-reparse file"):
        snapshot_family(main)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction coverage")
def test_snapshot_rejects_windows_parent_junction(tmp_path: Path) -> None:
    real_parent = tmp_path / "junction-target"
    real_parent.mkdir()
    (real_parent / "state.sqlite").write_bytes(b"main")
    junction = tmp_path / "junction"
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(real_parent)],
        capture_output=True,
        encoding="oem",
        errors="replace",
        check=False,
    )
    if created.returncode != 0:
        pytest.skip(f"junction creation is unavailable: {created.stderr}")

    with pytest.raises(WeixinStateFamilyGuardError, match="non-reparse directory"):
        snapshot_family(junction / "state.sqlite")


@pytest.mark.parametrize("hardlinked_role", tuple(MemberRole))
def test_snapshot_rejects_hardlinked_family_leaf(
    tmp_path: Path,
    hardlinked_role: MemberRole,
) -> None:
    main = tmp_path / "state.sqlite"
    if hardlinked_role in {MemberRole.WAL, MemberRole.SHM}:
        suffixes = ("", "-wal", "-shm")
    else:
        suffixes = ("", "-journal")
    if hardlinked_role is MemberRole.LOCK:
        suffixes += (".bridge.lock",)
    for suffix in suffixes:
        Path(f"{main}{suffix}").write_bytes(suffix.encode("ascii") or b"main")
    role_suffix = {
        MemberRole.MAIN: "",
        MemberRole.JOURNAL: "-journal",
        MemberRole.WAL: "-wal",
        MemberRole.SHM: "-shm",
        MemberRole.LOCK: ".bridge.lock",
    }[hardlinked_role]
    os.link(Path(f"{main}{role_suffix}"), tmp_path / "hardlink-evidence")

    with pytest.raises(WeixinStateFamilyGuardError, match="hardlinks are forbidden"):
        snapshot_family(main)


def test_clone_rejects_reparse_stage_directory(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}-journal").write_bytes(b"journal")
    real_stage = tmp_path / "real-stage"
    real_stage.mkdir()
    stage_alias = tmp_path / "stage-alias"
    _symlink_or_skip(stage_alias, real_stage, directory=True)

    with pytest.raises(WeixinStateFamilyGuardError, match="non-reparse directory"):
        clone_rollback_candidate(main, stage_alias)


@pytest.mark.parametrize(
    ("role", "suffix", "limit", "family_suffixes"),
    (
        (MemberRole.MAIN, "", MAX_MAIN_BYTES, ("", "-journal")),
        (MemberRole.JOURNAL, "-journal", MAX_JOURNAL_BYTES, ("", "-journal")),
        (MemberRole.WAL, "-wal", MAX_WAL_BYTES, ("", "-wal", "-shm")),
        (MemberRole.SHM, "-shm", MAX_SHM_BYTES, ("", "-wal", "-shm")),
        (
            MemberRole.LOCK,
            ".bridge.lock",
            MAX_LOCK_BYTES,
            ("", "-journal", ".bridge.lock"),
        ),
    ),
)
def test_snapshot_rejects_each_member_above_its_independent_byte_limit(
    tmp_path: Path,
    role: MemberRole,
    suffix: str,
    limit: int,
    family_suffixes: tuple[str, ...],
) -> None:
    main = tmp_path / "state.sqlite"
    for family_suffix in family_suffixes:
        path = Path(f"{main}{family_suffix}")
        path.write_bytes(b"x")
    with Path(f"{main}{suffix}").open("r+b") as oversized:
        oversized.truncate(limit + 1)

    with pytest.raises(WeixinStateFamilyGuardError, match="byte limit"):
        snapshot_family(main)


def test_clone_rejects_preexisting_target_without_overwriting_it(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"source-main")
    Path(f"{main}-journal").write_bytes(b"source-journal")
    existing = stage / main.name
    existing.write_bytes(b"do-not-overwrite")

    with pytest.raises(WeixinStateFamilyGuardError, match="target already exists"):
        clone_rollback_candidate(main, stage)

    assert existing.read_bytes() == b"do-not-overwrite"
    assert not (stage / f"{main.name}-journal").exists()


def test_clone_create_new_rejects_target_created_after_precheck(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}-journal").write_bytes(b"journal")
    raced_target = stage / main.name

    with pytest.raises(WeixinStateFamilyGuardError, match="target already exists"):
        clone_rollback_candidate(
            main,
            stage,
            seams=FamilyGuardSeams(
                after_snapshot=lambda: raced_target.write_bytes(b"attacker")
            ),
        )

    assert raced_target.read_bytes() == b"attacker"
    assert not (stage / f"{main.name}-journal").exists()


def test_clone_rejects_stage_reported_on_a_different_volume(tmp_path: Path) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}-journal").write_bytes(b"journal")

    def cross_volume(role: str, actual: int) -> int:
        return actual + 1 if role == "stage" else actual

    with pytest.raises(WeixinStateFamilyGuardError, match="same fixed volume"):
        clone_rollback_candidate(
            main,
            stage,
            seams=FamilyGuardSeams(volume_id=cross_volume),
        )


def test_snapshot_deadline_expires_at_equality(tmp_path: Path) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")
    ticks = iter((10.0, 11.0))

    with pytest.raises(WeixinStateFamilyGuardError, match="deadline expired"):
        snapshot_family(main, deadline_seconds=1.0, clock=lambda: next(ticks))


@pytest.mark.parametrize("invalid", (0.0, -1.0, math.inf, math.nan))
def test_snapshot_rejects_nonpositive_or_nonfinite_deadline(
    tmp_path: Path,
    invalid: float,
) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")

    with pytest.raises(WeixinStateFamilyGuardError, match="finite and positive"):
        snapshot_family(main, deadline_seconds=invalid)


@pytest.mark.parametrize("attack", ("replace", "write", "delete"))
def test_clone_rejects_source_toctou_after_snapshot(
    tmp_path: Path,
    attack: str,
) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"original-main")
    Path(f"{main}-journal").write_bytes(b"original-journal")

    def mutate_source() -> None:
        if attack == "replace":
            replacement = source / "replacement.tmp"
            replacement.write_bytes(b"replacement")
            os.replace(replacement, main)
        elif attack == "write":
            main.write_bytes(b"modified-main")
        else:
            main.unlink()

    with pytest.raises(
        WeixinStateFamilyGuardError,
        match="seam did not complete|changed|unavailable|enumeration",
    ):
        clone_rollback_candidate(
            main,
            stage,
            seams=FamilyGuardSeams(after_snapshot=mutate_source),
        )


def test_clone_rejects_parent_enumeration_drift(tmp_path: Path) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}-journal").write_bytes(b"journal")

    with pytest.raises(WeixinStateFamilyGuardError, match="parent enumeration changed"):
        clone_rollback_candidate(
            main,
            stage,
            seams=FamilyGuardSeams(
                before_source_revalidation=lambda: (source / "unrelated").write_bytes(
                    b"drift"
                )
            ),
        )


def test_clone_uses_one_absolute_deadline_across_snapshot_and_copy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    main.write_bytes(b"main")
    Path(f"{main}-journal").write_bytes(b"journal")
    now = [100.0]

    with pytest.raises(WeixinStateFamilyGuardError, match="deadline expired"):
        clone_rollback_candidate(
            main,
            stage,
            deadline_seconds=1.0,
            clock=lambda: now[0],
            seams=FamilyGuardSeams(
                after_snapshot=lambda: now.__setitem__(0, 101.0)
            ),
        )


@pytest.mark.parametrize(
    ("suffixes", "expected_kind"),
    (
        (("",), FamilyKind.CLEAN),
        (("", "-wal", "-shm"), FamilyKind.WAL_CANDIDATE),
    ),
)
def test_snapshot_accepts_closed_nonrollback_family_shapes_read_only(
    tmp_path: Path,
    suffixes: tuple[str, ...],
    expected_kind: FamilyKind,
) -> None:
    main = tmp_path / "state.sqlite"
    for suffix in suffixes:
        Path(f"{main}{suffix}").write_bytes(suffix.encode("ascii") or b"main")

    snapshot = snapshot_family(main)

    assert snapshot.kind is expected_kind


@pytest.mark.parametrize("suffixes", (("",), ("", "-wal", "-shm")))
def test_clone_refuses_every_nonrollback_family_shape(
    tmp_path: Path,
    suffixes: tuple[str, ...],
) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    for suffix in suffixes:
        Path(f"{main}{suffix}").write_bytes(suffix.encode("ascii") or b"main")

    with pytest.raises(WeixinStateFamilyGuardError, match="only rollback candidates"):
        clone_rollback_candidate(main, stage)


def test_clone_receipt_is_immutable_closed_metadata_without_paths_or_content(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    stage = tmp_path / "stage"
    source.mkdir()
    stage.mkdir()
    main = source / "state.sqlite"
    business_bytes = b"private-business-content-marker"
    main.write_bytes(business_bytes)
    Path(f"{main}-journal").write_bytes(b"journal")

    receipt = clone_rollback_candidate(main, stage)
    encoded = json.dumps(asdict(receipt), default=str, sort_keys=True)

    assert str(tmp_path) not in encoded
    assert business_bytes.decode("ascii") not in encoded
    assert receipt.outcome.value == "rollback_candidate_cloned"
    with pytest.raises(FrozenInstanceError):
        receipt.schema = 2  # type: ignore[misc]


@pytest.mark.skipif(os.name != "nt", reason="Windows handle identity coverage")
def test_windows_snapshot_receipt_uses_native_volume_and_file_index(
    tmp_path: Path,
) -> None:
    main = tmp_path / "state.sqlite"
    main.write_bytes(b"main")

    snapshot = snapshot_family(main)
    main_receipt = next(
        member for member in snapshot.members if member.role is MemberRole.MAIN
    )
    info = os.lstat(main)

    assert main_receipt.volume_serial == int(info.st_dev) & 0xFFFF_FFFF
    assert main_receipt.file_index == int(info.st_ino)
    assert main_receipt.attributes is not None
    assert main_receipt.attributes & 0x400 == 0
