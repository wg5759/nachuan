"""Undo is an exact, one-time server capability, never an arbitrary write API."""

from __future__ import annotations

from pathlib import Path
import time

import pytest

from orchestrator.undo_receipts import UndoReceiptError, UndoReceiptStore


def _store(tmp_path: Path) -> UndoReceiptStore:
    return UndoReceiptStore(tmp_path / "undo.db", b"u" * 32)


def test_receipt_restores_exact_preimage_once(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("before", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )
    target.write_text("after", encoding="utf-8")

    assert store.restore(token, "before")["status"] == "restored"
    assert target.read_text(encoding="utf-8") == "before"
    with pytest.raises(UndoReceiptError, match="已使用"):
        store.restore(token, "before")
    store.close()


def test_receipt_rejects_forged_content_and_preserves_file(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("after", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )
    with pytest.raises(UndoReceiptError, match="不匹配"):
        store.restore(token, "attacker-controlled")
    assert target.read_text(encoding="utf-8") == "after"
    store.close()


def test_receipt_refuses_to_clobber_later_changes(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    target = root / "new.txt"
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="new.txt", before="", after="agent", existed=False
    )
    target.write_text("human edit", encoding="utf-8")
    with pytest.raises(UndoReceiptError, match="又被修改"):
        store.restore(token, "")
    assert target.read_text(encoding="utf-8") == "human edit"
    store.close()


def test_new_file_receipt_removes_only_agent_created_file(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    target = root / "new.txt"
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="new.txt", before="", after="agent", existed=False
    )
    target.write_text("agent", encoding="utf-8")
    store.restore(token, "")
    assert not target.exists()
    store.close()


def test_receipt_rejects_target_reparse_swap_even_with_identical_content(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("before", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )
    target.unlink()
    outside = tmp_path / "outside.txt"
    outside.write_text("after", encoding="utf-8")
    try:
        target.symlink_to(outside)
    except OSError as exc:
        store.close()
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(UndoReceiptError, match="已改变"):
        store.restore(token, "before")
    assert outside.read_text(encoding="utf-8") == "after"
    store.close()


def test_stale_executing_receipt_recovers_after_process_crash(tmp_path: Path) -> None:
    from orchestrator import undo_receipts as undo_module

    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("before", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )
    target.write_text("after", encoding="utf-8")
    payload = store._decode(token)
    store._conn.execute(
        "UPDATE undo_receipts SET status='executing',started_at=? WHERE jti=?",
        (time.time() - undo_module._EXECUTING_LEASE_SECONDS - 1, payload["jti"]),
    )
    store._conn.commit()

    assert store.restore(token, "before")["status"] == "restored"
    assert target.read_text(encoding="utf-8") == "before"
    store.close()


def test_stale_executing_receipt_recognizes_already_applied_restore(tmp_path: Path) -> None:
    from orchestrator import undo_receipts as undo_module

    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("before", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )
    payload = store._decode(token)
    store._conn.execute(
        "UPDATE undo_receipts SET status='executing',started_at=? WHERE jti=?",
        (time.time() - undo_module._EXECUTING_LEASE_SECONDS - 1, payload["jti"]),
    )
    store._conn.commit()

    assert store.restore(token, "before")["status"] == "restored"
    assert target.read_text(encoding="utf-8") == "before"
    store.close()


def test_receipt_row_capacity_fails_closed_without_evicting_live_receipts(
    tmp_path: Path, monkeypatch
) -> None:
    from orchestrator import undo_receipts as undo_module

    monkeypatch.setattr(undo_module, "_MAX_RECEIPT_ROWS", 1)
    root = tmp_path / "work"
    root.mkdir()
    store = _store(tmp_path)
    first = store.issue(
        workdir=str(root), path="a.txt", before="", after="a", existed=False
    )
    second = store.issue(
        workdir=str(root), path="b.txt", before="", after="b", existed=False
    )
    assert first
    assert second == ""
    assert store._conn.execute("SELECT COUNT(*) FROM undo_receipts").fetchone()[0] == 1
    store.close()


def test_receipt_refuses_oversized_later_file_without_unbounded_read(tmp_path: Path) -> None:
    from orchestrator import undo_receipts as undo_module

    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("after", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )
    target.write_bytes(b"x" * (undo_module._MAX_TEXT_BYTES + 1))
    with pytest.raises(UndoReceiptError, match="大小上限"):
        store.restore(token, "before")
    assert target.stat().st_size == undo_module._MAX_TEXT_BYTES + 1
    store.close()


def test_projection_verifies_exact_live_receipt_without_consuming_it(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )

    assert store.verify_projection(
        token, path="a.txt", before="before", after="after"
    )
    assert not store.verify_projection(
        token, path="other.txt", before="before", after="after"
    )
    assert not store.verify_projection(
        token, path="a.txt", before="forged", after="after"
    )
    assert not store.verify_projection(
        token, path="a.txt", before="before", after="forged"
    )

    payload = store._decode(token)
    assert store._conn.execute(
        "SELECT status FROM undo_receipts WHERE jti=?", (payload["jti"],)
    ).fetchone() == ("pending",)
    store.close()


def test_projection_rejects_consumed_receipt(tmp_path: Path) -> None:
    root = tmp_path / "work"
    root.mkdir()
    target = root / "a.txt"
    target.write_text("after", encoding="utf-8")
    store = _store(tmp_path)
    token = store.issue(
        workdir=str(root), path="a.txt", before="before", after="after", existed=True
    )

    assert store.restore(token, "before")["status"] == "restored"
    assert not store.verify_projection(
        token, path="a.txt", before="before", after="after"
    )
    store.close()
