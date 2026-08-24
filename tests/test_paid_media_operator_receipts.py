from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import sqlite3

import pytest

from gateway.paid_media_operator_receipts import (
    PaidMediaOperatorReceiptConflict,
    PaidMediaOperatorReceiptStore,
    PaidMediaOperatorReceiptUnavailable,
    PaidMediaOperatorReceiptValidationError,
    PreparedRecoveryCandidate,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _candidate(label: str = "one") -> PreparedRecoveryCandidate:
    return PreparedRecoveryCandidate(
        operation_id="desktop-op-11111111-1111-4111-8111-111111111111",
        candidate_sha256=_digest(f"candidate:{label}"),
        consent_sha256=_digest(f"consent:{label}"),
        request_sha256=_digest(f"request:{label}"),
        prepared_sha256=_digest(f"prepared:{label}"),
    )


def test_inspect_creates_one_pending_decision_bound_to_candidate(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")

    decision = store.inspect(_candidate())

    assert decision.operation_id == _candidate().operation_id
    assert decision.candidate_sha256 == _candidate().candidate_sha256
    assert decision.state == "pending"
    assert decision.confirmation_text.startswith("RECOVER PREPARED ")


def test_inspect_exact_replay_returns_the_original_decision(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")

    first = store.inspect(_candidate())
    replay = store.inspect(_candidate())

    assert replay == first


def test_exact_challenge_confirmation_authorizes_execution(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    candidate = _candidate()
    pending = store.inspect(candidate)

    executing = store.authorize(
        candidate,
        decision_id=pending.decision_id,
        confirmation_text=pending.confirmation_text,
    )

    assert executing.state == "executing"
    assert executing.authorized_at_ms is not None
    assert store.inspect(candidate) == executing


def test_authorized_decision_commits_a_digest_only_completion_receipt(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    candidate = _candidate()
    pending = store.inspect(candidate)
    store.authorize(
        candidate,
        decision_id=pending.decision_id,
        confirmation_text=pending.confirmation_text,
    )

    receipt = store.complete(
        candidate,
        decision_id=pending.decision_id,
        result_sha256=_digest("result"),
        archive_receipt_sha256=_digest("archive"),
        ack_receipt_sha256=_digest("ack"),
    )

    assert receipt.operation_id == candidate.operation_id
    assert receipt.decision_id == pending.decision_id
    assert receipt.candidate_sha256 == candidate.candidate_sha256
    assert receipt.result_sha256 == _digest("result")
    assert receipt.archive_receipt_sha256 == _digest("archive")
    assert receipt.ack_receipt_sha256 == _digest("ack")
    assert len(receipt.receipt_sha256) == 64
    assert store.inspect(candidate).state == "completed"


def test_inspect_rejects_candidate_drift_without_replacing_decision(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    original = _candidate()
    decision = store.inspect(original)
    drifted = PreparedRecoveryCandidate(
        operation_id=original.operation_id,
        candidate_sha256=_digest("candidate:drifted"),
        consent_sha256=original.consent_sha256,
        request_sha256=original.request_sha256,
        prepared_sha256=original.prepared_sha256,
    )

    with pytest.raises(PaidMediaOperatorReceiptConflict):
        store.inspect(drifted)

    assert store.inspect(original) == decision


def test_wrong_confirmation_cannot_leave_pending_state(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    candidate = _candidate()
    pending = store.inspect(candidate)

    with pytest.raises(PaidMediaOperatorReceiptValidationError):
        store.authorize(
            candidate,
            decision_id=pending.decision_id,
            confirmation_text="RECOVER PREPARED 000000000000",
        )

    assert store.inspect(candidate) == pending


def test_second_decision_id_cannot_authorize_existing_candidate(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    candidate = _candidate()
    pending = store.inspect(candidate)
    second_decision_id = "operator-recovery-decision-v1:" + ("f" * 64)

    with pytest.raises(PaidMediaOperatorReceiptConflict):
        store.authorize(
            candidate,
            decision_id=second_decision_id,
            confirmation_text=pending.confirmation_text,
        )

    assert store.inspect(candidate) == pending


def test_completion_requires_authorized_executing_state(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    candidate = _candidate()
    pending = store.inspect(candidate)

    with pytest.raises(PaidMediaOperatorReceiptConflict):
        store.complete(
            candidate,
            decision_id=pending.decision_id,
            result_sha256=_digest("result"),
            archive_receipt_sha256=_digest("archive"),
            ack_receipt_sha256=_digest("ack"),
        )

    assert store.inspect(candidate) == pending


def test_authorize_and_complete_are_exactly_replayable_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "operator-recovery.db"
    candidate = _candidate()
    store = PaidMediaOperatorReceiptStore(path)
    pending = store.inspect(candidate)
    executing = store.authorize(
        candidate,
        decision_id=pending.decision_id,
        confirmation_text=pending.confirmation_text,
    )

    reopened = PaidMediaOperatorReceiptStore(path)
    assert (
        reopened.authorize(
            candidate,
            decision_id=pending.decision_id,
            confirmation_text=pending.confirmation_text,
        )
        == executing
    )
    first = reopened.complete(
        candidate,
        decision_id=pending.decision_id,
        result_sha256=_digest("result"),
        archive_receipt_sha256=_digest("archive"),
        ack_receipt_sha256=_digest("ack"),
    )
    replay = PaidMediaOperatorReceiptStore(path).complete(
        candidate,
        decision_id=pending.decision_id,
        result_sha256=_digest("result"),
        archive_receipt_sha256=_digest("archive"),
        ack_receipt_sha256=_digest("ack"),
    )

    assert replay == first


def test_completed_proof_drift_fails_closed(
    tmp_path: Path,
) -> None:
    store = PaidMediaOperatorReceiptStore(tmp_path / "operator-recovery.db")
    candidate = _candidate()
    pending = store.inspect(candidate)
    store.authorize(
        candidate,
        decision_id=pending.decision_id,
        confirmation_text=pending.confirmation_text,
    )
    original = store.complete(
        candidate,
        decision_id=pending.decision_id,
        result_sha256=_digest("result"),
        archive_receipt_sha256=_digest("archive"),
        ack_receipt_sha256=_digest("ack"),
    )

    with pytest.raises(PaidMediaOperatorReceiptConflict):
        store.complete(
            candidate,
            decision_id=pending.decision_id,
            result_sha256=_digest("different-result"),
            archive_receipt_sha256=original.archive_receipt_sha256,
            ack_receipt_sha256=original.ack_receipt_sha256,
        )


def test_sqlite_identity_and_receipt_schema_store_only_digest_bindings(
    tmp_path: Path,
) -> None:
    path = tmp_path / "operator-recovery.db"
    store = PaidMediaOperatorReceiptStore(path)
    candidate = _candidate()
    pending = store.inspect(candidate)
    store.authorize(
        candidate,
        decision_id=pending.decision_id,
        confirmation_text=pending.confirmation_text,
    )
    store.complete(
        candidate,
        decision_id=pending.decision_id,
        result_sha256=_digest("result"),
        archive_receipt_sha256=_digest("archive"),
        ack_receipt_sha256=_digest("ack"),
    )

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone() == (
            0x4E434F52,
        )
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(paid_media_operator_recovery_decisions)"
            )
        }

    assert columns == {
        "operation_id",
        "decision_id",
        "candidate_sha256",
        "consent_sha256",
        "request_sha256",
        "prepared_sha256",
        "challenge",
        "state",
        "created_at_ms",
        "authorized_at_ms",
        "completed_at_ms",
        "result_sha256",
        "archive_receipt_sha256",
        "ack_receipt_sha256",
        "receipt_sha256",
    }
    database_family = b"".join(
        candidate_path.read_bytes().lower()
        for candidate_path in (
            path,
            Path(f"{path}-wal"),
            Path(f"{path}-shm"),
            Path(f"{path}-journal"),
        )
        if candidate_path.is_file()
    )
    for forbidden in (
        b"principal",
        b"alias",
        b"token",
        b"url",
        b"provider",
        b"response_body",
    ):
        assert forbidden not in database_family


def test_concurrent_inspection_still_issues_exactly_one_decision(
    tmp_path: Path,
) -> None:
    path = tmp_path / "operator-recovery.db"
    candidate = _candidate()
    PaidMediaOperatorReceiptStore(path)

    def inspect_once() -> object:
        return PaidMediaOperatorReceiptStore(path).inspect(candidate)

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(lambda _index: inspect_once(), range(24)))

    assert len(set(decisions)) == 1


def test_unknown_sqlite_version_fails_closed_on_reopen(tmp_path: Path) -> None:
    path = tmp_path / "operator-recovery.db"
    PaidMediaOperatorReceiptStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=999")

    with pytest.raises(PaidMediaOperatorReceiptUnavailable):
        PaidMediaOperatorReceiptStore(path)


def test_malformed_persisted_challenge_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "operator-recovery.db"
    candidate = _candidate()
    PaidMediaOperatorReceiptStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO paid_media_operator_recovery_decisions(
                operation_id,decision_id,candidate_sha256,consent_sha256,
                request_sha256,prepared_sha256,challenge,state,
                created_at_ms,authorized_at_ms,completed_at_ms,
                result_sha256,archive_receipt_sha256,ack_receipt_sha256,
                receipt_sha256
            ) VALUES(?,?,?,?,?,?,'!!!!!!!!!!!!','pending',1,NULL,NULL,
                     NULL,NULL,NULL,NULL)
            """,
            (
                candidate.operation_id,
                "operator-recovery-decision-v1:" + ("a" * 64),
                candidate.candidate_sha256,
                candidate.consent_sha256,
                candidate.request_sha256,
                candidate.prepared_sha256,
            ),
        )

    with pytest.raises(PaidMediaOperatorReceiptUnavailable):
        PaidMediaOperatorReceiptStore(path).inspect(candidate)
