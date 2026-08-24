from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from gateway.durable_media_requests import (
    DurableMediaRequestStore,
    DurableMediaRequestUnavailable,
    hash_media_request,
)
from gateway.paid_media_asset_protocol import RESULT_SCHEMA, create_asset_token


PRINCIPAL = "2" * 64
EPOCH = 7


def _video_metadata(version: int = 2) -> dict[str, object]:
    metadata: dict[str, object] = {
        "version": version,
        "task_alias": f"nvt1_{'f' * 64}",
        "requested_model": "paid-video",
        "provider_name": "provider-a",
        "provider_domain": "c" * 64,
        "provider_credential_domain": "d" * 64,
        "upstream_model": "upstream-video",
        "upstream_task_id": "upstream-task",
        "poll_attempt": 0,
        "poll_fencing_token": "",
        "poll_lease_expires_at": 0.0,
        "next_poll_at": 0.0,
        "last_response": None,
        "terminal_response": None,
    }
    if version == 2:
        metadata.update(
            {
                "prepared_token": "",
                "prepared_provider_response": None,
                "prepared_asset_response": None,
                "prepare_sha256": "",
            }
        )
    return metadata


@pytest.mark.parametrize(
    ("version", "field", "invalid"),
    [
        (1, "version", True),
        (2, "version", 2.0),
        (2, "provider_name", 123),
        (2, "provider_domain", int("1" * 64)),
    ],
)
def test_video_envelope_rejects_nonexact_json_scalar_types(
    version: int,
    field: str,
    invalid: object,
) -> None:
    metadata = _video_metadata(version)
    metadata[field] = invalid
    with pytest.raises(sqlite3.DatabaseError):
        DurableMediaRequestStore._validated_video_metadata(metadata)


def _claim_video(store: DurableMediaRequestStore, key: str):
    request_digest = hash_media_request(
        "videos.create", {"model": "paid-video", "prompt": key}
    )
    claim = store.claim(
        principal_hash=PRINCIPAL,
        operation="videos.create",
        idempotency_key=key,
        request_sha256=request_digest,
        now=1.0,
    )
    assert claim.state == "claimed"
    assert store.reserve_asset_capacity(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=PRINCIPAL,
        operation="videos.create",
        installation_epoch=EPOCH,
    )
    assert store.enter_provider_phase(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        max_success_bytes=1024 * 1024,
        now=2.0,
    )
    return claim, request_digest


def _asset_document(turn_id: str) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "kind": "video",
        "created": 1_784_200_000,
        "turnId": turn_id,
        "assets": [
            {
                "token": create_asset_token(),
                "mediaType": "video/mp4",
                "byteLength": 4096,
                "sha256": "a" * 64,
                "validationReceiptSha256": "b" * 64,
            }
        ],
    }


def _persist_nonterminal_create(
    store: DurableMediaRequestStore,
    *,
    claim,
) -> dict[str, object]:
    persisted, receipt = store.succeed_video(
        turn_id=claim.turn_id,
        fencing_token=claim.fencing_token,
        principal_hash=PRINCIPAL,
        response={
            "task_id": "provider-task-secret",
            "status": "queued",
            "url": "https://provider.invalid/must-not-persist.mp4",
        },
        requested_model="paid-video",
        provider_name="provider-a",
        provider_domain="c" * 64,
        provider_credential_domain="d" * 64,
        upstream_model="upstream-video",
        upstream_task_id="provider-task-secret",
        terminal=False,
        now=3.0,
    )
    assert persisted
    assert receipt == {
        "task_id": f"nvt1_{claim.turn_id}",
        "status": "processing",
    }
    return receipt


def test_video_terminal_asset_slot_is_replayable_restart_safe_and_ackable(
    tmp_path: Path,
) -> None:
    path = tmp_path / "paid-media-requests.db"
    store = DurableMediaRequestStore(path)
    claim, request_digest = _claim_video(
        store, "video-terminal-slot-1111111111111111"
    )
    receipt = _persist_nonterminal_create(store, claim=claim)
    alias = str(receipt["task_id"])

    replay = store.claim(
        principal_hash=PRINCIPAL,
        operation="videos.create",
        idempotency_key="video-terminal-slot-1111111111111111",
        request_sha256=request_digest,
        now=4.0,
    )
    assert replay.state == "succeeded" and replay.response == receipt

    first_poll = store.begin_video_poll(
        task_alias=alias, principal_hash=PRINCIPAL, now=5.0
    )
    assert first_poll.state == "claimed"
    saved, nonterminal = store.finish_video_poll(
        task_alias=alias,
        principal_hash=PRINCIPAL,
        fencing_token=first_poll.fencing_token,
        response={
            "status": "processing",
            "progress": 25,
            "url": "https://provider.invalid/not-terminal.mp4",
        },
        terminal=False,
        now=6.0,
    )
    assert saved
    assert nonterminal == {"task_id": alias, "status": "processing", "progress": 25}

    terminal_poll = store.begin_video_poll(
        task_alias=alias, principal_hash=PRINCIPAL, now=100.0
    )
    assert terminal_poll.state == "claimed"
    document = _asset_document(claim.turn_id)
    saved, public = store.finish_video_poll_asset(
        task_alias=alias,
        principal_hash=PRINCIPAL,
        fencing_token=terminal_poll.fencing_token,
        response=document,
        now=101.0,
    )
    assert saved and public == document
    assert store.begin_video_poll(
        task_alias=alias, principal_hash=PRINCIPAL, now=102.0
    ).response == document
    assert store.read_unacked_asset_success_document(
        turn_id=claim.turn_id,
        principal_hash=PRINCIPAL,
        operation="videos.create",
    ).response == document
    store.close()

    restarted = DurableMediaRequestStore(path)
    try:
        assert restarted.read_asset_success_document(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
        ).response == document
        token = str(document["assets"][0]["token"])
        ack = restarted.ack_asset_success(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
            installation_epoch=EPOCH,
            tokens=[token],
            archive_receipt_sha256="e" * 64,
            now=103.0,
        )
        assert not ack.replayed and not ack.cleanup_complete
        assert restarted.complete_asset_ack_cleanup(
            turn_id=claim.turn_id,
            principal_hash=PRINCIPAL,
            operation="videos.create",
            installation_epoch=EPOCH,
            token_set_digest=ack.token_set_digest,
            archive_receipt_sha256=ack.archive_receipt_sha256,
            now=104.0,
        )
        with sqlite3.connect(path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone() == (0,)
    finally:
        restarted.close()


def test_prepared_video_poll_survives_restart_before_asset_and_terminal_publish(
    tmp_path: Path,
) -> None:
    path = tmp_path / "prepared-recovery.db"
    store = DurableMediaRequestStore(path)
    claim, _request_digest = _claim_video(
        store, "video-prepared-recovery-111111111111"
    )
    receipt = _persist_nonterminal_create(store, claim=claim)
    alias = str(receipt["task_id"])
    poll = store.begin_video_poll(
        task_alias=alias,
        principal_hash=PRINCIPAL,
        now=4.0,
    )
    provider_terminal = {
        "status": "completed",
        "metadata": {
            "url": "https://provider.invalid/prepared.mp4",
        },
    }
    prepared = store.prepare_video_poll_asset(
        task_alias=alias,
        principal_hash=PRINCIPAL,
        fencing_token=poll.fencing_token,
        provider_response=provider_terminal,
        now=5.0,
    )
    assert prepared.asset_response is None
    assert prepared.provider_response == provider_terminal
    assert prepared.token.startswith("nma1_")
    assert len(prepared.prepare_sha256) == 64
    assert prepared.token not in repr(prepared)
    assert "prepared.mp4" not in repr(prepared)
    store.close()

    restarted = DurableMediaRequestStore(path)
    recovered = restarted.begin_video_poll(
        task_alias=alias,
        principal_hash=PRINCIPAL,
        now=400.0,
    )
    assert recovered.state == "prepared"
    assert recovered.prepared_token == prepared.token
    assert recovered.prepared_provider_response == provider_terminal
    assert recovered.prepared_asset_response is None
    assert recovered.prepare_sha256 == prepared.prepare_sha256
    assert prepared.token not in repr(recovered)
    assert "prepared.mp4" not in repr(recovered)
    document = _asset_document(claim.turn_id)
    document["assets"][0]["token"] = prepared.token
    attached = restarted.attach_video_poll_asset(
        task_alias=alias,
        principal_hash=PRINCIPAL,
        fencing_token=recovered.fencing_token,
        response=document,
        now=401.0,
    )
    assert attached.asset_response == document
    assert attached.prepare_sha256 != prepared.prepare_sha256
    restarted.close()

    final = DurableMediaRequestStore(path)
    try:
        persisted, public = final.commit_prepared_video_poll_asset(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            fencing_token=recovered.fencing_token,
            prepare_sha256=attached.prepare_sha256,
            now=402.0,
        )
        assert persisted and public == document
        terminal = final.begin_video_poll(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            now=403.0,
        )
        assert terminal.state == "terminal"
        assert terminal.response == document
    finally:
        final.close()


def test_expired_video_poll_owner_is_fenced_after_takeover(
    tmp_path: Path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "poll-takeover.db")
    try:
        claim, _request_digest = _claim_video(
            store, "video-poll-takeover-111111111111111"
        )
        receipt = _persist_nonterminal_create(store, claim=claim)
        alias = str(receipt["task_id"])
        old = store.begin_video_poll(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            now=4.0,
        )
        replacement = store.begin_video_poll(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            now=305.0,
        )
        assert replacement.state == "claimed"
        assert replacement.fencing_token != old.fencing_token
        provider_terminal = {
            "status": "completed",
            "metadata": {"url": "https://provider.invalid/takeover.mp4"},
        }
        with pytest.raises(DurableMediaRequestUnavailable):
            store.prepare_video_poll_asset(
                task_alias=alias,
                principal_hash=PRINCIPAL,
                fencing_token=old.fencing_token,
                provider_response=provider_terminal,
                now=306.0,
            )
        prepared = store.prepare_video_poll_asset(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            fencing_token=replacement.fencing_token,
            provider_response=provider_terminal,
            now=306.0,
        )
        assert prepared.token.startswith("nma1_")
    finally:
        store.close()


def test_prepared_video_rejects_wrong_fence_and_digest_without_root_mutation(
    tmp_path: Path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "prepared-negative.db")
    try:
        claim, _request_digest = _claim_video(
            store, "video-prepared-negative-111111111111"
        )
        receipt = _persist_nonterminal_create(store, claim=claim)
        alias = str(receipt["task_id"])
        poll = store.begin_video_poll(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            now=4.0,
        )
        provider_terminal = {
            "status": "completed",
            "metadata": {"url": "https://provider.invalid/negative.mp4"},
        }
        before = store.inspect_root_state()
        with pytest.raises(DurableMediaRequestUnavailable):
            store.prepare_video_poll_asset(
                task_alias=alias,
                principal_hash=PRINCIPAL,
                fencing_token="9" * 64,
                provider_response=provider_terminal,
                now=5.0,
            )
        assert store.inspect_root_state() == before

        prepared = store.prepare_video_poll_asset(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            fencing_token=poll.fencing_token,
            provider_response=provider_terminal,
            now=5.0,
        )
        document = _asset_document(claim.turn_id)
        document["assets"][0]["token"] = prepared.token
        attached = store.attach_video_poll_asset(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            fencing_token=poll.fencing_token,
            response=document,
            now=6.0,
        )
        before = store.inspect_root_state()
        with pytest.raises(DurableMediaRequestUnavailable):
            store.commit_prepared_video_poll_asset(
                task_alias=alias,
                principal_hash=PRINCIPAL,
                fencing_token=poll.fencing_token,
                prepare_sha256="8" * 64,
                now=7.0,
            )
        assert store.inspect_root_state() == before
        persisted, public = store.commit_prepared_video_poll_asset(
            task_alias=alias,
            principal_hash=PRINCIPAL,
            fencing_token=poll.fencing_token,
            prepare_sha256=attached.prepare_sha256,
            now=7.0,
        )
        assert persisted and public == document
    finally:
        store.close()


def test_immediate_terminal_video_keeps_create_receipt_separate_from_asset_result(
    tmp_path: Path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "immediate.db")
    try:
        claim, _request_digest = _claim_video(
            store, "video-immediate-terminal-111111111111"
        )
        document = _asset_document(claim.turn_id)
        persisted, receipt = store.succeed_video(
            turn_id=claim.turn_id,
            fencing_token=claim.fencing_token,
            principal_hash=PRINCIPAL,
            response={"task_id": "upstream", "status": "completed", "url": "https://x"},
            requested_model="paid-video",
            provider_name="provider-a",
            provider_domain="c" * 64,
            provider_credential_domain="d" * 64,
            upstream_model="upstream-video",
            upstream_task_id="upstream",
            terminal=True,
            terminal_asset_response=document,
            now=3.0,
        )
        assert persisted
        assert receipt == {
            "task_id": f"nvt1_{claim.turn_id}",
            "status": "processing",
        }
        terminal = store.begin_video_poll(
            task_alias=str(receipt["task_id"]),
            principal_hash=PRINCIPAL,
            now=4.0,
        )
        assert terminal.state == "terminal" and terminal.response == document
    finally:
        store.close()


def test_terminal_video_failure_releases_reserved_asset_capacity_without_url(
    tmp_path: Path,
) -> None:
    store = DurableMediaRequestStore(tmp_path / "failure.db")
    try:
        claim, _request_digest = _claim_video(
            store, "video-terminal-failure-11111111111111"
        )
        receipt = _persist_nonterminal_create(store, claim=claim)
        poll = store.begin_video_poll(
            task_alias=str(receipt["task_id"]), principal_hash=PRINCIPAL, now=4.0
        )
        saved, failure = store.finish_video_poll(
            task_alias=str(receipt["task_id"]),
            principal_hash=PRINCIPAL,
            fencing_token=poll.fencing_token,
            response={
                "status": "failed",
                "url": "https://provider.invalid/untrusted-error-url",
            },
            terminal=True,
            now=5.0,
        )
        assert saved
        assert failure == {"task_id": receipt["task_id"], "status": "failed"}
        with sqlite3.connect(store.path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone() == (192 * 1024 * 1024,)
            assert connection.execute(
                "SELECT COUNT(*) FROM durable_media_asset_authority"
            ).fetchone() == (1,)
        assert store.complete_video_terminal_failure_cleanup(
            task_alias=str(receipt["task_id"]),
            principal_hash=PRINCIPAL,
            now=6.0,
        )
        with sqlite3.connect(store.path) as connection:
            assert connection.execute(
                "SELECT reserved_total_bytes FROM durable_media_asset_capacity"
            ).fetchone() == (0,)
    finally:
        store.close()


def test_concurrent_terminal_video_asset_commit_has_one_fence_winner(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent.db"
    first = DurableMediaRequestStore(path)
    second = DurableMediaRequestStore(path)
    try:
        claim, _request_digest = _claim_video(
            first, "video-terminal-concurrent-1111111111"
        )
        receipt = _persist_nonterminal_create(first, claim=claim)
        poll = first.begin_video_poll(
            task_alias=str(receipt["task_id"]), principal_hash=PRINCIPAL, now=4.0
        )
        document = _asset_document(claim.turn_id)

        def finish(store: DurableMediaRequestStore):
            return store.finish_video_poll_asset(
                task_alias=str(receipt["task_id"]),
                principal_hash=PRINCIPAL,
                fencing_token=poll.fencing_token,
                response=document,
                now=5.0,
            )[0]

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(finish, (first, second)))
        assert sorted(results) == [False, True]
    finally:
        second.close()
        first.close()
