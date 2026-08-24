from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
from gateway.app import app
from gateway.providers.base import ProviderError
from gateway.provider_call_ledger import (
    ProviderCallContext,
    ProviderCallLedger,
    ProviderRouteIdentity,
)
from gateway.router import Router
from gateway.route_attestation import bind_agent_author_receipt, seal_route_receipt
from gateway.weixin_idempotency import (
    WeixinIdempotencyStore,
    WeixinIdempotencyUnavailable,
    hash_channel_principal,
    hash_turn_identity,
    hash_weixin_request,
    validate_channel_idempotency_key,
    validate_weixin_idempotency_key,
)
from orchestrator.agent import (
    BufferedConversationStore,
    ConversationReceiptUnavailable,
    ConversationStore,
    session_key,
)


AUTH = {"Authorization": "Bearer test-key"}
KEY = "wxmsg-v1:" + ("a" * 64)


class _VerifiedChatRouter:
    def __init__(self) -> None:
        self._route = SimpleNamespace(
            provider=SimpleNamespace(name="provider-a"),
            upstream_model="upstream-a",
            tier="cheap",
            modality="chat",
            exec_backend="",
        )

    def resolve(self, model: str):
        return self._route if model == "model-a" else None

    def routes_info(self) -> list[dict[str, object]]:
        return [
            {
                "model": "model-a",
                "tier": "cheap",
                "modality": "chat",
                "rank": 1,
                "flagship": False,
            }
        ]

    async def aclose(self) -> None:
        return None


@contextmanager
def _verified_chat_route(client: TestClient):
    original_router = client.app.state.router
    client.app.state.router = _VerifiedChatRouter()
    try:
        yield
    finally:
        client.app.state.router = original_router


@pytest.fixture(autouse=True)
def _install_verified_model_a(monkeypatch):
    """Keep idempotency tests off the diagnostics-only echo route."""

    original_resolve = Router.resolve
    route = SimpleNamespace(
        provider=SimpleNamespace(name="provider-a"),
        upstream_model="upstream-a",
        tier="cheap",
        modality="chat",
        exec_backend="",
    )

    def resolve(self, model: str):
        if model == "model-a":
            return route
        return original_resolve(self, model)

    monkeypatch.setattr(Router, "resolve", resolve)


def _truthful_agent_result(
    reply: str = "stable reply",
    *,
    model: str = "model-a",
    outcome: str = "completed_unverified",
    blocked: bool = False,
) -> dict[str, object]:
    verified = outcome == "completed"
    return {
        "reply": reply,
        "model": model,
        "turns": 1,
        "usage": {},
        "outcome": outcome,
        "blocked": blocked,
        "reviewed": verified,
        "verified": verified,
        "machine_verified": verified,
    }


def _principal(user_id: str = "user-1", chat_id: str = "chat-1") -> str:
    return hash_channel_principal(
        channel="weixin", user_id=user_id, chat_id=chat_id
    )


def _request_hash(message: str = "hello") -> str:
    return hash_weixin_request(
        channel="weixin",
        chat_id="chat-1",
        user_id="user-1",
        message=message,
        model="model-a",
        system=None,
        video_async=False,
    )


def test_sqlite_claim_is_atomic_across_concurrent_callers(tmp_path):
    store = WeixinIdempotencyStore(tmp_path / "turns.db", lease_seconds=60)
    principal = _principal()

    def claim_once():
        return store.claim(principal, KEY, _request_hash(), now=100.0)

    with ThreadPoolExecutor(max_workers=12) as pool:
        claims = list(pool.map(lambda _index: claim_once(), range(24)))

    assert sum(claim.state == "claimed" for claim in claims) == 1
    assert sum(claim.state == "processing" for claim in claims) == 23
    assert len({claim.fencing_token for claim in claims if claim.state == "claimed"}) == 1


def test_record_capacity_is_hard_across_independent_store_instances(tmp_path):
    path = tmp_path / "turns.db"
    stores = [
        WeixinIdempotencyStore(path, lease_seconds=60, max_records=2)
        for _ in range(4)
    ]
    principal = _principal()

    def claim_distinct(index: int) -> str:
        key = "wxmsg-v1:" + f"{index + 1:064x}"
        try:
            return stores[index % len(stores)].claim(
                principal,
                key,
                _request_hash(f"capacity-{index}"),
                now=100.0,
            ).state
        except WeixinIdempotencyUnavailable:
            return "capacity"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(claim_distinct, range(16)))

    assert outcomes.count("claimed") == 2
    assert outcomes.count("capacity") == 14
    with sqlite3.connect(path) as connection:
        actual = connection.execute(
            "SELECT COUNT(*) FROM weixin_agent_idempotency"
        ).fetchone()[0]
        accounted = connection.execute(
            "SELECT record_count FROM weixin_agent_idempotency_meta WHERE singleton=1"
        ).fetchone()[0]
    assert actual == accounted == 2


def test_legacy_ledger_migrates_exact_usage_counters_once(tmp_path):
    path = tmp_path / "turns.db"
    payload = json.dumps({"reply": "legacy"}, separators=(",", ":"))
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE weixin_agent_idempotency (
                principal_hash TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                fencing_token TEXT NOT NULL,
                lease_expires_at REAL NOT NULL,
                attempt_count INTEGER NOT NULL,
                response_json TEXT,
                last_error_code TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(principal_hash, key_hash)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            "INSERT INTO weixin_agent_idempotency ("
            "principal_hash,key_hash,request_sha256,status,fencing_token,"
            "lease_expires_at,attempt_count,response_json,last_error_code,"
            "created_at,updated_at) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?)",
            (
                _principal(),
                "b" * 64,
                _request_hash(),
                "succeeded",
                "",
                0.0,
                1,
                payload,
                "",
                1.0,
                1.0,
            ),
        )
        connection.commit()

    WeixinIdempotencyStore(path)
    with sqlite3.connect(path) as connection:
        meta = connection.execute(
            "SELECT record_count,response_bytes FROM "
            "weixin_agent_idempotency_meta WHERE singleton=1"
        ).fetchone()
        phase = connection.execute(
            "SELECT provider_phase FROM weixin_agent_idempotency"
        ).fetchone()
        recovery = connection.execute(
            "SELECT recovery_id FROM weixin_agent_idempotency"
        ).fetchone()
        recovery_indexes = {
            str(row[1]): int(row[2])
            for row in connection.execute(
                "PRAGMA index_list(weixin_agent_idempotency)"
            ).fetchall()
        }
    assert meta == (1, len(payload.encode("utf-8")))
    assert phase == (0,)
    expected_recovery = hashlib.sha256(
        b"nachuan-weixin-turn-v1\x00"
        + _principal().encode("ascii")
        + b"\x00"
        + ("b" * 64).encode("ascii")
    ).hexdigest()
    assert recovery == (expected_recovery,)
    assert recovery_indexes["weixin_idempotency_recovery_idx"] == 1


def test_legacy_recovery_id_backfill_fails_closed_above_configured_bound(tmp_path):
    path = tmp_path / "oversized-legacy-turns.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE weixin_agent_idempotency (
                principal_hash TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                fencing_token TEXT NOT NULL,
                lease_expires_at REAL NOT NULL,
                attempt_count INTEGER NOT NULL,
                response_json TEXT,
                last_error_code TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY(principal_hash, key_hash)
            ) WITHOUT ROWID
            """
        )
        connection.executemany(
            "INSERT INTO weixin_agent_idempotency ("
            "principal_hash,key_hash,request_sha256,status,fencing_token,"
            "lease_expires_at,attempt_count,response_json,last_error_code,"
            "created_at,updated_at) VALUES (?,?,?,'failed','',0,1,NULL,'',1,1)",
            [
                ("1" * 64, "3" * 64, "4" * 64),
                ("2" * 64, "3" * 64, "4" * 64),
            ],
        )
        connection.commit()

    with pytest.raises(
        WeixinIdempotencyUnavailable,
        match="cannot initialize idempotency ledger",
    ):
        WeixinIdempotencyStore(path, max_records=1)


def test_provider_phase_atomically_fences_expired_owner_and_survives_reclaim(tmp_path):
    store = WeixinIdempotencyStore(tmp_path / "turns.db", lease_seconds=10)
    principal = _principal()
    request_hash = _request_hash("provider-phase")
    first = store.claim(principal, KEY, request_hash, now=10.0)
    assert first.state == "claimed"

    second = store.claim(principal, KEY, request_hash, now=20.001)
    assert second.state == "claimed"
    assert not store.enter_provider_phase(
        principal,
        KEY,
        request_hash,
        first.fencing_token,
        now=20.002,
    )
    assert store.enter_provider_phase(
        principal,
        KEY,
        request_hash,
        second.fencing_token,
        now=20.002,
    )

    recovery = store.claim(principal, KEY, request_hash, now=30.003)
    assert recovery.state == "recovery_required"
    assert recovery.fencing_token not in {"", second.fencing_token}
    assert not store.enter_provider_phase(
        principal,
        KEY,
        request_hash,
        recovery.fencing_token,
        now=30.004,
    )
    assert store.succeed(
        principal,
        KEY,
        request_hash,
        recovery.fencing_token,
        {"reply": "safe recovery notice"},
        now=30.004,
    )


def test_success_survives_restart_and_conflicting_semantics_are_rejected(tmp_path):
    path = tmp_path / "turns.db"
    principal = _principal()
    first = WeixinIdempotencyStore(path, lease_seconds=60)
    claim = first.claim(principal, KEY, _request_hash(), now=100.0)
    assert claim.state == "claimed"
    assert first.succeed(
        principal,
        KEY,
        _request_hash(),
        claim.fencing_token,
        {"reply": "cached business reply", "model": "model-a", "turns": 1},
        now=101.0,
    )

    restarted = WeixinIdempotencyStore(path, lease_seconds=60)
    cached = restarted.claim(principal, KEY, _request_hash(), now=500.0)
    assert cached.state == "succeeded"
    assert cached.response == {
        "reply": "cached business reply",
        "model": "model-a",
        "turns": 1,
    }
    conflict = restarted.claim(principal, KEY, _request_hash("different"), now=500.0)
    assert conflict.state == "conflict"


def test_failure_is_retryable_and_expired_claim_is_fenced(tmp_path):
    store = WeixinIdempotencyStore(tmp_path / "turns.db", lease_seconds=10)
    principal = _principal()
    failed = store.claim(principal, KEY, _request_hash(), now=10.0)
    assert failed.state == "claimed"
    assert store.fail(
        principal,
        KEY,
        _request_hash(),
        failed.fencing_token,
        error_code="ProviderError",
        now=11.0,
    )
    retry = store.claim(principal, KEY, _request_hash(), now=12.0)
    assert retry.state == "claimed"
    assert retry.fencing_token != failed.fencing_token

    reclaimed = store.claim(principal, KEY, _request_hash(), now=23.0)
    assert reclaimed.state == "claimed"
    assert reclaimed.fencing_token != retry.fencing_token
    assert not store.succeed(
        principal,
        KEY,
        _request_hash(),
        retry.fencing_token,
        {"reply": "stale"},
        now=24.0,
    )
    assert store.succeed(
        principal,
        KEY,
        _request_hash(),
        reclaimed.fencing_token,
        {"reply": "winner"},
        now=24.0,
    )
    assert store.claim(principal, KEY, _request_hash(), now=25.0).response == {
        "reply": "winner"
    }


def test_expired_owner_cannot_renew_commit_or_release_without_reclaim(tmp_path):
    store = WeixinIdempotencyStore(tmp_path / "turns.db", lease_seconds=10)
    principal = _principal()
    claim = store.claim(principal, KEY, _request_hash(), now=10.0)
    assert claim.state == "claimed"

    assert not store.renew(
        principal, KEY, _request_hash(), claim.fencing_token, now=20.001
    )
    assert not store.succeed(
        principal,
        KEY,
        _request_hash(),
        claim.fencing_token,
        {"reply": "expired owner must not commit"},
        now=20.001,
    )
    assert not store.fail(
        principal,
        KEY,
        _request_hash(),
        claim.fencing_token,
        error_code="late_failure",
        now=20.001,
    )


def test_idempotency_store_rejects_symlink_database_path(tmp_path):
    target = tmp_path / "outside.db"
    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE outside_marker(value TEXT)")
    link = tmp_path / "turns.db"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("current platform policy does not permit symlink creation")

    with pytest.raises(WeixinIdempotencyUnavailable) as caught:
        WeixinIdempotencyStore(link)
    assert isinstance(caught.value.__cause__, OSError)
    assert "reparse" in str(caught.value.__cause__).lower()


def test_idempotency_store_rejects_symlink_parent_directory(tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        os.symlink(real_parent, linked_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("current platform policy does not permit directory symlinks")

    with pytest.raises(WeixinIdempotencyUnavailable) as caught:
        WeixinIdempotencyStore(linked_parent / "turns.db")
    assert isinstance(caught.value.__cause__, OSError)
    assert "reparse" in str(caught.value.__cause__).lower()


def test_idempotency_store_rechecks_path_before_each_connection(tmp_path):
    path = tmp_path / "turns.db"
    store = WeixinIdempotencyStore(path)
    target = tmp_path / "replacement.db"
    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE outside_marker(value TEXT)")
    # The live WAL keeper deliberately pins the database on Windows, closing
    # the common replacement window.  Close it to simulate a post-shutdown
    # pathname swap and prove every later operation still revalidates.
    store.close()
    path.unlink()
    try:
        os.symlink(target, path)
    except (OSError, NotImplementedError):
        pytest.skip("current platform policy does not permit symlink creation")

    with pytest.raises(WeixinIdempotencyUnavailable, match="closed"):
        store.claim(_principal(), KEY, _request_hash(), now=1.0)
    with pytest.raises(WeixinIdempotencyUnavailable) as caught:
        WeixinIdempotencyStore(path)
    assert isinstance(caught.value.__cause__, OSError)
    assert "reparse" in str(caught.value.__cause__).lower()


def test_database_retains_only_hashes_not_api_key_request_or_raw_idempotency_key(tmp_path):
    path = tmp_path / "turns.db"
    api_key = "api-key-must-never-be-persisted"
    message = "sensitive-request-original-must-never-be-persisted"
    store = WeixinIdempotencyStore(path)
    principal = _principal()
    request_hash = _request_hash(message)
    claim = store.claim(principal, KEY, request_hash, now=1.0)
    assert store.succeed(
        principal,
        KEY,
        request_hash,
        claim.fencing_token,
        {"reply": "allowed business response"},
        now=2.0,
    )

    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT principal_hash,key_hash,request_sha256,response_json "
            "FROM weixin_agent_idempotency"
        ).fetchone()
    assert row is not None
    serialized = json.dumps(row, ensure_ascii=False)
    assert api_key not in serialized
    assert message not in serialized
    assert KEY not in serialized
    assert row[0] == principal
    assert row[2] == request_hash
    assert json.loads(row[3]) == {"reply": "allowed business response"}


def test_idempotency_store_prunes_terminal_rows_by_ttl_and_max_count(tmp_path):
    path = tmp_path / "turns.db"
    store = WeixinIdempotencyStore(
        path,
        lease_seconds=10,
        retention_seconds=100,
        max_records=2,
        prune_batch=10,
    )
    principal = _principal()

    def complete(hex_digit: str, now: float) -> None:
        key = "wxmsg-v1:" + (hex_digit * 64)
        request_hash = _request_hash(f"message-{hex_digit}")
        claim = store.claim(principal, key, request_hash, now=now)
        assert claim.state == "claimed"
        assert store.succeed(
            principal,
            key,
            request_hash,
            claim.fencing_token,
            {"reply": f"reply-{hex_digit}"},
            now=now + 1,
        )

    complete("1", 1)
    complete("2", 2)
    complete("3", 3)
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM weixin_agent_idempotency").fetchone()[0] <= 2

    # A later claim removes every terminal row older than the conservative TTL.
    fresh_key = "wxmsg-v1:" + ("4" * 64)
    store.claim(principal, fresh_key, _request_hash("fresh"), now=1000)
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT status,updated_at FROM weixin_agent_idempotency ORDER BY updated_at"
        ).fetchall()
    assert rows == [("processing", 1000.0)]


def test_idempotency_store_enforces_total_response_byte_budget(tmp_path):
    path = tmp_path / "turns.db"
    store = WeixinIdempotencyStore(
        path,
        lease_seconds=10,
        max_records=100,
        max_total_response_bytes=60,
        prune_batch=1,
    )
    principal = _principal()

    first_key = "wxmsg-v1:" + ("5" * 64)
    first_hash = _request_hash("first-byte-budget")
    first = store.claim(principal, first_key, first_hash, now=1.0)
    assert store.succeed(
        principal,
        first_key,
        first_hash,
        first.fencing_token,
        {"reply": "x" * 32},
        now=2.0,
    )

    second_key = "wxmsg-v1:" + ("6" * 64)
    second_hash = _request_hash("second-byte-budget")
    second = store.claim(principal, second_key, second_hash, now=3.0)
    assert store.succeed(
        principal,
        second_key,
        second_hash,
        second.fencing_token,
        {"reply": "y" * 32},
        now=4.0,
    )

    with sqlite3.connect(path) as connection:
        count, response_bytes = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(response_json AS BLOB))),0) "
            "FROM weixin_agent_idempotency WHERE response_json IS NOT NULL"
        ).fetchone()
    assert count == 1
    assert response_bytes <= 60


def test_byte_budget_cleanup_never_evicts_the_replay_being_claimed(tmp_path):
    path = tmp_path / "turns.db"
    principal = _principal()
    producer = WeixinIdempotencyStore(
        path,
        lease_seconds=10,
        max_records=100,
        max_total_response_bytes=1_000,
        prune_batch=1,
    )
    first_key = "wxmsg-v1:" + ("d" * 64)
    second_key = "wxmsg-v1:" + ("e" * 64)
    first_hash = _request_hash("protected-oldest-replay")
    second_hash = _request_hash("evictable-newer-replay")
    first = producer.claim(principal, first_key, first_hash, now=1.0)
    assert producer.succeed(
        principal,
        first_key,
        first_hash,
        first.fencing_token,
        {"reply": "a" * 16},
        now=2.0,
    )
    second = producer.claim(principal, second_key, second_hash, now=3.0)
    assert producer.succeed(
        principal,
        second_key,
        second_hash,
        second.fencing_token,
        {"reply": "b" * 16},
        now=4.0,
    )

    constrained = WeixinIdempotencyStore(
        path,
        lease_seconds=10,
        max_records=100,
        max_total_response_bytes=30,
        prune_batch=1,
    )
    replay = constrained.claim(principal, first_key, first_hash, now=5.0)

    assert replay.state == "succeeded"
    assert replay.response == {"reply": "a" * 16}
    with sqlite3.connect(path) as connection:
        remaining = connection.execute(
            "SELECT COUNT(*) FROM weixin_agent_idempotency "
            "WHERE response_json IS NOT NULL"
        ).fetchone()[0]
    assert remaining == 1


def test_conversation_pair_and_replay_receipt_commit_in_one_transaction(tmp_path):
    path = tmp_path / "conversations.db"
    base = ConversationStore(db_path=str(path))
    turn_key = hash_turn_identity(_principal(), KEY)
    request_hash = _request_hash("atomic")
    buffered = BufferedConversationStore(base)
    buffered.append("weixin:chat-atomic", "user", "atomic")
    buffered.append("weixin:chat-atomic", "assistant", "reply")
    stored = buffered.commit(
        turn_key=turn_key,
        request_sha256=request_hash,
        result={"reply": "reply", "model": "model-a", "turns": 1},
    )
    assert stored["reply"] == "reply"
    base.close()

    restarted = ConversationStore(db_path=str(path))
    try:
        assert restarted.get("weixin:chat-atomic") == [
            {"role": "user", "content": "atomic"},
            {"role": "assistant", "content": "reply"},
        ]
        assert restarted.idempotent_result(turn_key, request_hash) == stored
        receipt_status = restarted.turn_receipt_snapshot(turn_key)
        assert receipt_status["found"] is True
        assert receipt_status["request_hash_present"] is True
        assert receipt_status["response_present"] is True
        assert receipt_status["replay_available"] is True
        assert isinstance(receipt_status["created_at"], float)
        assert "response" not in receipt_status
        assert "request_sha256" not in receipt_status
        duplicate = BufferedConversationStore(restarted)
        duplicate.append("weixin:chat-atomic", "user", "atomic")
        duplicate.append("weixin:chat-atomic", "assistant", "duplicate")
        assert duplicate.commit(
            turn_key=turn_key,
            request_sha256=request_hash,
            result={"reply": "duplicate"},
        ) == stored
        assert len(restarted.get("weixin:chat-atomic")) == 2
    finally:
        restarted.close()


def test_gateway_reserves_and_fences_receipt_before_agent_then_consumes_it(
    monkeypatch,
):
    events: list[str] = []

    async def fake_agent_chat(_router, conversations, **kwargs):
        events.append("agent")
        key = session_key(kwargs["channel"], kwargs["chat_id"])
        conversations.append(key, "user", kwargs["message"])
        conversations.append(key, "assistant", "reserved reply")
        return _truthful_agent_result("reserved reply", model="model-a")

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "reserve before provider",
        "chat_id": "chat-reservation-order",
        "user_id": "user-reservation-order",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("6" * 64),
    }
    with TestClient(app) as client:
        with _verified_chat_route(client):
            conversations = client.app.state.conversations
            turn_store = client.app.state.weixin_idempotency
            original_reserve = conversations.reserve_turn_receipt
            original_enter_turn = conversations.enter_turn_provider_phase
            original_enter_gateway = turn_store.enter_provider_phase
            original_commit = conversations.commit_idempotent_turn

            def reserve(**kwargs):
                events.append("reserve")
                return original_reserve(**kwargs)

            def enter_turn(**kwargs):
                events.append("conversation_provider_phase")
                return original_enter_turn(**kwargs)

            def enter_gateway(*args, **kwargs):
                events.append("gateway_provider_phase")
                return original_enter_gateway(*args, **kwargs)

            def commit(**kwargs):
                events.append("conversation_commit")
                return original_commit(**kwargs)

            monkeypatch.setattr(conversations, "reserve_turn_receipt", reserve)
            monkeypatch.setattr(conversations, "enter_turn_provider_phase", enter_turn)
            monkeypatch.setattr(turn_store, "enter_provider_phase", enter_gateway)
            monkeypatch.setattr(conversations, "commit_idempotent_turn", commit)
            response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

            principal = hash_channel_principal(
                channel="weixin",
                user_id=payload["user_id"],
                chat_id=payload["chat_id"],
            )
            turn_key = hash_turn_identity(principal, payload["idempotency_key"])
            request_hash = hash_weixin_request(
                channel="weixin",
                chat_id=payload["chat_id"],
                user_id=payload["user_id"],
                message=payload["message"],
                model=payload["model"],
                system=None,
                video_async=False,
            )
            stored = conversations.idempotent_result(turn_key, request_hash)
            receipt_found = conversations.turn_receipt_snapshot(turn_key)["found"]

    assert response.status_code == 200
    assert events == [
        "reserve",
        "conversation_provider_phase",
        "gateway_provider_phase",
        "agent",
        "conversation_commit",
    ]
    assert stored is not None
    assert stored["reply"] == "reserved reply"
    assert receipt_found is True


def test_gateway_receipt_capacity_failure_stops_before_provider_phase(monkeypatch):
    agent_calls = 0
    provider_phase_calls = 0

    async def must_not_run(*_args, **_kwargs):
        nonlocal agent_calls
        agent_calls += 1
        raise AssertionError("Agent must not run without reserved receipt capacity")

    monkeypatch.setattr(gateway_app, "agent_chat", must_not_run)
    payload = {
        "message": "capacity preflight",
        "chat_id": "chat-reservation-full",
        "user_id": "user-reservation-full",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("7" * 64),
    }
    with TestClient(app) as client:
        with _verified_chat_route(client):
            conversations = client.app.state.conversations
            turn_store = client.app.state.weixin_idempotency

            def refuse_reservation(**_kwargs):
                raise ConversationReceiptUnavailable("simulated protected window full")

            original_enter = turn_store.enter_provider_phase

            def enter_provider(*args, **kwargs):
                nonlocal provider_phase_calls
                provider_phase_calls += 1
                return original_enter(*args, **kwargs)

            monkeypatch.setattr(conversations, "reserve_turn_receipt", refuse_reservation)
            monkeypatch.setattr(turn_store, "enter_provider_phase", enter_provider)
            first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            second = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert first.status_code == 503
    assert first.json()["detail"] == {
        "code": "turn_receipt_reservation_unavailable",
        "retryable": True,
    }
    assert second.status_code == 503
    assert second.json()["detail"] == first.json()["detail"]
    assert agent_calls == 0
    assert provider_phase_calls == 0


def test_conversation_fence_gap_recovers_without_second_provider_attempt(monkeypatch):
    agent_calls = 0

    async def must_not_run(*_args, **_kwargs):
        nonlocal agent_calls
        agent_calls += 1
        raise AssertionError("recovery Turn must not call the Agent")

    monkeypatch.setattr(gateway_app, "agent_chat", must_not_run)
    payload = {
        "message": "crash between durable fences",
        "chat_id": "chat-two-fence-gap",
        "user_id": "user-two-fence-gap",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("8" * 64),
    }
    with TestClient(app) as client:
        with _verified_chat_route(client):
            turn_store = client.app.state.weixin_idempotency
            original_enter = turn_store.enter_provider_phase
            monkeypatch.setattr(
                turn_store,
                "enter_provider_phase",
                lambda *_args, **_kwargs: False,
            )
            first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            monkeypatch.setattr(turn_store, "enter_provider_phase", original_enter)
            second = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert first.status_code == 409
    assert first.json()["detail"]["reason"] == "provider_phase_fenced"
    assert second.status_code == 200
    assert second.json()["blocked"] is True
    assert second.json()["outcome"] == "provider_result_recovery_required"
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert agent_calls == 0


def test_legacy_succeeded_replay_downgrades_unattested_model_and_internal_route(
    monkeypatch,
):
    calls = 0

    async def must_not_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("legacy succeeded replay must not enter the Agent")

    monkeypatch.setattr(gateway_app, "agent_chat", must_not_run)
    key = "wxmsg-v1:" + ("1" * 64)
    payload = {
        "message": "replay legacy succeeded result",
        "chat_id": "chat-legacy-succeeded",
        "user_id": "user-legacy-succeeded",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": key,
    }
    principal = hash_channel_principal(
        channel=payload["channel"],
        user_id=payload["user_id"],
        chat_id=payload["chat_id"],
    )
    request_hash = hash_weixin_request(
        channel=payload["channel"],
        chat_id=payload["chat_id"],
        user_id=payload["user_id"],
        message=payload["message"],
        model=payload["model"],
        system=None,
        video_async=False,
    )
    secret = "legacy-private-route-attestation"
    legacy = {
        **_truthful_agent_result(
            "legacy business reply",
            model="requested-premium-never-attested",
            outcome="partial",
        ),
        "actual_model": "different-actual-model",
        "final_route_receipt": {"_nachuan_route_attestation": secret},
        "agent_route": {
            "label": "orchestrated",
            "orchestration": {
                "mode": "org",
                "author_lineage": [{"call_receipts": [secret]}],
                "_nachuan_route_attestation": secret,
            },
        },
    }

    with TestClient(app) as client:
        with _verified_chat_route(client):
            store = client.app.state.weixin_idempotency
            claimed = store.claim(principal, key, request_hash)
            assert claimed.state == "claimed"
            assert store.succeed(
                principal,
                key,
                request_hash,
                claimed.fencing_token,
                legacy,
            )
            replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    document = replay.json()
    encoded = json.dumps(document, ensure_ascii=False)
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert document["reply"] == "legacy business reply"
    assert document["outcome"] == "partial"
    assert document["model"] == "nachuan-engine"
    assert document["channel_result_version"] == 2
    assert document["attribution_state"] == "local_engine"
    assert "actual_model" not in document
    assert "final_route_receipt" not in document
    assert secret not in encoded
    assert calls == 0


def test_legacy_conversation_receipt_recovery_is_sanitized_before_gateway_commit(
    monkeypatch,
):
    calls = 0

    async def must_not_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("committed conversation receipt must bypass the Agent")

    monkeypatch.setattr(gateway_app, "agent_chat", must_not_run)
    key = "wxmsg-v1:" + ("b" * 64)
    payload = {
        "message": "recover legacy conversation receipt",
        "chat_id": "chat-legacy-conversation-receipt",
        "user_id": "user-legacy-conversation-receipt",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": key,
    }
    principal = hash_channel_principal(
        channel=payload["channel"],
        user_id=payload["user_id"],
        chat_id=payload["chat_id"],
    )
    turn_key = hash_turn_identity(principal, key)
    request_hash = hash_weixin_request(
        channel=payload["channel"],
        chat_id=payload["chat_id"],
        user_id=payload["user_id"],
        message=payload["message"],
        model=payload["model"],
        system=None,
        video_async=False,
    )
    secret = "legacy-conversation-receipt-secret"
    legacy = {
        **_truthful_agent_result(
            "recovered legacy reply",
            model="unattested-conversation-model",
            outcome="partial",
        ),
        "actual_model": "unattested-conversation-model",
        "final_route_receipt": {"_nachuan_route_attestation": secret},
        "agent_route": {
            "label": "legacy-route",
            "orchestration": {
                "mode": "org",
                "author_lineage": [{"private_receipt": secret}],
            },
        },
    }

    with TestClient(app) as client:
        with _verified_chat_route(client):
            conversations = client.app.state.conversations
            assert conversations.reserve_turn_receipt(
                turn_key=turn_key,
                request_sha256=request_hash,
            ) == "reserved"
            assert conversations.enter_turn_provider_phase(
                turn_key=turn_key,
                request_sha256=request_hash,
            ) == "provider_started"
            conversations.commit_idempotent_turn(
                turn_key=turn_key,
                request_sha256=request_hash,
                entries=[],
                result=legacy,
                require_provider_started=True,
            )
            recovered = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    document = recovered.json()
    encoded = json.dumps(document, ensure_ascii=False)
    assert recovered.status_code == 200
    assert recovered.headers["Idempotency-Replayed"] == "true"
    assert document["reply"] == "recovered legacy reply"
    assert document["outcome"] == "partial"
    assert document["model"] == "nachuan-engine"
    assert document["channel_result_version"] == 2
    assert document["attribution_state"] == "local_engine"
    assert "actual_model" not in document
    assert "final_route_receipt" not in document
    assert secret not in encoded
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == document
    assert calls == 0


def test_gateway_rejects_contradictory_agent_success_and_never_retries_it(
    monkeypatch,
):
    calls = 0

    async def contradictory_result(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return _truthful_agent_result(
            "not actually verified",
            model="model-a",
            outcome="completed",
        ) | {"verified": False, "machine_verified": False}

    monkeypatch.setattr(gateway_app, "agent_chat", contradictory_result)
    payload = {
        "message": "truthful outcome required",
        "chat_id": "chat-invalid-agent-result",
        "user_id": "user-invalid-agent-result",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("9" * 64),
    }
    with TestClient(app) as client:
        with _verified_chat_route(client):
            first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            second = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert first.status_code == 502
    assert first.json()["detail"] == {
        "code": "invalid_agent_result",
        "retryable": False,
    }
    assert second.status_code == 200
    assert second.json()["outcome"] == "provider_result_recovery_required"
    assert calls == 1


def test_turn_identity_uses_stable_channel_principal_not_runtime_api_key():
    stable_principal = _principal()
    assert stable_principal == _principal()
    assert hash_turn_identity(stable_principal, KEY) == hash_turn_identity(
        _principal(), KEY
    )

    other_chat_principal = _principal(chat_id="chat-2")
    assert other_chat_principal != stable_principal
    assert hash_turn_identity(other_chat_principal, KEY) != hash_turn_identity(
        stable_principal, KEY
    )


def test_weixin_endpoint_caches_success_and_rejects_semantic_conflict(monkeypatch):
    calls = 0

    async def fake_agent_chat(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return _truthful_agent_result("stable reply", model="model-a") | {
            "session": "weixin:chat-1",
            "user_id": "user-1",
            "memories_used": ["must-not-enter-idempotency-response"],
        }

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "hello",
        "chat_id": "chat-1",
        "user_id": "user-1",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("b" * 64),
    }
    with TestClient(app) as client:
        first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        second = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        conflict = client.post(
            "/v1/agent/chat", headers=AUTH, json={**payload, "message": "changed"}
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert first.json()["model"] == "nachuan-engine"
    assert first.json()["channel_result_version"] == 2
    assert first.json()["attribution_state"] == "local_engine"
    assert second.headers["Idempotency-Replayed"] == "true"
    assert calls == 1
    assert "session" not in first.json()
    assert "user_id" not in first.json()
    assert "memories_used" not in first.json()
    assert conflict.status_code == 409


def test_new_attested_provider_result_persists_v2_without_private_receipt(monkeypatch):
    calls = 0

    async def attested_agent_result(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        reply = "provider-authored reply"
        provider_call = seal_route_receipt(
            {
                "route_receipt_version": 1,
                "model": "model-a",
                "requested_model": "model-a",
                "actual_model": "model-a",
                "provider": "provider-a",
                "upstream_model": "upstream-a",
                "reported_model": "upstream-a",
                "observed_model": "upstream-a",
                "model_family": "model-a",
                "model_identity_error": None,
                "independence_domain": "sha256:" + ("c" * 64),
            },
            authored_output=reply,
        )
        return _truthful_agent_result(reply, model="model-a") | {
            "actual_model": "model-a",
            "final_route_receipt": bind_agent_author_receipt(
                provider_call,
                reply=reply,
            ),
        }

    monkeypatch.setattr(gateway_app, "agent_chat", attested_agent_result)
    payload = {
        "message": "persist attested provider result",
        "chat_id": "chat-attested-v2",
        "user_id": "user-attested-v2",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("3" * 64),
    }

    with TestClient(app) as client:
        with _verified_chat_route(client):
            first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    document = first.json()
    assert first.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert document["reply"] == "provider-authored reply"
    assert document["model"] == "model-a"
    assert document["channel_result_version"] == 2
    assert document["attribution_state"] == "provider_attested"
    assert "actual_model" not in document
    assert "final_route_receipt" not in document
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == document
    assert calls == 1


def test_video_capacity_permit_change_replays_same_turn_without_second_agent_call(
    monkeypatch,
):
    capacity_flags: list[bool] = []

    async def fake_agent_chat(*_args, **kwargs):
        capacity_flags.append(kwargs["video_async_capacity_available"])
        return {
            "reply": "当前异步视频队列已满，本次没有创建视频任务。",
            "model": "model-a",
            "turns": 1,
            "usage": {},
            "outcome": "rejected_capacity",
            "blocked": True,
            "reviewed": False,
            "verified": False,
            "machine_verified": False,
            "agent_route": {"label": "video_capacity"},
            "video_rejected": "capacity",
        }

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "生成一段视频",
        "chat_id": "chat-capacity-permit",
        "user_id": "user-capacity-permit",
        "channel": "weixin",
        "model": "model-a",
        "video_async": True,
        "idempotency_key": "wxmsg-v1:" + ("9" * 64),
    }
    with TestClient(app) as client:
        rejected = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={**payload, "video_async_capacity_available": False},
        )
        replay = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={**payload, "video_async_capacity_available": True},
        )

    assert rejected.status_code == 200
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == rejected.json()
    assert replay.json()["agent_route"] == {"label": "video_capacity"}
    assert "video_task" not in replay.json()
    assert capacity_flags == [False]


def test_video_capacity_permit_rejects_non_boolean_values(monkeypatch):
    monkeypatch.setattr(
        gateway_app,
        "agent_chat",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("非布尔容量标志不得进入 Agent")
        ),
    )
    payload = {
        "message": "你好",
        "chat_id": "chat-invalid-capacity-permit",
        "user_id": "user-invalid-capacity-permit",
        "channel": "weixin",
        "model": "model-a",
        "video_async": True,
        "video_async_capacity_available": "false",
        "idempotency_key": "wxmsg-v1:" + ("8" * 64),
    }
    with TestClient(app) as client:
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert response.status_code == 422
    assert response.json()["detail"] == "video_async_capacity_available 必须是布尔值"


def test_runtime_api_key_rotation_replays_without_second_agent_call(monkeypatch):
    from gateway.config import get_settings

    calls = 0

    async def fake_agent_chat(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return _truthful_agent_result(
            "survives key rotation",
            model="model-a",
            outcome="blocked",
            blocked=True,
        )

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    monkeypatch.setenv("GATEWAY_API_KEYS", "test-key,rotated-runtime-key")
    get_settings.cache_clear()
    payload = {
        "message": "same inbound update",
        "chat_id": "chat-key-rotation",
        "user_id": "user-key-rotation",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("e" * 64),
    }
    try:
        with TestClient(app) as client:
            first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            replay = client.post(
                "/v1/agent/chat",
                headers={"Authorization": "Bearer rotated-runtime-key"},
                json=payload,
            )
    finally:
        get_settings.cache_clear()

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert calls == 1


def test_weixin_endpoint_does_not_auto_retry_after_ambiguous_provider_failure(
    monkeypatch,
):
    calls = 0

    async def flaky_agent_chat(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ProviderError("temporary", status_code=502)
        return {"reply": "must not run", "model": "model-a", "turns": 1, "usage": {}}

    monkeypatch.setattr(gateway_app, "agent_chat", flaky_agent_chat)
    payload = {
        "message": "retry me",
        "chat_id": "chat-failure",
        "user_id": "user-1",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("c" * 64),
    }
    with TestClient(app) as client:
        first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        second = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert first.status_code == 502
    assert second.status_code == 200
    assert second.json()["outcome"] == "provider_result_recovery_required"
    assert second.json()["blocked"] is True
    assert calls == 1


def test_durable_channel_replay_stops_before_models_after_possible_paid_call(
    monkeypatch, tmp_path
):
    calls = 0

    async def must_not_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("provider recovery preflight must stop the agent")

    monkeypatch.setattr(gateway_app, "agent_chat", must_not_run)
    key = "wxmsg-v1:" + ("4" * 64)
    payload = {
        "message": "recover uncertain result",
        "chat_id": "chat-paid-recovery",
        "user_id": "user-paid-recovery",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": key,
    }
    principal = hash_channel_principal(
        channel="weixin",
        user_id=payload["user_id"],
        chat_id=payload["chat_id"],
    )
    turn_id = hash_turn_identity(principal, key)
    ledger = ProviderCallLedger(tmp_path / "provider-calls.db", required=True)
    prior = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="model-a",
            actual_model="model-a",
            provider="provider",
            upstream_model="sku",
        ),
        context=ProviderCallContext(
            turn_id=turn_id,
            workflow_id="weixin:agent_chat",
        ),
        attempt=1,
        stream=False,
    )
    assert prior.finish(status="success")

    try:
        with TestClient(app) as client:
            monkeypatch.setattr(
                client.app.state,
                "provider_call_ledger",
                ledger,
            )
            first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
            replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)
    finally:
        ledger.close()

    assert first.status_code == 200
    assert first.headers["Idempotency-Replayed"] == "false"
    assert first.json()["blocked"] is True
    assert first.json()["outcome"] == "provider_result_recovery_required"
    assert first.json()["model"] == "nachuan-engine"
    assert first.json()["channel_result_version"] == 2
    assert first.json()["attribution_state"] == "local_engine"
    assert first.json()["recovery_id"] == turn_id
    assert len(first.json()["recovery_id"]) == 64
    assert first.json()["notice_trace_id"]
    assert "trace_id" not in first.json()
    assert turn_id in first.json()["reply"]
    assert "重复扣费" in first.json()["reply"]
    assert "请勿原样重发付费或不可逆任务" in first.json()["reply"]
    assert "稍后重新发送" not in first.json()["reply"]
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert calls == 0


def test_expired_provider_phase_reclaim_persists_notice_without_entering_agent(
    monkeypatch,
):
    calls = 0

    async def must_not_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("provider-phase recovery must stop the agent")

    monkeypatch.setattr(gateway_app, "agent_chat", must_not_run)
    key = "wxmsg-v1:" + ("2" * 64)
    payload = {
        "message": "expired provider phase",
        "chat_id": "chat-expired-provider-phase",
        "user_id": "user-expired-provider-phase",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": key,
    }
    principal = hash_channel_principal(
        channel="weixin",
        user_id=payload["user_id"],
        chat_id=payload["chat_id"],
    )
    request_hash = hash_weixin_request(
        channel="weixin",
        chat_id=payload["chat_id"],
        user_id=payload["user_id"],
        message=payload["message"],
        model=payload["model"],
        system=None,
        video_async=False,
    )

    with TestClient(app) as client:
        store = client.app.state.weixin_idempotency
        old = store.claim(principal, key, request_hash, now=100.0)
        assert old.state == "claimed"
        assert store.enter_provider_phase(
            principal,
            key,
            request_hash,
            old.fencing_token,
            now=101.0,
        )
        notice = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert notice.status_code == 200
    assert notice.headers["Idempotency-Replayed"] == "false"
    assert notice.json()["outcome"] == "provider_result_recovery_required"
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == notice.json()
    assert calls == 0


def test_gateway_commit_failure_recovers_receipt_without_second_agent_turn(monkeypatch):
    calls = 0
    extraction_calls = 0

    async def fake_extract(*_args, **_kwargs):
        nonlocal extraction_calls
        extraction_calls += 1

    async def fake_agent_chat(_router, conversations, **kwargs):
        nonlocal calls
        calls += 1
        key = session_key(kwargs["channel"], kwargs["chat_id"])
        conversations.append(key, "user", kwargs["message"])
        conversations.append(key, "assistant", "one business result")
        return _truthful_agent_result(
            "one business result",
            model="model-a",
        ) | {"turns": len(conversations.get(key)) // 2}

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    monkeypatch.setattr(gateway_app, "_extract_and_store_scoped", fake_extract)
    payload = {
        "message": "crash-window",
        "chat_id": "chat-crash-window",
        "user_id": "user-1",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("d" * 64),
    }
    with TestClient(app) as client:
        ledger = app.state.weixin_idempotency
        original_succeed = ledger.succeed
        persist_calls = 0

        def fail_first_gateway_commit(*args, **kwargs):
            nonlocal persist_calls
            persist_calls += 1
            if persist_calls == 1:
                from gateway.weixin_idempotency import WeixinIdempotencyUnavailable

                raise WeixinIdempotencyUnavailable("simulated crash gap")
            return original_succeed(*args, **kwargs)

        monkeypatch.setattr(ledger, "succeed", fail_first_gateway_commit)
        first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        second = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        history = app.state.conversations.get("weixin:chat-crash-window")

    assert first.status_code == 503
    assert second.status_code == 200
    assert second.headers["Idempotency-Replayed"] == "true"
    assert second.json()["reply"] == "one business result"
    assert calls == 1
    # Recovery of an already committed conversation must not schedule another
    # paid auxiliary model call without its own durable claim.
    assert extraction_calls == 0
    assert history == [
        {"role": "user", "content": "crash-window"},
        {"role": "assistant", "content": "one business result"},
    ]


def test_idempotency_key_is_required_for_each_durable_channel_namespace():
    valid = {
        "message": "hello",
        "chat_id": "chat-validation",
        "user_id": "user-1",
        "channel": "weixin",
        "model": "model-a",
    }
    with TestClient(app) as client:
        missing = client.post("/v1/agent/chat", headers=AUTH, json=valid)
        malformed = client.post(
            "/v1/agent/chat", headers=AUTH, json={**valid, "idempotency_key": "short"}
        )
        wrong_channel = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={**valid, "channel": "api", "idempotency_key": KEY},
        )
        missing_feishu = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={**valid, "channel": "feishu"},
        )
        wrong_feishu_namespace = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json={**valid, "channel": "feishu", "idempotency_key": KEY},
        )

    assert missing.status_code == 422
    assert malformed.status_code == 422
    assert wrong_channel.status_code == 422
    assert missing_feishu.status_code == 422
    assert wrong_feishu_namespace.status_code == 422


def test_agent_endpoint_rejects_non_object_json_before_channel_access_checks():
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/v1/agent/chat",
            headers=AUTH,
            json=["not", "an", "object"],
        )

    assert response.status_code == 422
    assert response.json()["detail"] == "请求体必须是 JSON 对象"


def test_channel_idempotency_namespaces_are_strict_and_hashable():
    feishu_key = "fsmsg-v1:" + ("b" * 64)
    principal = hash_channel_principal(
        channel="feishu", user_id="ou-user-1", chat_id="oc-chat-1"
    )

    assert validate_channel_idempotency_key(feishu_key, channel="feishu") == feishu_key
    assert len(hash_turn_identity(principal, feishu_key)) == 64

    for value, channel in ((KEY, "feishu"), (feishu_key, "weixin")):
        try:
            validate_channel_idempotency_key(value, channel=channel)
        except ValueError:
            pass
        else:  # pragma: no cover - guards namespace regression
            raise AssertionError("cross-channel idempotency key was accepted")

    try:
        validate_weixin_idempotency_key(feishu_key)
    except ValueError:
        pass
    else:  # pragma: no cover - guards legacy validator semantics
        raise AssertionError("legacy Weixin validator accepted a Feishu key")


def test_feishu_endpoint_uses_the_same_durable_replay_fence(monkeypatch):
    calls = 0

    async def fake_agent_chat(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return _truthful_agent_result(
            "one Feishu business result",
            model="model-a",
            outcome="blocked",
            blocked=True,
        ) | {
            "session": "must-not-leak",
        }

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "durable Feishu update",
        "chat_id": "oc-durable-chat",
        "user_id": "ou-durable-user",
        "channel": "feishu",
        "model": "model-a",
        "idempotency_key": "fsmsg-v1:" + ("f" * 64),
    }
    with TestClient(app) as client:
        first = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        replay = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.headers["Idempotency-Replayed"] == "true"
    assert replay.json() == first.json()
    assert replay.json()["reply"] == "one Feishu business result"
    assert "session" not in replay.json()
    assert calls == 1


def test_durable_deadline_deducts_preflight_time_from_agent_budget(monkeypatch):
    calls = 0

    async def agent_that_only_fits_a_fresh_budget(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.35)
        return _truthful_agent_result("must miss the remaining deadline")

    clock = SimpleNamespace(now=100.0)
    real_time_module = gateway_app.time

    class PolicyClock:
        def monotonic(self):
            return clock.now

        def __getattr__(self, name):
            return getattr(real_time_module, name)

    monkeypatch.setattr(gateway_app, "time", PolicyClock())
    monkeypatch.setattr(gateway_app, "agent_chat", agent_that_only_fits_a_fresh_budget)
    monkeypatch.setattr(
        gateway_app,
        "_DURABLE_TURN_DEADLINE_SECONDS",
        1.0,
        raising=False,
    )
    payload = {
        "message": "preflight consumes the same deadline",
        "chat_id": "chat-preflight-deadline",
        "user_id": "user-preflight-deadline",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("5" * 64),
    }

    with TestClient(app) as client:
        conversations = client.app.state.conversations
        original_recovery_read = conversations.idempotent_result

        def recovery_read_after_slow_preflight(*args, **kwargs):
            clock.now += 0.8
            return original_recovery_read(*args, **kwargs)

        monkeypatch.setattr(
            conversations,
            "idempotent_result",
            recovery_read_after_slow_preflight,
        )
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert response.status_code == 504
    assert response.json()["detail"] == {
        "code": "durable_turn_deadline_exceeded",
        "retryable": True,
    }
    assert calls == 1


def test_expired_preflight_never_enters_agent_and_releases_for_safe_retry(
    monkeypatch,
):
    calls = 0

    async def agent_after_safe_retry(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.1)
        return _truthful_agent_result("fresh retry after safe abandon")

    clock = SimpleNamespace(now=200.0)
    real_time_module = gateway_app.time

    class PolicyClock:
        def monotonic(self):
            return clock.now

        def __getattr__(self, name):
            return getattr(real_time_module, name)

    monkeypatch.setattr(gateway_app, "time", PolicyClock())
    monkeypatch.setattr(gateway_app, "agent_chat", agent_after_safe_retry)
    monkeypatch.setattr(
        gateway_app,
        "_DURABLE_TURN_DEADLINE_SECONDS",
        1.0,
        raising=False,
    )
    payload = {
        "message": "expired before agent",
        "chat_id": "chat-expired-preflight",
        "user_id": "user-expired-preflight",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("6" * 64),
    }

    with TestClient(app) as client:
        conversations = client.app.state.conversations
        original_recovery_read = conversations.idempotent_result
        recovery_reads = 0

        def first_recovery_read_exhausts_deadline(*args, **kwargs):
            nonlocal recovery_reads
            recovery_reads += 1
            if recovery_reads == 1:
                clock.now += 1.1
            return original_recovery_read(*args, **kwargs)

        monkeypatch.setattr(
            conversations,
            "idempotent_result",
            first_recovery_read_exhausts_deadline,
        )
        expired = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        calls_after_expired_request = calls
        retry = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert expired.status_code == 504
    assert expired.json()["detail"] == {
        "code": "durable_turn_deadline_exceeded",
        "retryable": True,
    }
    assert calls_after_expired_request == 0
    assert retry.status_code == 200
    assert retry.headers["Idempotency-Replayed"] == "false"
    assert retry.json()["reply"] == "fresh retry after safe abandon"
    assert calls == 1


def test_deadline_exhausted_during_final_pre_provider_step_never_enters_agent(
    monkeypatch,
):
    calls = 0

    async def agent_after_safe_retry(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.1)
        return _truthful_agent_result("retry after pre-provider abandon")

    clock = SimpleNamespace(now=300.0)
    real_time_module = gateway_app.time

    class PolicyClock:
        def monotonic(self):
            return clock.now

        def __getattr__(self, name):
            return getattr(real_time_module, name)

    original_renew = gateway_app._renew_durable_turn_or_raise
    renew_calls = 0

    async def first_renew_exhausts_deadline(*args, **kwargs):
        nonlocal renew_calls
        renew_calls += 1
        await original_renew(*args, **kwargs)
        if renew_calls == 1:
            clock.now += 1.1

    monkeypatch.setattr(gateway_app, "time", PolicyClock())
    monkeypatch.setattr(gateway_app, "agent_chat", agent_after_safe_retry)
    monkeypatch.setattr(
        gateway_app,
        "_renew_durable_turn_or_raise",
        first_renew_exhausts_deadline,
    )
    monkeypatch.setattr(
        gateway_app,
        "_DURABLE_TURN_DEADLINE_SECONDS",
        1.0,
        raising=False,
    )
    payload = {
        "message": "deadline expires during final pre-provider check",
        "chat_id": "chat-final-pre-provider-deadline",
        "user_id": "user-final-pre-provider-deadline",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("0" * 64),
    }

    with TestClient(app) as client:
        expired = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        calls_after_expired_request = calls
        retry = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert expired.status_code == 504
    assert expired.json()["detail"] == {
        "code": "durable_turn_deadline_exceeded",
        "retryable": True,
    }
    assert calls_after_expired_request == 0
    assert retry.status_code == 200
    assert retry.headers["Idempotency-Replayed"] == "false"
    assert retry.json()["reply"] == "retry after pre-provider abandon"
    assert calls == 1


@pytest.mark.parametrize(
    ("channel", "idempotency_key"),
    [
        ("weixin", "wxmsg-v1:" + ("7" * 64)),
        ("feishu", "fsmsg-v1:" + ("8" * 64)),
    ],
)
def test_each_durable_channel_has_a_bounded_turn_deadline(
    monkeypatch, channel, idempotency_key
):
    async def slow_agent_chat(*_args, **_kwargs):
        await asyncio.sleep(0.08)
        return {
            "reply": "too late",
            "model": "model-a",
            "turns": 1,
            "usage": {},
            "blocked": True,
        }

    monkeypatch.setattr(gateway_app, "agent_chat", slow_agent_chat)
    monkeypatch.setattr(
        gateway_app, "_DURABLE_TURN_DEADLINE_SECONDS", 0.02, raising=False
    )
    payload = {
        "message": f"deadline-{channel}",
        "chat_id": f"chat-deadline-{channel}",
        "user_id": f"user-deadline-{channel}",
        "channel": channel,
        "model": "model-a",
        "idempotency_key": idempotency_key,
    }

    with TestClient(app) as client:
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert response.status_code == 504
    assert response.json()["detail"] == {
        "code": "durable_turn_deadline_exceeded",
        "retryable": True,
    }


@pytest.mark.parametrize(
    ("channel", "idempotency_key"),
    [
        ("weixin", "wxmsg-v1:" + ("9" * 64)),
        ("feishu", "fsmsg-v1:" + ("a" * 64)),
    ],
)
def test_heartbeat_renewal_error_cancels_work_and_propagates_lease_lost(
    monkeypatch, channel, idempotency_key
):
    cancelled = asyncio.Event()

    async def slow_agent_chat(*_args, **_kwargs):
        try:
            await asyncio.sleep(0.08)
        finally:
            cancelled.set()
        return {
            "reply": "must not commit",
            "model": "model-a",
            "turns": 1,
            "usage": {},
            "blocked": True,
        }

    async def broken_heartbeat(*_args, **_kwargs):
        raise WeixinIdempotencyUnavailable("simulated heartbeat storage failure")

    monkeypatch.setattr(gateway_app, "agent_chat", slow_agent_chat)
    monkeypatch.setattr(
        gateway_app, "_renew_weixin_idempotency_lease", broken_heartbeat
    )
    payload = {
        "message": f"heartbeat-{channel}",
        "chat_id": f"chat-heartbeat-{channel}",
        "user_id": f"user-heartbeat-{channel}",
        "channel": channel,
        "model": "model-a",
        "idempotency_key": idempotency_key,
    }

    with TestClient(app) as client:
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "durable_turn_lease_lost",
        "reason": "heartbeat_unavailable",
        "retryable": True,
    }
    assert cancelled.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status_code", "reason"),
    [
        ("fenced", 409, "heartbeat_fenced"),
        ("unavailable", 503, "heartbeat_unavailable"),
    ],
)
async def test_real_heartbeat_renew_failure_is_a_lease_lost_terminal(
    monkeypatch, outcome, status_code, reason
):
    class FakeStore:
        lease_seconds = 0.003
        renew_calls = 0

        def renew(self, *_args):
            self.renew_calls += 1
            if outcome == "unavailable":
                raise WeixinIdempotencyUnavailable("simulated renewal outage")
            return False

    async def inline_threadpool(func, *args, **kwargs):
        return func(*args, **kwargs)

    store = FakeStore()
    monkeypatch.setattr(
        gateway_app, "_durable_heartbeat_interval", lambda _store: 0.0
    )
    # This test owns the explicit renew outcomes.  Keep the threadpool timeout
    # branch out of scope so host load cannot turn ``False`` into an unrelated
    # heartbeat_unavailable result before FakeStore.renew is even invoked.
    monkeypatch.setattr(gateway_app, "run_in_threadpool", inline_threadpool)
    with pytest.raises(gateway_app._DurableTurnLeaseLost) as caught:
        await gateway_app._renew_weixin_idempotency_lease(
            store,
            _principal(),
            KEY,
            _request_hash(),
            "f" * 64,
            asyncio.Event(),
        )

    assert store.renew_calls == 1
    assert caught.value.status_code == status_code
    assert caught.value.detail == {
        "code": "durable_turn_lease_lost",
        "reason": reason,
        "retryable": True,
    }


@pytest.mark.asyncio
async def test_uncooperative_agent_cancellation_fails_closed(monkeypatch):
    release = asyncio.Event()

    async def ignores_first_cancellation():
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()

    monkeypatch.setattr(gateway_app, "_DURABLE_TASK_STOP_GRACE_SECONDS", 0.01)
    task = asyncio.create_task(ignores_first_cancellation())
    await asyncio.sleep(0)

    with pytest.raises(gateway_app._DurableTurnLeaseLost) as caught:
        await gateway_app._cancel_agent_task(task)

    assert caught.value.detail["reason"] == "agent_cancel_timeout"
    assert not task.done()
    release.set()
    await task


def test_lease_is_rechecked_before_entering_side_effectful_agent(monkeypatch):
    calls = 0

    async def fake_agent_chat(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {
            "reply": "must not run",
            "model": "model-a",
            "turns": 1,
            "usage": {},
            "blocked": True,
        }

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "preflight fence",
        "chat_id": "chat-preflight-fence",
        "user_id": "user-preflight-fence",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("b" * 64),
    }
    with TestClient(app) as client:
        monkeypatch.setattr(app.state.weixin_idempotency, "renew", lambda *_a, **_k: False)
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "durable_turn_lease_lost"
    assert calls == 0


def test_provider_phase_is_atomically_entered_before_agent(monkeypatch):
    calls = 0

    async def fake_agent_chat(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("fenced provider phase must stop the agent")

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "provider phase fence",
        "chat_id": "chat-provider-phase-fence",
        "user_id": "user-provider-phase-fence",
        "channel": "weixin",
        "model": "model-a",
        "idempotency_key": "wxmsg-v1:" + ("3" * 64),
    }
    with TestClient(app) as client:
        monkeypatch.setattr(
            app.state.weixin_idempotency,
            "enter_provider_phase",
            lambda *_a, **_k: False,
        )
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "durable_turn_lease_lost",
        "reason": "provider_phase_fenced",
        "retryable": True,
    }
    assert calls == 0


def test_lease_is_rechecked_before_conversation_commit(monkeypatch):
    async def fake_agent_chat(_router, conversations, **kwargs):
        key = session_key(kwargs["channel"], kwargs["chat_id"])
        conversations.append(key, "user", kwargs["message"])
        conversations.append(key, "assistant", "buffered only")
        return _truthful_agent_result(
            "buffered only",
            model="model-a",
            outcome="blocked",
            blocked=True,
        )

    monkeypatch.setattr(gateway_app, "agent_chat", fake_agent_chat)
    payload = {
        "message": "commit fence",
        "chat_id": "chat-commit-fence",
        "user_id": "user-commit-fence",
        "channel": "feishu",
        "model": "model-a",
        "idempotency_key": "fsmsg-v1:" + ("c" * 64),
    }
    renew_results = iter((True, False))
    with TestClient(app) as client:
        monkeypatch.setattr(
            app.state.weixin_idempotency,
            "renew",
            lambda *_a, **_k: next(renew_results),
        )
        response = client.post("/v1/agent/chat", headers=AUTH, json=payload)
        history = app.state.conversations.get("feishu:chat-commit-fence")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "durable_turn_lease_lost"
    assert history == []
