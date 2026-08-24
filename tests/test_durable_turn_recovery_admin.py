"""Strict, non-sensitive administrator lookup for durable Turn recovery."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from fastapi.testclient import TestClient

from gateway.app import app
from gateway.provider_call_ledger import (
    ProviderCallContext,
    ProviderCallLedger,
    ProviderRouteIdentity,
)
from gateway.weixin_idempotency import (
    WeixinIdempotencyUnavailable,
    hash_channel_principal,
    hash_turn_identity,
)
from orchestrator.agent import ConversationReceiptUnavailable

AUTH = {"Authorization": "Bearer test-key"}


def test_recovery_lookup_requires_admin_and_returns_only_status(
    tmp_path, monkeypatch, approval_auth_headers
):
    ledger = ProviderCallLedger(tmp_path / "provider-calls.db", required=True)
    secret_marker = "must-not-leak-provider-error-or-business-data"
    key = "wxmsg-v1:" + ("d" * 64)
    principal = hash_channel_principal(
        channel="weixin",
        user_id="recovery-admin-user",
        chat_id="recovery-admin-chat",
    )
    recovery_id = hash_turn_identity(principal, key)
    key_hash = hashlib.sha256(
        b"nachuan-durable-channel-message-key-v1\x00" + key.encode("ascii")
    ).hexdigest()
    assert recovery_id == hashlib.sha256(
        b"nachuan-weixin-turn-v1\x00"
        + principal.encode("ascii")
        + b"\x00"
        + key_hash.encode("ascii")
    ).hexdigest()
    request_sha256 = hashlib.sha256(b"recovery-admin-request").hexdigest()

    try:
        with TestClient(app) as client:
            store = client.app.state.weixin_idempotency
            claim = store.claim(principal, key, request_sha256)
            assert claim.state == "claimed"
            assert store.enter_provider_phase(
                principal,
                key,
                request_sha256,
                claim.fencing_token,
            )
            assert store.succeed(
                principal,
                key,
                request_sha256,
                claim.fencing_token,
                {
                    "reply": secret_marker,
                    "outcome": "provider_result_recovery_required",
                    "recovery_id": recovery_id,
                    "notice_trace_id": "current-notice-only",
                },
            )

            context = ProviderCallContext(
                trace_id="old-provider-trace-id",
                turn_id=recovery_id,
                workflow_id="weixin:agent_chat",
            )
            identity = ProviderRouteIdentity(
                requested_model="secret-requested-model",
                actual_model="secret-actual-model",
                provider="secret-provider",
                upstream_model="secret-upstream-model",
            )
            unknown = ledger.start_attempt(
                identity=identity,
                context=context,
                attempt=1,
                stream=False,
            )
            assert unknown.finish(
                status="provider_error",
                observed_model="served-model",
                error_type="submission_outcome_unknown",
                error_message=secret_marker,
            )
            safe = ledger.start_attempt(
                identity=identity,
                context=context,
                attempt=2,
                stream=False,
            )
            assert safe.finish(
                status="provider_error",
                error_type="ConnectError",
                error_message=secret_marker,
            )
            monkeypatch.setattr(client.app.state, "provider_call_ledger", ledger)

            denied = client.get(
                f"/admin/durable-turn-recovery/{recovery_id}", headers=AUTH
            )
            assert denied.status_code == 401
            approval_only = {
                "X-Nachuan-Approval-Key": approval_auth_headers[
                    "X-Nachuan-Approval-Key"
                ]
            }
            assert client.get(
                f"/admin/durable-turn-recovery/{recovery_id}",
                headers=approval_only,
            ).status_code == 401

            invalid = client.get(
                "/admin/durable-turn-recovery/not-a-recovery-id",
                headers=approval_auth_headers,
            )
            assert invalid.status_code == 422

            missing_id = hashlib.sha256(b"missing-recovery-id").hexdigest()
            assert missing_id != recovery_id
            missing = client.get(
                f"/admin/durable-turn-recovery/{missing_id}",
                headers=approval_auth_headers,
            )
            assert missing.status_code == 404

            result = client.get(
                f"/admin/durable-turn-recovery/{recovery_id}",
                headers=approval_auth_headers,
            )
            assert result.status_code == 200
            assert result.headers["Cache-Control"] == "no-store"
            body = result.json()
            assert set(body) == {
                "recovery_id",
                "recovery_state",
                "operator_action_required",
                "idempotency",
                "provider_calls",
                "conversation_receipt",
            }
            assert body["recovery_id"] == recovery_id
            assert body["recovery_state"] == "operator_action_required"
            assert body["operator_action_required"] is True
            assert body["conversation_receipt"] == {"found": False}
            assert body["idempotency"] == {
                "found": True,
                "record_status": "succeeded",
                "provider_phase_entered": True,
                "attempt_count": 1,
                "response_persisted": True,
                "recovery_notice_persisted": True,
                "processing_lease_active": False,
            }
            assert body["provider_calls"]["found"] is True
            assert body["provider_calls"]["total_calls"] == 2
            assert body["provider_calls"]["terminal_calls"] == 2
            assert body["provider_calls"]["open_unresolved_calls"] == 0
            assert body["provider_calls"]["status_counts"]["provider_error"] == 2
            assert body["provider_calls"]["proven_pre_submission_failures"] == 1
            assert body["provider_calls"]["possibly_submitted_calls"] == 1
            assert body["provider_calls"]["requires_operator_recovery"] is True
            assert body["provider_calls"]["attempts_truncated"] is False
            assert len(body["provider_calls"]["attempts"]) == 2
            first_attempt = body["provider_calls"]["attempts"][0]
            assert set(first_attempt) == {
                "call_id",
                "started_at",
                "finished_at",
                "attempt",
                "provider",
                "upstream_model",
                "status",
                "error_type",
                "trace_id",
                "observed_model",
            }
            assert first_attempt["provider"] == "secret-provider"
            assert first_attempt["upstream_model"] == "secret-upstream-model"
            assert first_attempt["trace_id"] == "old-provider-trace-id"
            assert first_attempt["observed_model"] == "served-model"
            serialized = json.dumps(body, sort_keys=True)
            assert secret_marker not in serialized

            def all_keys(value):
                if isinstance(value, dict):
                    for item_key, item_value in value.items():
                        yield item_key
                        yield from all_keys(item_value)
                elif isinstance(value, list):
                    for item in value:
                        yield from all_keys(item)

            returned_keys = set(all_keys(body))
            for forbidden in {
                "prompt",
                "response",
                "error_message",
                "key",
                "base_url",
                "task_id",
                "billing_dimensions_json",
            }:
                assert forbidden not in returned_keys

            # The same provider message key in another authenticated principal
            # must produce a distinct recovery handle and remain isolated.
            other_principal = hash_channel_principal(
                channel="weixin",
                user_id="recovery-admin-other-user",
                chat_id="recovery-admin-other-chat",
            )
            other_recovery_id = hash_turn_identity(other_principal, key)
            assert other_recovery_id != recovery_id
            other_request = hashlib.sha256(b"other-recovery-request").hexdigest()
            other_claim = store.claim(other_principal, key, other_request)
            assert other_claim.state == "claimed"
            assert store.enter_provider_phase(
                other_principal,
                key,
                other_request,
                other_claim.fencing_token,
            )
            business_result = {"reply": secret_marker, "blocked": False}
            assert store.succeed(
                other_principal,
                key,
                other_request,
                other_claim.fencing_token,
                business_result,
            )
            client.app.state.conversations.commit_idempotent_turn(
                turn_key=other_recovery_id,
                request_sha256=other_request,
                entries=[],
                result=business_result,
            )
            other_attempt = ledger.start_attempt(
                identity=identity,
                context=ProviderCallContext(
                    trace_id="other-old-provider-trace",
                    turn_id=other_recovery_id,
                    workflow_id="weixin:agent_chat",
                ),
                attempt=1,
                stream=False,
            )
            assert other_attempt.finish(
                status="provider_error",
                error_type="submission_outcome_unknown",
                error_message=secret_marker,
            )
            with sqlite3.connect(str(store.path)) as connection:
                deleted = connection.execute(
                    "DELETE FROM weixin_agent_idempotency WHERE recovery_id=?",
                    (other_recovery_id,),
                ).rowcount
                connection.commit()
            assert deleted == 1

            receipt_recovery = client.get(
                f"/admin/durable-turn-recovery/{other_recovery_id}",
                headers=approval_auth_headers,
            )
            assert receipt_recovery.status_code == 200
            receipt_body = receipt_recovery.json()
            assert receipt_body["idempotency"] == {"found": False}
            assert receipt_body["conversation_receipt"]["found"] is True
            assert receipt_body["conversation_receipt"]["request_hash_present"] is True
            assert receipt_body["conversation_receipt"]["response_present"] is True
            assert receipt_body["conversation_receipt"]["replay_available"] is True
            assert isinstance(receipt_body["conversation_receipt"]["created_at"], float)
            assert receipt_body["recovery_state"] == "replay_available"
            assert receipt_body["operator_action_required"] is False
            assert secret_marker not in json.dumps(receipt_body, sort_keys=True)

            isolated = client.get(
                f"/admin/durable-turn-recovery/{recovery_id}",
                headers=approval_auth_headers,
            ).json()
            assert isolated["provider_calls"]["total_calls"] == 2
            assert all(
                attempt["trace_id"] != "other-old-provider-trace"
                for attempt in isolated["provider_calls"]["attempts"]
            )

            for entered_provider_phase in (False, True):
                active_principal = hash_channel_principal(
                    channel="weixin",
                    user_id=f"active-user-{entered_provider_phase}",
                    chat_id=f"active-chat-{entered_provider_phase}",
                )
                active_recovery_id = hash_turn_identity(active_principal, key)
                active_request = hashlib.sha256(
                    f"active-request-{entered_provider_phase}".encode("ascii")
                ).hexdigest()
                active_claim = store.claim(
                    active_principal, key, active_request
                )
                assert active_claim.state == "claimed"
                if entered_provider_phase:
                    assert store.enter_provider_phase(
                        active_principal,
                        key,
                        active_request,
                        active_claim.fencing_token,
                    )
                active_result = client.get(
                    f"/admin/durable-turn-recovery/{active_recovery_id}",
                    headers=approval_auth_headers,
                )
                assert active_result.status_code == 200
                assert active_result.json()["recovery_state"] == "in_progress"
                assert active_result.json()["operator_action_required"] is False
                assert store.fail(
                    active_principal,
                    key,
                    active_request,
                    active_claim.fencing_token,
                    error_code="test_cleanup",
                )

            conversation_store = client.app.state.conversations
            original_receipt_snapshot = conversation_store.turn_receipt_snapshot

            def receipt_unavailable(_recovery_id: str) -> dict:
                raise ConversationReceiptUnavailable("receipt database unavailable")

            monkeypatch.setattr(
                conversation_store,
                "turn_receipt_snapshot",
                receipt_unavailable,
            )
            receipt_unavailable_result = client.get(
                f"/admin/durable-turn-recovery/{recovery_id}",
                headers=approval_auth_headers,
            )
            assert receipt_unavailable_result.status_code == 503
            monkeypatch.setattr(
                conversation_store,
                "turn_receipt_snapshot",
                original_receipt_snapshot,
            )

            def unavailable(_recovery_id: str) -> dict:
                raise WeixinIdempotencyUnavailable("database unavailable")

            monkeypatch.setattr(store, "recovery_snapshot", unavailable)
            unavailable_result = client.get(
                f"/admin/durable-turn-recovery/{recovery_id}",
                headers=approval_auth_headers,
            )
            assert unavailable_result.status_code == 503
    finally:
        ledger.close()
