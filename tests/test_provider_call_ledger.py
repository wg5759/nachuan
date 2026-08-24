from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import httpx
import pytest
import respx

from gateway.failover import (
    chat_once_with_deadline,
    chat_with_fallback,
    stream_with_fallback,
)
from gateway.provider_call_ledger import (
    ProviderCallContext,
    ProviderCallLedger,
    ProviderCallLedgerUnavailable,
    ProviderRouteIdentity,
    bind_provider_call_context,
    configured_provider_call_ledger,
    financial_usage_from_payload,
)
from gateway.schemas import ChatCompletionRequest
from gateway.providers.base import ProviderError, ProviderSubmissionOutcomeUnknown
from gateway.providers.openai_compat import OpenAICompatProvider


@pytest.fixture(autouse=True)
def _isolate_quota_state():
    """Ledger outcomes must not cool models used by unrelated tests."""
    from gateway import quota_state

    quota_state.clear()
    try:
        yield
    finally:
        quota_state.clear()


class _Route:
    def __init__(self, provider, upstream_model: str = "vendor-model") -> None:
        self.provider = provider
        self.upstream_model = upstream_model
        self.tier = "premium"


class _Router:
    def __init__(self, routes: dict[str, _Route]) -> None:
        self._routes = routes

    def resolve(self, model: str):  # noqa: ANN201
        return self._routes.get(model)


def _request(model: str = "primary") -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model=model,
        messages=[{"role": "user", "content": "hello"}],
    )


def _sqlite_artifacts(path) -> dict[str, bytes]:  # noqa: ANN001
    return {
        suffix: candidate.read_bytes()
        for suffix in ("", "-wal", "-shm", "-journal")
        if (candidate := path.parent / f"{path.name}{suffix}").exists()
    }


def test_unknown_sqlite_database_is_rejected_without_mutating_any_artifact(
    tmp_path,
) -> None:
    path = tmp_path / "unrelated.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("CREATE TABLE unrelated (value TEXT NOT NULL)")
        connection.execute("INSERT INTO unrelated(value) VALUES ('keep-me-byte-exact')")
    before = _sqlite_artifacts(path)

    def open_unknown_database() -> None:
        ledger = ProviderCallLedger(path, required=True)
        ledger.close()

    with pytest.raises(ProviderCallLedgerUnavailable, match="unrecognized database"):
        open_unknown_database()

    assert _sqlite_artifacts(path) == before
    with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as connection:
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "delete"
        assert connection.execute("SELECT value FROM unrelated").fetchone() == (
            "keep-me-byte-exact",
        )


def _assert_provider_ledger_reopen_is_read_only_failure(path) -> None:  # noqa: ANN001
    before = _sqlite_artifacts(path)

    def reopen() -> None:
        ledger = ProviderCallLedger(path, required=True)
        ledger.close()

    with pytest.raises(ProviderCallLedgerUnavailable, match="schema authority"):
        reopen()
    assert _sqlite_artifacts(path) == before


def test_current_database_missing_required_object_is_not_silently_repaired(
    tmp_path,
) -> None:
    path = tmp_path / "missing-object.db"
    ProviderCallLedger(path, required=True).close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP INDEX idx_provider_calls_turn")

    _assert_provider_ledger_reopen_is_read_only_failure(path)


@pytest.mark.parametrize(
    ("trigger_name", "tampered_sql"),
    (
        (
            "provider_calls_no_delete",
            """
            CREATE TRIGGER provider_calls_no_delete
            BEFORE DELETE ON provider_calls
            BEGIN
                SELECT RAISE(ABORT, 'PROVIDER CALL LEDGER IS APPEND-ONLY');
            END
            """,
        ),
        (
            "provider_calls_terminal_immutable",
            """
            CREATE TRIGGER provider_calls_terminal_immutable
            BEFORE UPDATE ON provider_calls
            WHEN OLD.status<>'started'
            BEGIN
                SELECT RAISE(ABORT, 'terminal provider call is immutable');
            END
            """,
        ),
    ),
    ids=("quoted-literal-case", "token-boundary"),
)
def test_current_database_trigger_sql_requires_exact_materialized_authority(
    tmp_path, trigger_name, tampered_sql
) -> None:
    path = tmp_path / f"tampered-{trigger_name}.db"
    ProviderCallLedger(path, required=True).close()
    with sqlite3.connect(path) as connection:
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(tampered_sql)

    _assert_provider_ledger_reopen_is_read_only_failure(path)


@pytest.mark.parametrize(
    "pragma_sql",
    ("PRAGMA application_id=305419896", "PRAGMA user_version=999"),
    ids=("application-id", "user-version"),
)
def test_current_database_wrong_version_is_rejected_without_mutation(
    tmp_path, pragma_sql
) -> None:
    path = tmp_path / "wrong-version.db"
    ProviderCallLedger(path, required=True).close()
    with sqlite3.connect(path) as connection:
        connection.execute(pragma_sql)

    _assert_provider_ledger_reopen_is_read_only_failure(path)


def test_financial_usage_rejects_fractional_and_contradictory_token_evidence() -> None:
    fractional = financial_usage_from_payload(
        {"usage": {"prompt_tokens": 1.9, "completion_tokens": "2.0", "total_tokens": 3}}
    )
    assert fractional["prompt_tokens"] is None
    assert fractional["completion_tokens"] is None

    mismatch = financial_usage_from_payload(
        {"usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 100}}
    )
    assert mismatch["prompt_tokens"] == 5
    assert mismatch["completion_tokens"] == 4
    assert mismatch["total_tokens"] is None
    assert mismatch["usage_validation_error"] == "total_tokens_mismatch"


def test_billing_dimensions_and_schema_are_stored_as_one_versioned_unit(tmp_path) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    identity = ProviderRouteIdentity(
        requested_model="image",
        actual_model="image",
        provider="vendor",
        upstream_model="image-sku",
    )

    missing_schema = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(),
        attempt=1,
        stream=False,
    )
    assert missing_schema.finish(
        status="success",
        usage={
            "billing_dimensions_json": {
                "operation": "media.generate_image",
                "n": 1,
            }
        },
    )

    empty_dimensions = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(),
        attempt=2,
        stream=False,
    )
    assert empty_dimensions.finish(
        status="success",
        usage={
            "billing_dimensions_json": {"prompt": "must never be stored"},
            "billing_dimensions_schema": "media_billing_dimensions_v1",
        },
    )

    for call in ledger.list_calls():
        assert call["billing_dimensions_json"] is None
        assert call["billing_dimensions_schema"] is None


def test_operational_snapshot_is_non_secret_and_remembers_real_write_failure(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        "gateway.provider_call_ledger.shutil.disk_usage",
        lambda _path: SimpleNamespace(
            total=100 * 1024 * 1024 * 1024,
            used=10 * 1024 * 1024 * 1024,
            free=90 * 1024 * 1024 * 1024,
        ),
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    healthy = ledger.operational_snapshot()
    assert healthy["required"] is True
    assert healthy["ready"] is True
    assert healthy["status"] == "ok"
    assert healthy["capacity_status"] == "ok"
    assert "path" not in json.dumps(healthy).lower()

    ledger._last_write_error_type = "OperationalError"
    ledger._last_write_error_at = 123.5
    failed = ledger.operational_snapshot()
    assert failed["ready"] is False
    assert failed["last_write_error_type"] == "OperationalError"
    assert failed["last_write_error_at"] == 123.5

    attempt = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="actual",
            provider="provider",
            upstream_model="sku",
        ),
        context=ProviderCallContext(),
        attempt=1,
        stream=False,
    )
    assert ledger.operational_snapshot()["ready"] is True
    assert attempt.finish(status="success") is True

    ledger.close()
    unavailable = ledger.operational_snapshot()
    assert unavailable["ready"] is False
    assert unavailable["status"] == "unavailable"
    assert unavailable["last_write_error_type"] == "ProgrammingError"


def test_durable_turn_preflight_blocks_possible_submission_but_not_proven_preconnect(
    tmp_path,
) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    turn_id = "a" * 64
    identity = ProviderRouteIdentity(
        requested_model="requested",
        actual_model="actual",
        provider="provider",
        upstream_model="sku",
    )
    workflow_id = "weixin:agent_chat"
    assert ledger.turn_requires_operator_recovery(turn_id, workflow_id) is False

    invalid_pair_turn = "b" * 64
    invalid_pair = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(
            turn_id=invalid_pair_turn,
            workflow_id=workflow_id,
        ),
        attempt=1,
        stream=False,
    )
    assert invalid_pair.finish(
        status="success",
        error_type="ConnectError",
        error_message="must not make success look pre-submission-safe",
    )
    assert ledger.turn_requires_operator_recovery(
        invalid_pair_turn, workflow_id
    ) is True
    invalid_snapshot = ledger.recovery_snapshot(invalid_pair_turn)
    assert invalid_snapshot["proven_pre_submission_failures"] == 0
    assert invalid_snapshot["possibly_submitted_calls"] == 1
    assert invalid_snapshot["requires_operator_recovery"] is True

    ordinary_http = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(
            turn_id=turn_id,
            workflow_id="http:/v1/chat/completions",
        ),
        attempt=1,
        stream=False,
    )
    assert ordinary_http.finish(status="success")
    assert ledger.turn_requires_operator_recovery(turn_id, workflow_id) is False

    preconnect = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(turn_id=turn_id, workflow_id=workflow_id),
        attempt=2,
        stream=False,
    )
    assert preconnect.finish(
        status="provider_error",
        error_type="ConnectError",
        error_message="redacted",
    )
    assert ledger.turn_requires_operator_recovery(turn_id, workflow_id) is False

    submitted = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(turn_id=turn_id, workflow_id=workflow_id),
        attempt=3,
        stream=False,
    )
    assert submitted.finish(status="success")
    assert ledger.turn_requires_operator_recovery(turn_id, workflow_id) is True

    with pytest.raises(ProviderCallLedgerUnavailable, match="lowercase SHA-256"):
        ledger.turn_requires_operator_recovery("not-a-durable-turn", workflow_id)
    with pytest.raises(ProviderCallLedgerUnavailable, match="persistent channel"):
        ledger.turn_requires_operator_recovery(turn_id, "http:/v1/chat/completions")


@pytest.mark.parametrize("status", ["provider_error", "cancelled"])
def test_durable_turn_null_error_type_is_never_proven_pre_submission(
    tmp_path, status
) -> None:
    ledger = ProviderCallLedger(tmp_path / f"null-{status}.db", required=True)
    turn_id = ("c" if status == "provider_error" else "d") * 64
    attempt = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="actual",
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
    assert attempt.finish(status=status, error_type=None)
    assert ledger.turn_requires_operator_recovery(
        turn_id, "weixin:agent_chat"
    ) is True
    snapshot = ledger.recovery_snapshot(turn_id)
    assert snapshot["proven_pre_submission_failures"] == 0
    assert snapshot["possibly_submitted_calls"] == 1
    assert snapshot["requires_operator_recovery"] is True
    ledger.close()


def test_configured_ledger_reopens_after_lifespan_closes_cached_handle(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "configured-provider-calls.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(path))
    first = configured_provider_call_ledger()
    assert isinstance(first, ProviderCallLedger)
    first.close()
    assert first.closed is True

    reopened = configured_provider_call_ledger()
    try:
        assert isinstance(reopened, ProviderCallLedger)
        assert reopened is not first
        assert reopened.closed is False
        assert reopened.operational_snapshot()["ready"] is True
    finally:
        reopened.close()


async def test_successful_provider_attempt_is_recorded_with_frozen_identity_and_usage(
    tmp_path,
) -> None:
    class Provider:
        name = "vendor"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            return {
                "model": "vendor-model-20260715",
                "choices": [{"message": {"role": "assistant", "content": "ok"}}],
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 7,
                    "total_tokens": 18,
                    "cost_usd": "0.0125",
                },
            }

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    context = ProviderCallContext(
        trace_id="trace-1",
        turn_id="turn-1",
        workflow_id="workflow-1",
        role="planner",
    )
    with bind_provider_call_context(context):
        result, served, _route = await chat_with_fallback(
            _Router({"primary": _Route(Provider())}),
            _request(),
            provider_call_ledger=ledger,
        )

    assert result["choices"][0]["message"]["content"] == "ok"
    assert served == "primary"
    calls = ledger.list_calls()
    assert len(calls) == 1
    assert calls[0] == {
        "call_id": calls[0]["call_id"],
        "started_at": calls[0]["started_at"],
        "finished_at": calls[0]["finished_at"],
        "trace_id": "trace-1",
        "turn_id": "turn-1",
        "workflow_id": "workflow-1",
        "role": "planner",
        "attempt": 1,
        "requested_model": "primary",
        "actual_model": "primary",
        "provider": "vendor",
        "upstream_model": "vendor-model",
        "observed_model": "vendor-model-20260715",
        "stream": False,
        "status": "success",
        "error_type": None,
        "error_message": None,
        "latency_ms": calls[0]["latency_ms"],
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "total_tokens": 18,
        "cached_tokens": None,
        "cache_read_tokens": None,
        "cache_creation_tokens": None,
        "cost_microusd": 12500,
        "cost_basis": None,
        "cost_attribution_basis": None,
        "provider_model_usage_json": None,
        "usage_validation_error": None,
        "billing_dimensions_json": None,
        "billing_dimensions_schema": None,
    }
    assert calls[0]["finished_at"] >= calls[0]["started_at"]
    assert calls[0]["latency_ms"] >= 0


async def test_provider_429_is_unknown_and_stops_before_second_attempt(
    tmp_path, monkeypatch
) -> None:
    class FailingProvider:
        name = "primary-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            raise ProviderError("quota exhausted", status_code=429)

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            return {
                "model": "backup-upstream",
                "choices": [{"message": {"content": "backup"}}],
            }

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    backup = BackupProvider()
    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(
            _Router(
                {
                    "primary": _Route(FailingProvider(), "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            provider_call_ledger=ledger,
        )

    assert backup.calls == 0
    calls = ledger.list_calls()
    assert [(call["attempt"], call["actual_model"], call["status"]) for call in calls] == [
        (1, "primary", "provider_error"),
    ]
    assert calls[0]["error_type"] == "chat_submission_outcome_unknown"
    assert calls[0]["error_message"] == (
        "sha256:" + hashlib.sha256(b"quota exhausted").hexdigest()
    )
    assert "quota exhausted" not in json.dumps(calls)


def test_legacy_plaintext_provider_errors_are_migrated_and_future_writes_blocked(
    tmp_path,
) -> None:
    path = tmp_path / "usage.db"
    ledger = ProviderCallLedger(path, required=True)
    attempt = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="resolved",
            provider="provider",
            upstream_model="sku",
        ),
        context=ProviderCallContext(),
        attempt=1,
        stream=False,
    )
    assert attempt.finish(
        status="provider_error",
        error_type="ProviderError",
        error_message="initial safe value",
    )
    ledger.close()

    legacy_secret = "upstream echoed prompt and sk-secret-legacy"
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER provider_calls_terminal_immutable")
        connection.execute("DROP TRIGGER provider_calls_error_message_update_redacted")
        connection.execute(
            "UPDATE provider_calls SET error_message = ? WHERE call_id = ?",
            (legacy_secret, attempt.call_id),
        )
        connection.execute(
            "DELETE FROM provider_ledger_meta WHERE key = 'error_message_fingerprint_v1'"
        )

    migrated = ProviderCallLedger(path, required=True)
    call = migrated.list_calls()[0]
    assert call["error_message"] == (
        "sha256:" + hashlib.sha256(legacy_secret.encode("utf-8")).hexdigest()
    )
    assert legacy_secret not in json.dumps(call)

    with sqlite3.connect(path) as connection, pytest.raises(
        sqlite3.IntegrityError, match="provider error text must be fingerprinted"
    ):
        connection.execute(
            """
            INSERT INTO provider_calls (
                call_id, started_at, finished_at, attempt, requested_model,
                actual_model, provider, upstream_model, stream, status,
                error_type, error_message, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "raw-error-insert",
                1.0,
                2.0,
                1,
                "requested",
                "resolved",
                "provider",
                "sku",
                0,
                "provider_error",
                "ProviderError",
                "must never persist",
                1,
            ),
        )


@pytest.mark.parametrize(
    "failure_kind",
    ("http_400", "http_503", "invalid_json", "invalid_chat_body"),
)
@respx.mock
async def test_openai_chat_response_phase_unknown_stops_fallback_and_is_not_failed(
    failure_kind, tmp_path, monkeypatch
) -> None:
    base_url = "https://chat-response-unknown.example/v1"
    if failure_kind == "http_400":
        response = httpx.Response(400, text="invalid request")
    elif failure_kind == "http_503":
        response = httpx.Response(503, text="temporary upstream failure")
    elif failure_kind == "invalid_json":
        response = httpx.Response(
            200,
            text="<html>not json</html>",
            headers={"content-type": "text/html"},
        )
    else:
        response = httpx.Response(200, json={"choices": []})
    route = respx.post(f"{base_url}/chat/completions").mock(return_value=response)
    primary = OpenAICompatProvider("primary-provider", base_url, "test-key")

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            return {"choices": [{"message": {"content": "duplicate"}}]}

    backup = BackupProvider()
    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    try:
        with pytest.raises(ProviderError):
            await chat_with_fallback(
                _Router(
                    {
                        "primary": _Route(primary, "primary-upstream"),
                        "backup": _Route(backup, "backup-upstream"),
                    }
                ),
                _request(),
                provider_call_ledger=ledger,
            )
    finally:
        await primary.aclose()

    assert route.call_count == 1
    assert backup.calls == 0
    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == (
        "provider_error",
        "chat_submission_outcome_unknown",
    )
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


@pytest.mark.parametrize(
    "failure_kind",
    ("connect_error", "connect_timeout", "pool_timeout"),
)
@respx.mock
async def test_openai_chat_proven_pre_submission_connect_failure_can_fallback(
    failure_kind, tmp_path, monkeypatch
) -> None:
    base_url = "https://chat-ordinary-failure.example/v1"
    error_type = {
        "connect_error": httpx.ConnectError,
        "connect_timeout": httpx.ConnectTimeout,
        "pool_timeout": httpx.PoolTimeout,
    }[failure_kind]
    effect = error_type(failure_kind)
    route = respx.post(f"{base_url}/chat/completions").mock(
        side_effect=effect,
    )
    primary = OpenAICompatProvider("primary-provider", base_url, "test-key")

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            return {"choices": [{"message": {"content": "backup"}}]}

    backup = BackupProvider()
    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    try:
        result, served, _route = await chat_with_fallback(
            _Router(
                {
                    "primary": _Route(primary, "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            provider_call_ledger=ledger,
        )
    finally:
        await primary.aclose()

    assert route.call_count == 1
    assert served == "backup"
    assert result["choices"][0]["message"]["content"] == "backup"
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("provider_error", error_type.__name__),
        ("success", None),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 0
    assert summary["failed_calls"] == 1


async def test_nonstream_timeout_is_terminal_not_left_started(
    tmp_path, monkeypatch
) -> None:
    class SlowProvider:
        name = "slow-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            await asyncio.Event().wait()

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["slow"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    with pytest.raises(ProviderError):
        await chat_with_fallback(
            _Router({"slow": _Route(SlowProvider(), "slow-upstream")}),
            _request("slow"),
            attempt_timeout=0.01,
            total_timeout=0.05,
            provider_call_ledger=ledger,
        )

    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("timeout", "chat_submission_outcome_unknown")
    ]


async def test_nonstream_timeout_after_invocation_stops_fallback_to_avoid_duplicate_cost(
    tmp_path, monkeypatch
) -> None:
    class SlowProvider:
        name = "slow-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            await asyncio.Event().wait()

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            return {
                "model": "backup-upstream",
                "choices": [{"message": {"content": "backup"}}],
            }

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    backup = BackupProvider()

    # A latency timeout after provider invocation cannot prove that the vendor
    # rejected the request; replaying it would risk duplicate work and billing.
    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(
            _Router(
                {
                    "primary": _Route(SlowProvider(), "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            attempt_timeout=0.01,
            total_timeout=30.0,
            provider_call_ledger=ledger,
        )

    assert backup.calls == 0
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("timeout", "chat_submission_outcome_unknown"),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_nonstream_wrapped_read_timeout_stops_fallback_to_avoid_duplicate_cost(
    tmp_path, monkeypatch
) -> None:
    class WrappedTimeoutProvider:
        name = "wrapped-timeout-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            try:
                raise httpx.ReadTimeout(
                    "upstream read timed out",
                    request=httpx.Request("POST", "https://provider.test/v1/chat"),
                )
            except httpx.ReadTimeout as exc:
                raise ProviderError("provider adapter wrapped timeout") from exc

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            return {"choices": [{"message": {"content": "backup"}}]}

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    backup = BackupProvider()

    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(
            _Router(
                {
                    "primary": _Route(WrappedTimeoutProvider(), "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            total_timeout=30.0,
            provider_call_ledger=ledger,
        )

    assert backup.calls == 0
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("provider_error", "chat_submission_outcome_unknown"),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_nonstream_wrapped_connect_error_remains_pre_submission_failure(
    tmp_path, monkeypatch
) -> None:
    class WrappedConnectErrorProvider:
        name = "wrapped-connect-error-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            try:
                raise httpx.ConnectError(
                    "connection refused",
                    request=httpx.Request("POST", "https://provider.test/v1/chat"),
                )
            except httpx.ConnectError as exc:
                raise ProviderError("provider adapter wrapped connect error") from exc

    class BackupProvider:
        name = "backup-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            return {"choices": [{"message": {"content": "backup"}}]}

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    _result, served, _route = await chat_with_fallback(
        _Router(
            {
                "primary": _Route(WrappedConnectErrorProvider(), "primary-upstream"),
                "backup": _Route(BackupProvider(), "backup-upstream"),
            }
        ),
        _request(),
        total_timeout=30.0,
        provider_call_ledger=ledger,
    )

    assert served == "backup"
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("provider_error", "ConnectError"),
        ("success", None),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 0
    assert summary["failed_calls"] == 1


async def test_nonstream_implicit_read_timeout_context_stops_fallback(
    tmp_path, monkeypatch
) -> None:
    class CustomWrappedTimeoutProvider:
        name = "custom-wrapped-timeout-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            try:
                raise httpx.ReadTimeout(
                    "upstream read timed out",
                    request=httpx.Request("POST", "https://provider.test/v1/chat"),
                )
            except httpx.ReadTimeout:
                # Some adapters use an implicit context instead of ``raise from``.
                raise RuntimeError("custom adapter wrapped timeout")

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            return {"choices": [{"message": {"content": "backup"}}]}

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    backup = BackupProvider()

    with pytest.raises(ProviderSubmissionOutcomeUnknown):
        await chat_with_fallback(
            _Router(
                {
                    "primary": _Route(CustomWrappedTimeoutProvider(), "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            total_timeout=30.0,
            provider_call_ledger=ledger,
        )

    assert backup.calls == 0
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("provider_error", "chat_submission_outcome_unknown"),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_nonstream_cancellation_is_recorded_before_it_propagates(
    tmp_path, monkeypatch
) -> None:
    started = asyncio.Event()

    class BlockingProvider:
        name = "blocking-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            started.set()
            await asyncio.Event().wait()

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["blocking"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    task = asyncio.create_task(
        chat_with_fallback(
            _Router({"blocking": _Route(BlockingProvider())}),
            _request("blocking"),
            provider_call_ledger=ledger,
        )
    )
    # Durable SQLite start may be delayed by concurrent full-repo test I/O;
    # this is only a coordination guard, not the policy timeout under test.
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("cancelled", "chat_submission_outcome_unknown")
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_named_single_chat_cancellation_after_provider_start_is_unknown(
    tmp_path,
) -> None:
    started = asyncio.Event()

    class BlockingProvider:
        name = "blocking-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            started.set()
            await asyncio.Event().wait()

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    task = asyncio.create_task(
        chat_once_with_deadline(
            BlockingProvider(),
            _request("blocking"),
            "blocking-upstream",
            provider_call_ledger=ledger,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == (
        "cancelled",
        "chat_submission_outcome_unknown",
    )
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_cancellation_while_claim_is_committing_stays_pre_invocation_cancelled(
    tmp_path, monkeypatch
) -> None:
    class Provider:
        name = "must-not-be-called"

        def __init__(self) -> None:
            self.called = False

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.called = True
            return {"choices": [{"message": {"content": "unsafe"}}]}

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    db_path = tmp_path / "usage.db"
    ledger = ProviderCallLedger(db_path, required=True)
    blocker = sqlite3.connect(db_path)
    blocker.execute("BEGIN EXCLUSIVE")
    provider = Provider()
    task = asyncio.create_task(
        chat_with_fallback(
            _Router({"primary": _Route(provider)}),
            _request(),
            provider_call_ledger=ledger,
        )
    )
    try:
        await asyncio.sleep(0.1)
        assert provider.called is False
        task.cancel()
    finally:
        blocker.rollback()
        blocker.close()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=7.0)

    assert provider.called is False
    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == (
        "cancelled",
        "cancelled_before_provider_invocation",
    )
    assert ledger.financial_summary()["outcome_unknown_calls"] == 0


async def test_named_single_provider_call_uses_the_same_ledger(tmp_path) -> None:
    class Provider:
        name = "vision-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            return {
                "model": "vision-upstream",
                "choices": [{"message": {"content": "seen"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            }

    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    result = await chat_once_with_deadline(
        Provider(),
        _request("vision-seat"),
        "vision-upstream",
        provider_call_ledger=ledger,
        call_context=ProviderCallContext(role="vision_worker"),
    )

    assert result["choices"][0]["message"]["content"] == "seen"
    calls = ledger.list_calls()
    assert [(call["actual_model"], call["role"], call["status"]) for call in calls] == [
        ("vision-seat", "vision_worker", "success")
    ]
    assert calls[0]["total_tokens"] == 4


async def test_stream_provider_error_after_invocation_stops_before_fallback(
    tmp_path, monkeypatch
) -> None:
    class FailingStream:
        name = "failed-stream"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            if False:
                yield {}
            raise ProviderError("failed before first chunk", status_code=502)

    class BackupStream:
        name = "backup-stream"

        def __init__(self) -> None:
            self.calls = 0

        async def stream(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            yield {
                "model": "backup-upstream",
                "choices": [{"delta": {"content": "ok"}}],
            }
            yield {
                "model": "backup-upstream",
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            }

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    backup = BackupStream()
    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router(
                {
                    "primary": _Route(FailingStream(), "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            provider_call_ledger=ledger,
        )
    ]

    assert backup.calls == 0
    assert len(chunks) == 1
    assert chunks[0]["error"]["type"] == "provider_error"
    calls = ledger.list_calls()
    assert [
        (call["attempt"], call["actual_model"], call["status"], call["error_type"])
        for call in calls
    ] == [
        (1, "primary", "provider_error", "stream_submission_outcome_unknown"),
    ]


@pytest.mark.parametrize(
    "failure_kind",
    ("http_400", "http_503", "invalid_json", "invalid_chat_body"),
)
@respx.mock
async def test_openai_stream_response_phase_unknown_stops_precommit_fallback(
    failure_kind, tmp_path, monkeypatch
) -> None:
    base_url = "https://stream-response-unknown.example/v1"
    if failure_kind == "http_400":
        response = httpx.Response(400, text="invalid request")
    elif failure_kind == "http_503":
        response = httpx.Response(503, text="temporary upstream failure")
    elif failure_kind == "invalid_json":
        response = httpx.Response(
            200,
            text="data: {not-json}\n\n",
            headers={"content-type": "text/event-stream"},
        )
    else:
        response = httpx.Response(
            200,
            text="data: {}\n\ndata: [DONE]\n\n",
            headers={"content-type": "text/event-stream"},
        )
    route = respx.post(f"{base_url}/chat/completions").mock(return_value=response)
    primary = OpenAICompatProvider("primary-provider", base_url, "test-key")

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def stream(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            yield {"choices": [{"delta": {"content": "duplicate"}}]}

    backup = BackupProvider()
    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    try:
        chunks = [
            chunk
            async for chunk in stream_with_fallback(
                _Router(
                    {
                        "primary": _Route(primary, "primary-upstream"),
                        "backup": _Route(backup, "backup-upstream"),
                    }
                ),
                _request(),
                provider_call_ledger=ledger,
            )
        ]
    finally:
        await primary.aclose()

    assert route.call_count == 1
    assert backup.calls == 0
    assert len(chunks) == 1
    assert chunks[0]["error"]["type"] == "provider_error"
    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == (
        "provider_error",
        "stream_submission_outcome_unknown",
    )
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


@pytest.mark.parametrize(
    "failure_kind",
    ("connect_error", "connect_timeout", "pool_timeout"),
)
@respx.mock
async def test_openai_stream_proven_pre_submission_connect_failure_can_fallback(
    failure_kind, tmp_path, monkeypatch
) -> None:
    base_url = "https://stream-ordinary-failure.example/v1"
    error_type = {
        "connect_error": httpx.ConnectError,
        "connect_timeout": httpx.ConnectTimeout,
        "pool_timeout": httpx.PoolTimeout,
    }[failure_kind]
    effect = error_type(failure_kind)
    route = respx.post(f"{base_url}/chat/completions").mock(
        side_effect=effect,
    )
    primary = OpenAICompatProvider("primary-provider", base_url, "test-key")

    class BackupProvider:
        name = "backup-provider"

        def __init__(self) -> None:
            self.calls = 0

        async def stream(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            yield {"choices": [{"delta": {"content": "backup"}}]}

    backup = BackupProvider()
    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    try:
        chunks = [
            chunk
            async for chunk in stream_with_fallback(
                _Router(
                    {
                        "primary": _Route(primary, "primary-upstream"),
                        "backup": _Route(backup, "backup-upstream"),
                    }
                ),
                _request(),
                provider_call_ledger=ledger,
            )
        ]
    finally:
        await primary.aclose()

    assert route.call_count == 1
    assert backup.calls == 1
    assert chunks[0]["choices"][0]["delta"]["content"] == "backup"
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("provider_error", error_type.__name__),
        ("success", None),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 0
    assert summary["failed_calls"] == 1


async def test_stream_first_chunk_timeout_stops_fallback_to_avoid_duplicate_cost(
    tmp_path, monkeypatch
) -> None:
    class SlowStream:
        name = "slow-stream"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            await asyncio.Event().wait()
            yield {}

    class BackupStream:
        name = "backup-stream"

        def __init__(self) -> None:
            self.calls = 0

        async def stream(self, _req, _upstream):  # noqa: ANN001
            self.calls += 1
            yield {
                "model": "backup-upstream",
                "choices": [{"delta": {"content": "backup"}}],
            }

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    backup = BackupStream()

    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router(
                {
                    "primary": _Route(SlowStream(), "primary-upstream"),
                    "backup": _Route(backup, "backup-upstream"),
                }
            ),
            _request(),
            attempt_timeout=0.1,
            total_timeout=30.0,
            first_chunk_timeout=0.01,
            idle_chunk_timeout=0.05,
            provider_call_ledger=ledger,
        )
    ]

    assert backup.calls == 0
    assert len(chunks) == 1
    assert chunks[0]["error"]["type"] == "provider_error"
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("timeout", "stream_submission_outcome_unknown"),
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_stream_transport_timeout_after_commit_is_unknown_and_never_replayed(
    tmp_path, monkeypatch
) -> None:
    backup_called = False

    class InterruptedStream:
        name = "interrupting-provider"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            yield {
                "model": "observed-model",
                "choices": [{"delta": {"content": "partial"}}],
            }
            raise httpx.ReadTimeout(
                "upstream read timed out",
                request=httpx.Request("POST", "https://provider.test/v1/chat"),
            )

    class BackupStream:
        name = "backup-provider"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            nonlocal backup_called
            backup_called = True
            yield {"choices": [{"delta": {"content": "duplicate"}}]}

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router(
                {
                    "primary": _Route(InterruptedStream(), "primary-upstream"),
                    "backup": _Route(BackupStream(), "backup-upstream"),
                }
            ),
            _request(),
            provider_call_ledger=ledger,
        )
    ]

    assert chunks[0]["choices"][0]["delta"]["content"] == "partial"
    assert chunks[-1]["error"]["type"] == "provider_error"
    assert backup_called is False
    calls = ledger.list_calls()
    assert [(call["status"], call["error_type"]) for call in calls] == [
        ("stream_interrupted", "stream_submission_outcome_unknown")
    ]
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_stream_wrapped_read_timeout_after_commit_is_still_outcome_unknown(
    tmp_path, monkeypatch
) -> None:
    backup_called = False

    class WrappedTimeoutStream:
        name = "wrapped-timeout-provider"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            yield {
                "model": "observed-model",
                "choices": [{"delta": {"content": "partial"}}],
            }
            try:
                raise httpx.ReadTimeout(
                    "upstream read timed out",
                    request=httpx.Request("POST", "https://provider.test/v1/chat"),
                )
            except httpx.ReadTimeout as exc:
                raise ProviderError("provider adapter wrapped timeout") from exc

    class BackupStream:
        name = "backup-provider"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            nonlocal backup_called
            backup_called = True
            yield {"choices": [{"delta": {"content": "duplicate"}}]}

    monkeypatch.setattr(
        "gateway.failover.fallback_chain", lambda *_args: ["primary", "backup"]
    )
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router(
                {
                    "primary": _Route(WrappedTimeoutStream(), "primary-upstream"),
                    "backup": _Route(BackupStream(), "backup-upstream"),
                }
            ),
            _request(),
            provider_call_ledger=ledger,
        )
    ]

    assert chunks[0]["choices"][0]["delta"]["content"] == "partial"
    assert chunks[-1]["error"]["type"] == "provider_error"
    assert backup_called is False
    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == (
        "stream_interrupted",
        "stream_submission_outcome_unknown",
    )
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_stream_interruption_after_first_chunk_keeps_missing_usage_unknown(
    tmp_path, monkeypatch
) -> None:
    class InterruptedStream:
        name = "interrupting-provider"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            yield {
                "model": "observed-model",
                "choices": [{"delta": {"content": "partial"}}],
            }
            raise ProviderError("connection reset after output", status_code=502)

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    chunks = [
        chunk
        async for chunk in stream_with_fallback(
            _Router({"primary": _Route(InterruptedStream(), "requested-upstream")}),
            _request(),
            provider_call_ledger=ledger,
        )
    ]

    assert chunks[0]["choices"][0]["delta"]["content"] == "partial"
    assert chunks[-1]["error"]["type"] == "provider_error"
    call = ledger.list_calls()[0]
    assert call["status"] == "stream_interrupted"
    assert call["observed_model"] == "observed-model"
    assert call["prompt_tokens"] is None
    assert call["completion_tokens"] is None
    assert call["total_tokens"] is None
    assert call["cost_microusd"] is None


async def test_stream_consumer_cancellation_is_terminal_in_the_ledger(
    tmp_path, monkeypatch
) -> None:
    first_seen = asyncio.Event()

    class BlockingStream:
        name = "blocking-stream"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            yield {"model": "blocking-upstream", "choices": [{"delta": {"content": "one"}}]}
            await asyncio.Event().wait()

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    async def consume() -> None:
        async for chunk in stream_with_fallback(
            _Router({"primary": _Route(BlockingStream())}),
            _request(),
            provider_call_ledger=ledger,
        ):
            if chunk.get("choices"):
                first_seen.set()

    task = asyncio.create_task(consume())
    # Durable SQLite start may be delayed by concurrent full-repo test I/O;
    # this is only a coordination guard, not the policy timeout under test.
    await asyncio.wait_for(first_seen.wait(), timeout=5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    call = ledger.list_calls()[0]
    assert call["status"] == "cancelled"
    assert call["error_type"] == "stream_submission_outcome_unknown"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_stream_cancellation_before_first_chunk_after_provider_start_is_unknown(
    tmp_path, monkeypatch
) -> None:
    started = asyncio.Event()

    class BlockingStream:
        name = "blocking-stream"

        async def stream(self, _req, _upstream):  # noqa: ANN001
            started.set()
            await asyncio.Event().wait()
            yield {}

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    async def consume() -> None:
        async for _chunk in stream_with_fallback(
            _Router({"primary": _Route(BlockingStream())}),
            _request(),
            provider_call_ledger=ledger,
        ):
            pass

    task = asyncio.create_task(consume())
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    call = ledger.list_calls()[0]
    assert (call["status"], call["error_type"]) == (
        "cancelled",
        "stream_submission_outcome_unknown",
    )
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


async def test_stream_close_cancellation_cannot_strand_started_accounting(
    tmp_path, monkeypatch
) -> None:
    class CancellingCloseIterator:
        def __init__(self) -> None:
            self.sent = False

        def __aiter__(self):  # noqa: ANN204
            return self

        async def __anext__(self):  # noqa: ANN204
            if not self.sent:
                self.sent = True
                return {
                    "model": "observed",
                    "choices": [{"delta": {"content": "one"}}],
                }
            await asyncio.Event().wait()

        async def aclose(self) -> None:
            raise asyncio.CancelledError("provider close cancelled")

    class Provider:
        name = "bad-close-provider"

        def stream(self, _req, _upstream):  # noqa: ANN001, ANN201
            return CancellingCloseIterator()

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    stream = stream_with_fallback(
        _Router({"primary": _Route(Provider())}),
        _request(),
        provider_call_ledger=ledger,
    )

    first = await stream.__anext__()
    assert first["choices"][0]["delta"]["content"] == "one"
    with pytest.raises(asyncio.CancelledError, match="provider close cancelled"):
        await stream.aclose()

    call = ledger.list_calls()[0]
    assert call["status"] == "cancelled"
    assert call["error_type"] == "stream_submission_outcome_unknown"
    summary = ledger.financial_summary()
    assert summary["outcome_unknown_calls"] == 1
    assert summary["failed_calls"] == 0


def test_call_id_is_a_single_execution_claim_and_terminal_record_cannot_be_rewritten(
    tmp_path,
) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    identity = ProviderRouteIdentity(
        requested_model="requested",
        actual_model="actual",
        provider="provider",
        upstream_model="upstream",
    )
    first = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(trace_id="trace"),
        attempt=1,
        stream=False,
        call_id="stable-call-id",
    )
    with pytest.raises(ProviderCallLedgerUnavailable, match="claimed execution"):
        ledger.start_attempt(
            identity=identity,
            context=ProviderCallContext(trace_id="trace"),
            attempt=1,
            stream=False,
            call_id="stable-call-id",
        )

    assert first.call_id == "stable-call-id"
    assert len(ledger.list_calls()) == 1
    assert first.finish(status="success") is True
    with pytest.raises(ProviderCallLedgerUnavailable, match="claimed execution"):
        ledger.start_attempt(
            identity=identity,
            context=ProviderCallContext(trace_id="trace"),
            attempt=1,
            stream=False,
            call_id="stable-call-id",
        )
    call = ledger.list_calls()[0]
    assert call["status"] == "success"
    assert call["error_type"] is None


async def test_required_ledger_start_failure_blocks_provider_before_invocation(
    monkeypatch,
) -> None:
    class UnwritableLedger:
        required = True

        def start_attempt(self, **_fields):  # noqa: ANN003, ANN201
            raise ProviderCallLedgerUnavailable("disk is read-only")

    class Provider:
        name = "must-not-run"

        def __init__(self) -> None:
            self.called = False

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.called = True
            return {"choices": [{"message": {"content": "unsafe"}}]}

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    provider = Provider()
    with pytest.raises(ProviderCallLedgerUnavailable, match="read-only"):
        await chat_with_fallback(
            _Router({"primary": _Route(provider)}),
            _request(),
            provider_call_ledger=UnwritableLedger(),
        )

    assert provider.called is False


async def test_provider_identity_is_frozen_before_hot_reload_mutates_route(
    tmp_path, monkeypatch
) -> None:
    class MutatingProvider:
        name = "provider-before"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.name = "provider-after"
            self.route.upstream_model = "upstream-after"
            return {
                "model": "observed-model",
                "choices": [{"message": {"content": "ok"}}],
            }

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    provider = MutatingProvider()
    route = _Route(provider, "upstream-before")
    provider.route = route
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    await chat_with_fallback(
        _Router({"primary": route}),
        _request(),
        provider_call_ledger=ledger,
    )

    call = ledger.list_calls()[0]
    assert call["provider"] == "provider-before"
    assert call["upstream_model"] == "upstream-before"
    assert call["observed_model"] == "observed-model"


async def test_required_environment_mode_rejects_an_unopenable_database(
    tmp_path, monkeypatch
) -> None:
    class Provider:
        name = "must-not-run"

        def __init__(self) -> None:
            self.called = False

        async def chat(self, _req, _upstream):  # noqa: ANN001
            self.called = True
            return {"choices": [{"message": {"content": "unsafe"}}]}

    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    # sqlite3 cannot open a directory as a database file.
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(tmp_path))
    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    provider = Provider()

    with pytest.raises(ProviderCallLedgerUnavailable, match="initialization failed"):
        await chat_with_fallback(
            _Router({"primary": _Route(provider)}),
            _request(),
        )

    assert provider.called is False


async def test_required_ledger_failure_blocks_stream_method_too(monkeypatch) -> None:
    class UnwritableLedger:
        required = True

        def start_attempt(self, **_fields):  # noqa: ANN003, ANN201
            raise ProviderCallLedgerUnavailable("stream ledger unavailable")

    class StreamProvider:
        name = "must-not-stream"

        def __init__(self) -> None:
            self.called = False

        def stream(self, _req, _upstream):  # noqa: ANN001, ANN201
            self.called = True
            raise AssertionError("provider stream must stay blocked")

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    provider = StreamProvider()
    with pytest.raises(ProviderCallLedgerUnavailable, match="stream ledger unavailable"):
        _ = [
            chunk
            async for chunk in stream_with_fallback(
                _Router({"primary": _Route(provider)}),
                _request(),
                provider_call_ledger=UnwritableLedger(),
            )
        ]

    assert provider.called is False


async def test_out_of_range_provider_usage_finishes_success_with_unknown_values(
    tmp_path, monkeypatch
) -> None:
    class Provider:
        name = "overflow-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            return {
                "model": "observed",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 2**80,
                    "completion_tokens": 3,
                    "total_tokens": 2**80,
                    "cost_usd": "1e1000",
                },
            }

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    result, _served, _route = await chat_with_fallback(
        _Router({"primary": _Route(Provider())}),
        _request(),
        provider_call_ledger=ledger,
    )

    assert result["choices"][0]["message"]["content"] == "ok"
    call = ledger.list_calls()[0]
    assert call["status"] == "success"
    assert call["prompt_tokens"] is None
    assert call["completion_tokens"] == 3
    assert call["total_tokens"] is None
    assert call["cost_microusd"] is None


def test_terminal_capacity_is_reserved_before_execution_and_released_on_finish(
    tmp_path,
) -> None:
    path = tmp_path / "usage.db"
    ledger = ProviderCallLedger(path, required=True)
    attempt = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="actual",
            provider="provider",
            upstream_model="upstream",
        ),
        context=ProviderCallContext(trace_id="trace"),
        attempt=1,
        stream=False,
    )
    with sqlite3.connect(path) as reader:
        assert reader.execute(
            "SELECT length(terminal_reserve) FROM provider_calls"
        ).fetchone()[0] == 32 * 1024
    assert attempt.finish(status="success") is True
    with sqlite3.connect(path) as reader:
        assert reader.execute(
            "SELECT terminal_reserve FROM provider_calls"
        ).fetchone()[0] is None


def test_stale_started_attempt_is_reconciled_as_unknown_provider_error(tmp_path) -> None:
    ledger = ProviderCallLedger(
        tmp_path / "usage.db",
        required=True,
        stale_started_after_seconds=60,
    )
    attempt = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="actual",
            provider="provider",
            upstream_model="upstream",
        ),
        context=ProviderCallContext(trace_id="trace"),
        attempt=1,
        stream=False,
    )
    started_at = ledger.list_calls()[0]["started_at"]

    assert ledger.reconcile_stale_started(now=started_at + 61) == 1
    call = ledger.list_calls()[0]
    assert call["status"] == "provider_error"
    assert call["error_type"] == "stale_started_reconciled"
    assert call["prompt_tokens"] is None
    assert call["cost_microusd"] is None
    assert attempt.finish(status="success") is False


def test_concurrent_cold_start_is_reliable_and_keeps_one_schema(tmp_path) -> None:
    path = tmp_path / "usage.db"

    def initialize(_index: int) -> int:
        ledger = ProviderCallLedger(path, required=True)
        try:
            return len(ledger.list_calls())
        finally:
            ledger.close()

    with ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(initialize, range(24)))

    assert results == [0] * 24
    with sqlite3.connect(path) as reader:
        columns = {
            row[1] for row in reader.execute("PRAGMA table_info(provider_calls)")
        }
    assert "terminal_reserve" in columns


def test_financial_summary_keeps_partial_cost_and_tokens_unknown(tmp_path) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    identity = ProviderRouteIdentity(
        requested_model="requested",
        actual_model="resolved-alias",
        provider="vendor",
        upstream_model="configured-sku",
    )
    known = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(trace_id="trace"),
        attempt=1,
        stream=False,
    )
    unknown = ledger.start_attempt(
        identity=identity,
        context=ProviderCallContext(trace_id="trace"),
        attempt=2,
        stream=False,
    )
    assert known.finish(
        status="success",
        usage={
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
            "cost_microusd": 12_500,
        },
    )
    assert unknown.finish(status="provider_error", error_type="timeout")

    summary = ledger.financial_summary()
    assert summary["financial_source"] is True
    assert summary["total_calls"] == 2
    assert summary["unknown_token_calls"] == 1
    assert summary["unknown_cost_calls"] == 1
    assert summary["known_cost_usd"] == 0.0125
    assert summary["total_cost_usd"] is None
    row = summary["models"][0]
    assert row["resolved_model"] == "resolved-alias"
    assert row["model"] == "configured-sku"
    assert row["identity_basis"] == "configured_upstream_unverified"
    assert row["known_total_tokens"] == 15
    assert row["total_tokens"] is None
    assert row["known_cost_usd"] == 0.0125
    assert row["cost_usd"] is None


async def test_provider_response_cannot_self_grant_invoice_or_estimate_authority(
    tmp_path, monkeypatch
) -> None:
    class Provider:
        name = "untrusted-cost-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            return {
                "model": "observed",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                    "cost_usd": "1.25",
                    "cost_basis": "invoice_reconciled",
                },
            }

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    await chat_with_fallback(
        _Router({"primary": _Route(Provider())}),
        _request(),
        provider_call_ledger=ledger,
    )

    call = ledger.list_calls()[0]
    assert call["cost_microusd"] == 1_250_000
    assert call["cost_basis"] is None
    summary = ledger.financial_summary()
    assert summary["known_cost_usd"] == 1.25
    assert summary["billed_cost_usd"] == 0
    assert summary["unverified_cost_calls"] == 1
    assert summary["total_cost_usd"] is None
    assert summary["cost_basis"] == "unverified_cost_evidence"


async def test_provider_reported_cost_keeps_internal_model_breakdown(
    tmp_path, monkeypatch
) -> None:
    class Provider:
        name = "cli-provider"

        async def chat(self, _req, _upstream):  # noqa: ANN001
            return {
                "model": "primary-physical-model",
                "choices": [{"message": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 4,
                    "total_tokens": 14,
                    "cached_tokens": 2,
                    "cache_read_tokens": 2,
                    "cache_creation_tokens": 3,
                    "cost_usd": "0.25",
                    "cost_basis": "provider_reported",
                    "cost_attribution_basis": (
                        "cli_invocation_total_includes_provider_internal_models"
                    ),
                    "provider_model_usage": {
                        "primary-physical-model": {
                            "input_tokens": 5,
                            "output_tokens": 4,
                            "cache_read_input_tokens": 2,
                            "cache_creation_input_tokens": 3,
                        },
                        "auxiliary-model": {"input_tokens": 1, "cost_usd": "0.01"},
                    },
                },
            }

    monkeypatch.setattr("gateway.failover.fallback_chain", lambda *_args: ["primary"])
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    await chat_with_fallback(
        _Router({"primary": _Route(Provider())}),
        _request(),
        provider_call_ledger=ledger,
    )

    call = ledger.list_calls()[0]
    assert call["cost_basis"] == "provider_reported"
    assert call["cache_read_tokens"] == 2
    assert call["cache_creation_tokens"] == 3
    assert call["cost_attribution_basis"] == (
        "cli_invocation_total_includes_provider_internal_models"
    )
    breakdown = json.loads(call["provider_model_usage_json"])
    assert breakdown["auxiliary-model"] == {
        "cost_microusd": 10_000,
        "input_tokens": 1,
    }
    summary = ledger.financial_summary()
    assert summary["provider_reported_cost_calls"] == 1
    assert summary["provider_internal_breakdown_calls"] == 1
    assert summary["provider_reported_cost_usd"] == 0.25
    assert summary["billed_cost_usd"] == 0
    assert summary["total_cost_usd"] is None
    assert summary["billed_cost_complete"] is False
    assert summary["cost_basis"] == "provider_reported_complete"


def test_versioned_local_estimate_is_separate_from_actual_cost(tmp_path) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    attempt = ledger.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="resolved",
            provider="provider",
            upstream_model="sku",
        ),
        context=ProviderCallContext(),
        attempt=1,
        stream=False,
    )
    assert attempt.finish(
        status="success",
        usage={"cost_microusd": 500_000, "cost_basis": "estimated_local_table_v1"},
    )

    summary = ledger.financial_summary()
    assert summary["billed_cost_usd"] == 0
    assert summary["estimated_cost_usd"] == 0.5
    assert summary["total_cost_usd"] is None
    assert summary["billed_cost_complete"] is False
    assert summary["cost_basis"] == "versioned_estimate_complete"


def test_financial_summary_cache_is_copy_safe_and_invalidates_external_writes(
    tmp_path,
) -> None:
    path = tmp_path / "usage.db"
    reader = ProviderCallLedger(path, required=True)
    first = reader.financial_summary()
    first["models"].append({"tampered": True})
    assert reader.financial_summary()["models"] == []

    writer = ProviderCallLedger(path, required=True)
    attempt = writer.start_attempt(
        identity=ProviderRouteIdentity(
            requested_model="requested",
            actual_model="resolved",
            provider="provider",
            upstream_model="sku",
        ),
        context=ProviderCallContext(),
        attempt=1,
        stream=False,
    )
    assert attempt.finish(status="success")

    refreshed = reader.financial_summary()
    assert refreshed["total_calls"] == 1
    assert refreshed["database_bytes"] > 0
    assert refreshed["max_database_bytes"] >= refreshed["database_bytes"]
    assert refreshed["capacity_status"] in {"ok", "warning", "critical"}


def test_financial_summary_uses_a_short_lived_read_only_snapshot(
    tmp_path, monkeypatch
) -> None:
    ledger = ProviderCallLedger(tmp_path / "中文账本" / "调用记录.db", required=True)
    real_connect = sqlite3.connect
    observed: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def tracked_connect(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        observed.append((args, dict(kwargs)))
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    assert ledger.financial_summary()["total_calls"] == 0

    assert len(observed) == 1
    args, kwargs = observed[0]
    assert kwargs.get("uri") is True
    assert kwargs.get("check_same_thread") is False
    assert str(args[0]).endswith("?mode=ro")


def test_financial_summary_read_snapshot_failure_is_fail_closed(
    tmp_path, monkeypatch
) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    def broken_connect(*_args, **_kwargs):
        raise sqlite3.OperationalError("sensitive path or database detail")

    monkeypatch.setattr(sqlite3, "connect", broken_connect)
    with pytest.raises(
        ProviderCallLedgerUnavailable,
        match="financial summary unavailable: OperationalError",
    ) as exc_info:
        ledger.financial_summary()
    assert "sensitive path" not in str(exc_info.value)


def test_financial_summary_cache_probe_path_failure_is_fail_closed(
    tmp_path, monkeypatch
) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)

    def broken_path_check():
        raise OSError("sensitive redirected database path")

    monkeypatch.setattr(ledger, "_assert_database_path", broken_path_check)
    with pytest.raises(
        ProviderCallLedgerUnavailable,
        match="financial summary unavailable: OSError",
    ) as exc_info:
        ledger.financial_summary()
    assert "sensitive redirected" not in str(exc_info.value)


def test_period_window_uses_started_at_range_index(tmp_path) -> None:
    path = tmp_path / "usage.db"
    ProviderCallLedger(path, required=True).close()

    with sqlite3.connect(path) as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM provider_calls "
            "WHERE started_at >= ? AND started_at < ?",
            (0.0, 4_000_000_000.0),
        ).fetchall()

    detail = " ".join(str(row[3]) for row in plan).upper()
    assert "SEARCH PROVIDER_CALLS" in detail
    assert "IDX_PROVIDER_CALLS_STARTED" in detail


def test_financial_summary_exact_aggregate_cannot_overflow_sqlite_int64(
    tmp_path,
) -> None:
    ledger = ProviderCallLedger(tmp_path / "usage.db", required=True)
    identity = ProviderRouteIdentity(
        requested_model="requested",
        actual_model="resolved",
        provider="provider",
        upstream_model="sku",
    )
    maximum = (1 << 63) - 1
    for attempt_number in (1, 2):
        attempt = ledger.start_attempt(
            identity=identity,
            context=ProviderCallContext(),
            attempt=attempt_number,
            stream=False,
        )
        assert attempt.finish(
            status="success",
            usage={
                "prompt_tokens": maximum,
                "cost_microusd": maximum,
                "cost_basis": "provider_reported",
            },
        )

    summary = ledger.financial_summary(period="all")
    assert summary["models"][0]["known_prompt_tokens"] == maximum * 2
    assert summary["known_cost_microusd"] == str(maximum * 2)
    assert summary["provider_reported_cost_calls"] == 2


def test_http_trace_context_reaches_the_required_provider_ledger(
    tmp_path, monkeypatch
) -> None:
    from fastapi.testclient import TestClient

    from gateway.app import app

    db_path = tmp_path / "http-usage.db"
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_MODE", "required")
    monkeypatch.setenv("NACHUAN_PROVIDER_CALL_LEDGER_PATH", str(db_path))

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={
                "Authorization": "Bearer test-key",
                "X-Request-ID": "ledger.http.trace",
            },
            json={
                "model": "echo",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )

    assert response.status_code == 200
    calls = ProviderCallLedger(db_path, required=True).list_calls()
    # The request may also schedule memory extraction, which is another real
    # provider call.  Every hop must retain the originating HTTP trace.
    assert calls
    assert all(call["trace_id"] == "ledger.http.trace" for call in calls)
    assert all(call["status"] != "started" for call in calls)
    assert any(call["requested_model"] == "echo" for call in calls)
