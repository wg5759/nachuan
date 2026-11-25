from __future__ import annotations

import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

import pytest

from gateway.user_session_agent_protocol import (
    UserSessionAgentVerifier,
    derive_user_principal_key,
    derive_user_session_key,
    encode_user_session_frame,
)
from gateway.user_session_operation_ledger import (
    UserSessionOperationConflict,
    UserSessionOperationLedger,
    UserSessionOperationLedgerError,
)


INSTALLATION_ID = "a" * 64
ROOT_EPOCH = 7


def _scope(
    *,
    operation_id: str,
    principal_hash: str = "1" * 64,
    service_boot_id: str = "3" * 64,
    session_id: int = 8,
    agent_generation: int = 2,
    connector: str = "codex",
    fence: str = "5" * 64,
    direction: str = "agent_to_service",
):
    context = {
        "installation_id": INSTALLATION_ID,
        "root_epoch": ROOT_EPOCH,
        "service_boot_id": service_boot_id,
        "principal_hash": principal_hash,
        "session_id": session_id,
        "agent_generation": agent_generation,
    }
    principal_key = derive_user_principal_key(
        root_key="sk-service-pipe-" + "9" * 64,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
        principal_hash=principal_hash,
    )
    session_key = derive_user_session_key(
        principal_key=principal_key,
        **context,
    )
    raw = encode_user_session_frame(
        session_key=session_key,
        direction=direction,
        sequence=1,
        operation_id=operation_id,
        connector=connector,
        capability="subscription.status",
        payload={},
        fence=fence,
        **context,
    )
    return UserSessionAgentVerifier(
        session_key=session_key,
        expected_direction=direction,
        expected_sequence=1,
        **context,
    ).verify(raw).scope


def test_provider_phase_disconnect_is_unknown_and_never_reprepared(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    operation_id = str(uuid.uuid4())
    scope = _scope(operation_id=operation_id)
    ledger = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    prepared = ledger.prepare(scope)
    authorized = ledger.authorize_dispatch(scope)
    with pytest.raises(UserSessionOperationConflict):
        ledger.authorize_dispatch(scope)
    unknown = ledger.mark_disconnect(scope)

    assert prepared.state == "prepared" and prepared.retry_safe is True
    assert authorized.state == "dispatch_authorized"
    assert unknown.state == "submitted_unknown"
    assert unknown.retry_safe is False
    with pytest.raises(UserSessionOperationConflict):
        ledger.authorize_dispatch(scope)

    reopened = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    replay = reopened.prepare(scope)
    assert replay == unknown
    assert reopened.get(scope) == unknown
    raw = path.read_bytes()
    assert b"prompt" not in raw
    assert b"sk-" not in raw


def test_every_operation_lookup_and_transition_requires_the_authenticated_scope(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    operation_id = str(uuid.uuid4())
    owner = _scope(operation_id=operation_id)
    ledger = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    ledger.prepare(owner)

    with pytest.raises(UserSessionOperationLedgerError, match="agent request"):
        ledger.prepare(
            _scope(operation_id=str(uuid.uuid4()), direction="service_to_agent")
        )

    for alien in (
        _scope(operation_id=operation_id, principal_hash="2" * 64),
        _scope(operation_id=operation_id, service_boot_id="4" * 64),
        _scope(operation_id=operation_id, session_id=9),
        _scope(operation_id=operation_id, agent_generation=3),
        _scope(operation_id=operation_id, fence="6" * 64),
        _scope(operation_id=operation_id, connector="kimi_code"),
    ):
        with pytest.raises(UserSessionOperationLedgerError, match="unavailable"):
            ledger.get(alien)
        with pytest.raises(UserSessionOperationLedgerError, match="unavailable"):
            ledger.mark_disconnect(alien)

    with pytest.raises(UserSessionOperationConflict):
        ledger.prepare(_scope(operation_id=operation_id, service_boot_id="4" * 64))
    assert ledger.get(owner).state == "prepared"


def test_success_is_terminal_and_row_invariants_are_closed(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    scope = _scope(operation_id=str(uuid.uuid4()))
    ledger = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    ledger.prepare(scope)
    ledger.authorize_dispatch(scope)
    ledger.mark_provider_phase(scope)
    succeeded = ledger.mark_succeeded(scope, result_digest="7" * 64)

    assert succeeded.state == "succeeded"
    assert succeeded.retry_safe is False
    assert succeeded.result_digest == "7" * 64
    assert succeeded.state_sequence == 4
    assert ledger.mark_disconnect(scope) == succeeded
    with pytest.raises(UserSessionOperationConflict):
        ledger.authorize_dispatch(scope)
    with pytest.raises(UserSessionOperationConflict):
        ledger.mark_provider_phase(scope)


def test_database_identity_schema_and_connection_lifetime_are_strict(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    scope = _scope(operation_id=str(uuid.uuid4()))
    ledger = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    ledger.prepare(scope)
    assert ledger.get(scope).state == "prepared"

    # Windows only permits this while every SQLite connection is really closed.
    moved = path.with_name("closed-handle-proof.db")
    path.replace(moved)
    moved.replace(path)

    with closing(sqlite3.connect(path)) as connection:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    assert application_id == 0x4E435541
    assert user_version == 1

    with pytest.raises(UserSessionOperationLedgerError, match="authority"):
        UserSessionOperationLedger(
            path,
            installation_id="b" * 64,
            root_epoch=ROOT_EPOCH,
        )
    with pytest.raises(UserSessionOperationLedgerError, match="authority"):
        UserSessionOperationLedger(
            path,
            installation_id=INSTALLATION_ID,
            root_epoch=ROOT_EPOCH + 1,
        )

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA user_version=99")
        connection.commit()
    with pytest.raises(UserSessionOperationLedgerError, match="schema or integrity"):
        UserSessionOperationLedger(
            path,
            installation_id=INSTALLATION_ID,
            root_epoch=ROOT_EPOCH,
        )


def test_extra_schema_objects_fail_closed(tmp_path: Path) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    scope = _scope(operation_id=str(uuid.uuid4()))
    ledger = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    ledger.prepare(scope)

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE injected(value TEXT)")
        connection.commit()
    with pytest.raises(UserSessionOperationLedgerError, match="schema or integrity"):
        UserSessionOperationLedger(
            path,
            installation_id=INSTALLATION_ID,
            root_epoch=ROOT_EPOCH,
        )


def test_application_id_tamper_fails_closed(tmp_path: Path) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA application_id=1")
        connection.commit()

    with pytest.raises(UserSessionOperationLedgerError, match="schema or integrity"):
        UserSessionOperationLedger(
            path,
            installation_id=INSTALLATION_ID,
            root_epoch=ROOT_EPOCH,
        )


def test_invalid_state_rows_fail_closed_even_if_sqlite_checks_were_bypassed(
    tmp_path: Path,
) -> None:
    path = (tmp_path / "user-session-operations.db").resolve()
    scope = _scope(operation_id=str(uuid.uuid4()))
    ledger = UserSessionOperationLedger(
        path,
        installation_id=INSTALLATION_ID,
        root_epoch=ROOT_EPOCH,
    )
    ledger.prepare(scope)

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE operations SET state='succeeded',retry_safe=1,"
            "result_digest=NULL,state_sequence=2 WHERE operation_id=?",
            (scope.operation_id,),
        )
        connection.commit()

    with pytest.raises(UserSessionOperationLedgerError, match="integrity|row"):
        UserSessionOperationLedger(
            path,
            installation_id=INSTALLATION_ID,
            root_epoch=ROOT_EPOCH,
        )
