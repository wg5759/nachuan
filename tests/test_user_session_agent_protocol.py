from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from gateway.user_session_agent_protocol import (
    UserSessionAgentProtocolError,
    UserSessionAgentVerifier,
    VerifiedUserSessionOperationScope,
    derive_user_principal_key,
    derive_user_session_key,
    encode_user_session_frame,
)


def test_status_frame_is_identity_bound_strictly_ordered_and_not_replayable() -> None:
    root_key = "sk-service-pipe-" + "1" * 64
    context = {
        "installation_id": "2" * 64,
        "root_epoch": 7,
        "service_boot_id": "3" * 64,
        "principal_hash": "4" * 64,
        "session_id": 8,
        "agent_generation": 2,
    }
    principal_key = derive_user_principal_key(
        root_key=root_key,
        installation_id=context["installation_id"],
        root_epoch=context["root_epoch"],
        principal_hash=context["principal_hash"],
    )
    session_key = derive_user_session_key(principal_key=principal_key, **context)
    operation_id = str(uuid.uuid4())
    raw = encode_user_session_frame(
        session_key=session_key,
        direction="agent_to_service",
        sequence=1,
        operation_id=operation_id,
        connector="codex",
        capability="subscription.status",
        payload={},
        fence="5" * 64,
        **context,
    )
    verifier = UserSessionAgentVerifier(
        session_key=session_key,
        expected_direction="agent_to_service",
        expected_sequence=1,
        **context,
    )

    verified = verifier.verify(raw)

    assert verified.operation_id == operation_id
    assert verified.connector == "codex"
    assert verified.capability == "subscription.status"
    assert verified.payload == {}
    assert verified.scope.installation_id == context["installation_id"]
    assert verified.scope.root_epoch == context["root_epoch"]
    assert verified.scope.service_boot_id == context["service_boot_id"]
    assert verified.scope.principal_hash == context["principal_hash"]
    assert verified.scope.session_id == context["session_id"]
    assert verified.scope.agent_generation == context["agent_generation"]
    assert verified.scope.connector == "codex"
    assert verified.scope.operation_id == operation_id
    assert verified.scope.fence == "5" * 64
    assert verifier.next_sequence == 2
    with pytest.raises(UserSessionAgentProtocolError, match="sequence"):
        verifier.verify(raw)

    document = json.loads(raw)
    document["capability"] = "subscription.invoke_text"
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(UserSessionAgentProtocolError):
        UserSessionAgentVerifier(
            session_key=session_key,
            expected_direction="agent_to_service",
            expected_sequence=1,
            **context,
        ).verify(tampered)

    other_context = {**context, "principal_hash": "6" * 64}
    other_principal_key = derive_user_principal_key(
        root_key=root_key,
        installation_id=other_context["installation_id"],
        root_epoch=other_context["root_epoch"],
        principal_hash=other_context["principal_hash"],
    )
    assert other_principal_key != principal_key
    assert (
        derive_user_session_key(principal_key=other_principal_key, **other_context)
        != session_key
    )
    with pytest.raises(UserSessionAgentProtocolError):
        UserSessionAgentVerifier(
            session_key=session_key,
            expected_direction="agent_to_service",
            expected_sequence=1,
            **other_context,
        ).verify(raw)
    assert all(
        forbidden not in raw
        for forbidden in (b"prompt", b"argv", b"cwd", b"env", b"user_id")
    )


def test_same_sequence_concurrently_authenticates_at_most_once() -> None:
    context = {
        "installation_id": "2" * 64,
        "root_epoch": 7,
        "service_boot_id": "3" * 64,
        "principal_hash": "4" * 64,
        "session_id": 8,
        "agent_generation": 2,
    }
    principal_key = derive_user_principal_key(
        root_key="sk-service-pipe-" + "1" * 64,
        installation_id=context["installation_id"],
        root_epoch=context["root_epoch"],
        principal_hash=context["principal_hash"],
    )
    session_key = derive_user_session_key(principal_key=principal_key, **context)
    raw = encode_user_session_frame(
        session_key=session_key,
        direction="agent_to_service",
        sequence=1,
        operation_id=str(uuid.uuid4()),
        connector="codex",
        capability="subscription.status",
        payload={},
        fence="5" * 64,
        **context,
    )
    verifier = UserSessionAgentVerifier(
        session_key=session_key,
        expected_direction="agent_to_service",
        expected_sequence=1,
        **context,
    )
    start = threading.Barrier(8)

    def verify_once() -> str:
        start.wait()
        try:
            verifier.verify(raw)
        except UserSessionAgentProtocolError:
            return "rejected"
        return "accepted"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _index: verify_once(), range(8)))

    assert outcomes.count("accepted") == 1
    assert outcomes.count("rejected") == 7
    assert verifier.next_sequence == 2


def test_non_finite_frame_values_are_closed_protocol_failures() -> None:
    context = {
        "installation_id": "2" * 64,
        "root_epoch": 7,
        "service_boot_id": "3" * 64,
        "principal_hash": "4" * 64,
        "session_id": 8,
        "agent_generation": 2,
    }
    principal_key = derive_user_principal_key(
        root_key="sk-service-pipe-" + "1" * 64,
        installation_id=context["installation_id"],
        root_epoch=context["root_epoch"],
        principal_hash=context["principal_hash"],
    )
    session_key = derive_user_session_key(principal_key=principal_key, **context)
    raw = encode_user_session_frame(
        session_key=session_key,
        direction="agent_to_service",
        sequence=1,
        operation_id=str(uuid.uuid4()),
        connector="codex",
        capability="subscription.status",
        payload={},
        fence="5" * 64,
        **context,
    )
    document = json.loads(raw)
    document["root_epoch"] = float("nan")
    malformed = json.dumps(
        document,
        allow_nan=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    verifier = UserSessionAgentVerifier(
        session_key=session_key,
        expected_direction="agent_to_service",
        expected_sequence=1,
        **context,
    )

    with pytest.raises(UserSessionAgentProtocolError):
        verifier.verify(malformed)
    assert verifier.next_sequence == 1


def test_operation_scope_cannot_be_constructed_without_frame_authentication() -> None:
    with pytest.raises(UserSessionAgentProtocolError, match="not authenticated"):
        VerifiedUserSessionOperationScope(
            installation_id="2" * 64,
            root_epoch=7,
            service_boot_id="3" * 64,
            principal_hash="4" * 64,
            session_id=8,
            agent_generation=2,
            operation_id=str(uuid.uuid4()),
            connector="codex",
            request_digest="5" * 64,
            fence="6" * 64,
            direction="agent_to_service",
            sequence=1,
            capability="subscription.status",
        )


def test_status_only_slice_rejects_payloads_and_zero_keys() -> None:
    context = {
        "installation_id": "2" * 64,
        "root_epoch": 7,
        "service_boot_id": "3" * 64,
        "principal_hash": "4" * 64,
        "session_id": 8,
        "agent_generation": 2,
    }
    with pytest.raises(UserSessionAgentProtocolError, match="root key"):
        derive_user_principal_key(
            root_key="sk-service-pipe-" + "0" * 64,
            installation_id=context["installation_id"],
            root_epoch=context["root_epoch"],
            principal_hash=context["principal_hash"],
        )
    with pytest.raises(UserSessionAgentProtocolError, match="session key"):
        encode_user_session_frame(
            session_key=b"\0" * 32,
            direction="agent_to_service",
            sequence=1,
            operation_id=str(uuid.uuid4()),
            connector="codex",
            capability="subscription.status",
            payload={"prompt": "must-not-cross-this-status-protocol"},
            fence="5" * 64,
            **context,
        )
    principal_key = derive_user_principal_key(
        root_key="sk-service-pipe-" + "1" * 64,
        installation_id=context["installation_id"],
        root_epoch=context["root_epoch"],
        principal_hash=context["principal_hash"],
    )
    session_key = derive_user_session_key(principal_key=principal_key, **context)
    with pytest.raises(UserSessionAgentProtocolError, match="capability"):
        encode_user_session_frame(
            session_key=session_key,
            direction="agent_to_service",
            sequence=1,
            operation_id=str(uuid.uuid4()),
            connector="codex",
            capability="subscription.status",
            payload={"prompt": "must-not-cross-this-status-protocol"},
            fence="5" * 64,
            **context,
        )
