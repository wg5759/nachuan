from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
from dataclasses import replace
from typing import Any

import pytest

import gateway.installation_root_api as installation_root_api
from gateway.installation_root import (
    ComponentState,
    InstallationRoot,
    InstallationRootDependencies,
    InstallationRootLocked,
    InstallationRootSnapshot,
    InstallationRootUnavailable,
    RootMutationResult,
    UpdaterState,
)
from gateway.installation_root_api import (
    DESKTOP_ADVANCE_PATH,
    DESKTOP_BIND_PATH,
    DESKTOP_RECOVERY_ACK_PATH,
    DESKTOP_VERIFY_PATH,
    ERROR_SCHEMA,
    JSON_BYTE_LIMIT,
    MAX_JS_SAFE_INTEGER,
    MUTATION_SCHEMA,
    SNAPSHOT_PATH,
    SNAPSHOT_SCHEMA,
    UPDATER_ADVANCE_PATH,
    UPDATER_VERIFY_PATH,
    InstallationRootAPIConfigurationError,
    create_installation_root_dispatcher,
)
from gateway.installation_root_protocol import (
    HEADER_RESPONSE_REQUEST_NONCE,
    HEADER_SIGNATURE,
    RESPONSE_HEADER_NAMES,
    sign_request,
    verify_response,
)


BOOT_TOKEN = "0123456789abcdef" * 4
NOW_MS = 1_720_000_000_123
ZERO = "0" * 64
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def snapshot() -> InstallationRootSnapshot:
    return InstallationRootSnapshot(
        installation_id=DIGEST_A,
        owner_sid_digest=DIGEST_B,
        epoch=3,
        root_revision=11,
        status="active",
        lock_kind="none",
        lock_reason_digest=None,
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=DIGEST_C,
        components=(
            ComponentState(
                component="desktop",
                identity=DIGEST_D,
                epoch=3,
                bound=True,
                sequence_floor=7,
                state_digest=DIGEST_E,
                recovery_floor=None,
                recovery_state_digest=None,
            ),
            ComponentState(
                component="gateway",
                identity=DIGEST_F,
                epoch=3,
                bound=True,
                sequence_floor=9,
                state_digest=DIGEST_A,
                recovery_floor=9,
                recovery_state_digest=DIGEST_A,
            ),
        ),
        updater=UpdaterState(
            release_sequence=5,
            keyring_sequence=4,
            artifact_digest=DIGEST_B,
            state_digest=DIGEST_C,
        ),
    )


class FakeRoot:
    def __init__(self) -> None:
        self.value = snapshot()
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any], int]] = []

    def _mutation(self, name: str, args: tuple[Any, ...], kwargs: dict[str, Any]):
        self.calls.append((name, args, kwargs, threading.get_ident()))
        return RootMutationResult(
            self.value,
            applied=True,
            recovered=name in {"verify_component", "verify_updater"},
        )

    def snapshot(self):
        self.calls.append(("snapshot", (), {}, threading.get_ident()))
        return self.value

    def bind_component(self, *args, **kwargs):
        return self._mutation("bind_component", args, kwargs)

    def verify_component(self, *args, **kwargs):
        return self._mutation("verify_component", args, kwargs)

    def advance_component(self, *args, **kwargs):
        return self._mutation("advance_component", args, kwargs)

    def acknowledge_component_recovery(self, *args, **kwargs):
        return self._mutation("acknowledge_component_recovery", args, kwargs)

    def verify_updater(self, *args, **kwargs):
        return self._mutation("verify_updater", args, kwargs)

    def advance_updater(self, *args, **kwargs):
        return self._mutation("advance_updater", args, kwargs)


def compact(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def valid_body(path: str) -> dict[str, Any]:
    common = {"installationId": DIGEST_A, "epoch": 3, "identity": DIGEST_D}
    if path == DESKTOP_BIND_PATH:
        return {
            **common,
            "stateDigest": DIGEST_E,
            "expectedRootRevision": 11,
            "sequenceFloor": 7,
        }
    if path == DESKTOP_VERIFY_PATH:
        return {
            **common,
            "sequenceFloor": 8,
            "stateDigest": DIGEST_F,
            "previousStateDigest": DIGEST_E,
        }
    if path == DESKTOP_ADVANCE_PATH:
        return {
            **common,
            "expectedFloor": 7,
            "expectedStateDigest": DIGEST_E,
            "nextFloor": 8,
            "nextStateDigest": DIGEST_F,
            "expectedRootRevision": 11,
        }
    if path == DESKTOP_RECOVERY_ACK_PATH:
        return {
            **common,
            "recoveryFloor": 7,
            "recoveryStateDigest": DIGEST_E,
            "nextFloor": 8,
            "nextStateDigest": DIGEST_F,
            "expectedRootRevision": 11,
        }
    if path == UPDATER_VERIFY_PATH:
        return {
            "installationId": DIGEST_A,
            "epoch": 3,
            "releaseSequence": 6,
            "keyringSequence": 5,
            "artifactDigest": DIGEST_D,
            "stateDigest": DIGEST_E,
            "previous": {
                "releaseSequence": 5,
                "keyringSequence": 4,
                "artifactDigest": DIGEST_B,
                "stateDigest": DIGEST_C,
            },
        }
    if path == UPDATER_ADVANCE_PATH:
        return {
            "installationId": DIGEST_A,
            "epoch": 3,
            "expectedReleaseSequence": 5,
            "expectedKeyringSequence": 4,
            "expectedArtifactDigest": DIGEST_B,
            "expectedStateDigest": DIGEST_C,
            "nextReleaseSequence": 6,
            "nextKeyringSequence": 5,
            "nextArtifactDigest": DIGEST_D,
            "nextStateDigest": DIGEST_E,
            "expectedRootRevision": 11,
        }
    raise AssertionError(path)


def signed_headers(
    *,
    method: str,
    path: str,
    body: bytes,
    nonce: str = "1" * 64,
    timestamp_ms: int = NOW_MS,
) -> list[tuple[bytes, bytes]]:
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        method=method,
        path=path,
        body=body,
        timestamp_ms=timestamp_ms,
        nonce=nonce,
    )
    headers: list[tuple[bytes, bytes]] = [
        (b"host", b"127.0.0.1"),
        (b"cache-control", b"no-store"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if method == "POST":
        headers.append((b"content-type", b"application/json"))
    headers.extend(
        (name.lower().encode("ascii"), value.encode("ascii"))
        for name, value in signed.headers.items()
    )
    return headers


async def invoke_async(
    api,
    *,
    method: str,
    path: str,
    body: bytes,
    headers: list[tuple[bytes, bytes]],
    client: tuple[str, int] = ("127.0.0.1", 49152),
    query: bytes = b"",
    raw_path: bytes | None = None,
    chunks: list[tuple[bytes, bool]] | None = None,
    receive_delay: float = 0.0,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii") if raw_path is None else raw_path,
        "query_string": query,
        "headers": headers,
        "client": client,
        "server": ("127.0.0.1", 8765),
    }
    queue = list(chunks or [(body, False)])
    sent: list[dict[str, Any]] = []

    async def receive():
        if not queue:
            raise AssertionError("dispatcher read beyond the supplied request stream")
        if receive_delay:
            await asyncio.sleep(receive_delay)
        chunk, more = queue.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": more}

    async def send(message):
        sent.append(message)

    await api(scope, receive, send)
    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    assert sent[1].get("more_body") is False
    return sent[0]["status"], sent[0]["headers"], sent[1]["body"]


def invoke(api, **kwargs):
    return asyncio.run(invoke_async(api, **kwargs))


def signed_call(
    api,
    *,
    path: str,
    value: dict[str, Any] | None = None,
    nonce: str = "1" * 64,
):
    method = "GET" if path == SNAPSHOT_PATH else "POST"
    body = b"" if method == "GET" else compact(value if value is not None else valid_body(path))
    headers = signed_headers(method=method, path=path, body=body, nonce=nonce)
    return invoke(api, method=method, path=path, body=body, headers=headers)


def response_headers(headers: list[tuple[bytes, bytes]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for name, value in headers:
        result.setdefault(name.decode("ascii").lower(), []).append(
            value.decode("ascii")
        )
    return result


def assert_response_contract(
    result,
    *,
    status: int,
    nonce: str | None,
) -> dict[str, Any]:
    actual_status, headers, body = result
    assert actual_status == status
    raw = response_headers(headers)
    assert raw["content-type"] == ["application/json"]
    assert raw["cache-control"] == ["no-store"]
    assert raw["content-length"] == [str(len(body))]
    assert len(body) <= JSON_BYTE_LIMIT
    if nonce is None:
        assert not any(name.lower() in raw for name in RESPONSE_HEADER_NAMES)
    else:
        assert verify_response(
            boot_token=BOOT_TOKEN,
            request_nonce=nonce,
            status=status,
            headers=headers,
            body=body,
        ).request_nonce == nonce
        assert raw[HEADER_RESPONSE_REQUEST_NONCE.lower()] == [nonce]
    return json.loads(body)


def make_api(root=None):
    return create_installation_root_dispatcher(
        root=FakeRoot() if root is None else root,
        boot_token=BOOT_TOKEN,
        now_ms=lambda: NOW_MS,
    )


def test_snapshot_route_has_exact_closed_signed_shape_and_runs_off_loop_thread() -> None:
    root = FakeRoot()
    api = make_api(root)
    caller_thread = threading.get_ident()
    payload = assert_response_contract(
        signed_call(api, path=SNAPSHOT_PATH), status=200, nonce="1" * 64
    )
    assert set(payload) == {"schema", "snapshot"}
    assert payload["schema"] == SNAPSHOT_SCHEMA
    value = payload["snapshot"]
    assert set(value) == {
        "installationId",
        "ownerSidDigest",
        "epoch",
        "rootRevision",
        "status",
        "lockKind",
        "lockReasonDigest",
        "reanchorPending",
        "reanchorOperationDigest",
        "reanchorSnapshotDigest",
        "reanchorSourceEpoch",
        "principalDigest",
        "components",
        "updater",
    }
    assert set(value["components"]) == {"desktop", "gateway"}
    assert set(value["components"]["desktop"]) == {
        "identity",
        "epoch",
        "bound",
        "sequenceFloor",
        "stateDigest",
        "recoveryFloor",
        "recoveryStateDigest",
    }
    assert set(value["updater"]) == {
        "releaseSequence",
        "keyringSequence",
        "artifactDigest",
        "stateDigest",
    }
    assert root.calls[0][3] != caller_thread


def test_real_v5_hidden_private_components_pending_is_valid_closed_wire_v1(
    tmp_path: Path,
) -> None:
    identities = iter(index.to_bytes(32, "big") for index in range(1, 6))

    def random_bytes(length: int) -> bytes:
        assert length == 32
        return next(identities)

    dependencies = InstallationRootDependencies(
        owner_sid=lambda: "S-1-5-21-1000-2000-3000-4000",
        random_bytes=random_bytes,
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent,
    )
    root = InstallationRoot.provision(
        tmp_path / "installation-root-v5.db", dependencies=dependencies
    )
    current = root.snapshot()
    for component, state_digest in (
        ("desktop", DIGEST_D),
        ("gateway", DIGEST_E),
    ):
        state = current.component(component)
        current = root.bind_component(
            component,
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=state.identity,
            state_digest=state_digest,
            expected_root_revision=current.root_revision,
        ).snapshot

    assert current.status == "provisioning"
    assert current.component("desktop").bound is True
    assert current.component("gateway").bound is True
    assert current.component("gateway_assets").bound is False
    assert current.component("channel_media").bound is False

    payload = assert_response_contract(
        signed_call(make_api(root), path=SNAPSHOT_PATH),
        status=200,
        nonce="1" * 64,
    )
    assert payload["schema"] == SNAPSHOT_SCHEMA
    assert payload["snapshot"]["status"] == "provisioning"
    assert tuple(payload["snapshot"]["components"]) == ("desktop", "gateway")
    assert all(
        component["bound"]
        for component in payload["snapshot"]["components"].values()
    )


@pytest.mark.parametrize(
    ("path", "method_name", "expected_keys", "recovered"),
    [
        (
            DESKTOP_BIND_PATH,
            "bind_component",
            {
                "installation_id",
                "epoch",
                "identity",
                "state_digest",
                "expected_root_revision",
                "sequence_floor",
            },
            False,
        ),
        (
            DESKTOP_VERIFY_PATH,
            "verify_component",
            {
                "installation_id",
                "epoch",
                "identity",
                "sequence_floor",
                "state_digest",
                "previous_state_digest",
            },
            True,
        ),
        (
            DESKTOP_ADVANCE_PATH,
            "advance_component",
            {
                "installation_id",
                "epoch",
                "identity",
                "expected_floor",
                "expected_state_digest",
                "next_floor",
                "next_state_digest",
                "expected_root_revision",
            },
            False,
        ),
        (
            DESKTOP_RECOVERY_ACK_PATH,
            "acknowledge_component_recovery",
            {
                "installation_id",
                "epoch",
                "identity",
                "recovery_floor",
                "recovery_state_digest",
                "next_floor",
                "next_state_digest",
                "expected_root_revision",
            },
            False,
        ),
        (
            UPDATER_VERIFY_PATH,
            "verify_updater",
            {
                "installation_id",
                "epoch",
                "release_sequence",
                "keyring_sequence",
                "artifact_digest",
                "updater_state_digest",
                "previous_release_sequence",
                "previous_keyring_sequence",
                "previous_artifact_digest",
                "previous_updater_state_digest",
            },
            True,
        ),
        (
            UPDATER_ADVANCE_PATH,
            "advance_updater",
            {
                "installation_id",
                "epoch",
                "expected_release_sequence",
                "expected_keyring_sequence",
                "expected_artifact_digest",
                "expected_updater_state_digest",
                "next_release_sequence",
                "next_keyring_sequence",
                "next_artifact_digest",
                "next_updater_state_digest",
                "expected_root_revision",
            },
            False,
        ),
    ],
)
def test_every_mutation_route_maps_exact_wire_fields(
    path: str, method_name: str, expected_keys: set[str], recovered: bool
) -> None:
    root = FakeRoot()
    api = make_api(root)
    nonce = str(len(path) % 10) * 64
    payload = assert_response_contract(
        signed_call(api, path=path, nonce=nonce), status=200, nonce=nonce
    )
    assert set(payload) == {"schema", "snapshot", "applied", "recovered"}
    assert payload["schema"] == MUTATION_SCHEMA
    assert payload["applied"] is True
    assert payload["recovered"] is recovered
    name, args, kwargs, _thread = root.calls[-1]
    assert name == method_name
    assert set(kwargs) == expected_keys
    if path.startswith("/internal/v1/installation-root/components/"):
        assert args == ("desktop",)
    else:
        assert args == ()


def test_updater_verify_null_previous_omits_all_previous_root_arguments() -> None:
    root = FakeRoot()
    api = make_api(root)
    value = valid_body(UPDATER_VERIFY_PATH)
    value["previous"] = None
    assert_response_contract(
        signed_call(api, path=UPDATER_VERIFY_PATH, value=value),
        status=200,
        nonce="1" * 64,
    )
    kwargs = root.calls[-1][2]
    assert not any(name.startswith("previous_") for name in kwargs)


def test_frozen_python_hmac_vector_is_accepted_byte_for_byte() -> None:
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        method="GET",
        path=SNAPSHOT_PATH,
        body=b"",
        timestamp_ms=NOW_MS,
        nonce="11" * 32,
    )
    assert signed.body_sha256 == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    # This literal is generated by the frozen Python framing implementation;
    # the Desktop TypeScript implementation must match it exactly.
    assert signed.headers[HEADER_SIGNATURE] == (
        "fca77875a5d1e383bc5aabfc34fdf68f7689730047b681a682a24ca2b39060ba"
    )
    api = make_api()
    headers = [
        (b"host", b"127.0.0.1"),
        (b"cache-control", b"no-store"),
        (b"content-length", b"0"),
        *[
            (name.encode("ascii"), value.encode("ascii"))
            for name, value in signed.headers.items()
        ],
    ]
    assert_response_contract(
        invoke(
            api,
            method="GET",
            path=SNAPSHOT_PATH,
            body=b"",
            headers=headers,
        ),
        status=200,
        nonce="11" * 32,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra=True),
        lambda value: value.pop("identity"),
        lambda value: value.update(epoch=True),
        lambda value: value.update(epoch=0),
        lambda value: value.update(epoch=MAX_JS_SAFE_INTEGER + 1),
        lambda value: value.update(identity=DIGEST_A.upper()),
        lambda value: value.update(identity=ZERO),
        lambda value: value.update(sequenceFloor=1.0),
    ],
)
def test_request_dto_rejects_extra_missing_wrong_type_and_unsafe_values(mutation) -> None:
    value = valid_body(DESKTOP_BIND_PATH)
    mutation(value)
    payload = assert_response_contract(
        signed_call(make_api(), path=DESKTOP_BIND_PATH, value=value),
        status=400,
        nonce="1" * 64,
    )
    assert payload == {"schema": ERROR_SCHEMA, "code": "invalid_request"}


@pytest.mark.parametrize(
    "body",
    [
        b'{"installationId":"' + DIGEST_A.encode() + b'","installationId":"' + DIGEST_A.encode() + b'"}',
        b"[]",
        b'{"epoch":NaN}',
        b"\xff",
    ],
)
def test_json_parser_rejects_duplicate_nonobject_nonfinite_and_non_utf8(body: bytes) -> None:
    api = make_api()
    headers = signed_headers(
        method="POST", path=DESKTOP_BIND_PATH, body=body, nonce="2" * 64
    )
    payload = assert_response_contract(
        invoke(
            api,
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=headers,
        ),
        status=400,
        nonce="2" * 64,
    )
    assert payload["code"] == "invalid_request"


def test_nested_updater_proof_and_flat_advance_are_closed_sets() -> None:
    verify = valid_body(UPDATER_VERIFY_PATH)
    verify["previous"]["extra"] = 1
    result = signed_call(make_api(), path=UPDATER_VERIFY_PATH, value=verify)
    assert assert_response_contract(result, status=400, nonce="1" * 64)["code"] == "invalid_request"


@pytest.mark.parametrize(
    ("path", "change"),
    [
        (UPDATER_VERIFY_PATH, {"releaseSequence": 0}),
        (UPDATER_VERIFY_PATH, {"stateDigest": ZERO}),
        (UPDATER_ADVANCE_PATH, {"expectedReleaseSequence": 0}),
        (UPDATER_ADVANCE_PATH, {"nextArtifactDigest": ZERO}),
    ],
)
def test_structurally_inconsistent_updater_proofs_are_rejected_before_root(
    path: str, change: dict[str, Any]
) -> None:
    root = FakeRoot()
    value = valid_body(path)
    value.update(change)
    payload = assert_response_contract(
        signed_call(make_api(root), path=path, value=value),
        status=400,
        nonce="1" * 64,
    )
    assert payload["code"] == "invalid_request"
    assert root.calls == []

    advance = valid_body(UPDATER_ADVANCE_PATH)
    advance["expected"] = {
        "releaseSequence": 5,
        "keyringSequence": 4,
        "artifactDigest": DIGEST_B,
        "stateDigest": DIGEST_C,
    }
    result = signed_call(make_api(), path=UPDATER_ADVANCE_PATH, value=advance)
    assert assert_response_contract(result, status=400, nonce="1" * 64)["code"] == "invalid_request"


@pytest.mark.parametrize(
    ("path", "change"),
    [
        (DESKTOP_ADVANCE_PATH, {"nextFloor": 9}),
        (DESKTOP_ADVANCE_PATH, {"nextStateDigest": DIGEST_E}),
        (DESKTOP_RECOVERY_ACK_PATH, {"nextFloor": 9}),
        (DESKTOP_RECOVERY_ACK_PATH, {"nextStateDigest": DIGEST_E}),
        (UPDATER_ADVANCE_PATH, {"nextReleaseSequence": 5, "nextKeyringSequence": 4}),
        (UPDATER_ADVANCE_PATH, {"nextStateDigest": ZERO}),
    ],
)
def test_invalid_transitions_are_client_errors_before_root(path: str, change: dict[str, Any]) -> None:
    root = FakeRoot()
    value = valid_body(path)
    value.update(change)
    payload = assert_response_contract(
        signed_call(make_api(root), path=path, value=value),
        status=400,
        nonce="1" * 64,
    )
    assert payload["code"] == "invalid_request"
    assert root.calls == []


@pytest.mark.parametrize(
    ("scope_change", "method", "path"),
    [
        ({"client": ("192.0.2.20", 5000)}, "GET", SNAPSHOT_PATH),
        ({"query": b"x=1"}, "GET", SNAPSHOT_PATH),
        ({"raw_path": b"/internal/v1/installation-root/%73napshot"}, "GET", SNAPSHOT_PATH),
        ({}, "POST", SNAPSHOT_PATH),
        ({}, "GET", "/internal/v1/installation-root/unknown"),
    ],
)
def test_peer_query_raw_path_method_and_path_fail_before_auth(
    scope_change: dict[str, Any], method: str, path: str
) -> None:
    body = b""
    # Sign the nominal route where possible; transport policy must still win.
    signed_path = SNAPSHOT_PATH if path.endswith("unknown") else path
    headers = signed_headers(method=method, path=signed_path, body=body)
    kwargs = {
        "api": make_api(),
        "method": method,
        "path": path,
        "body": body,
        "headers": headers,
        **scope_change,
    }
    payload = assert_response_contract(
        invoke(**kwargs), status=400, nonce=None
    )
    assert payload == {"schema": ERROR_SCHEMA, "code": "invalid_request"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda headers: headers.__setitem__(
            next(i for i, pair in enumerate(headers) if pair[0] == b"content-type"),
            (b"content-type", b"application/json; charset=utf-8"),
        ),
        lambda headers: headers.append((b"content-type", b"application/json")),
        lambda headers: headers.__setitem__(
            next(i for i, pair in enumerate(headers) if pair[0] == b"cache-control"),
            (b"cache-control", b"no-cache"),
        ),
        lambda headers: headers.append((b"cache-control", b"no-store")),
        lambda headers: headers.append((b"content-length", b"1")),
        lambda headers: headers.__setitem__(
            next(i for i, pair in enumerate(headers) if pair[0] == b"content-length"),
            (b"content-length", b"9" * 10_000),
        ),
        lambda headers: headers.append((b"transfer-encoding", b"chunked")),
        lambda headers: headers.append((b"content-encoding", b"identity")),
        lambda headers: headers.append((b"authorization", b"Bearer ignored")),
    ],
)
def test_post_transport_headers_are_exact_and_unambiguous(mutate) -> None:
    body = compact(valid_body(DESKTOP_BIND_PATH))
    headers = signed_headers(method="POST", path=DESKTOP_BIND_PATH, body=body)
    mutate(headers)
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=headers,
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"


def test_get_requires_no_store_accepts_absent_length_and_rejects_any_body() -> None:
    headers = signed_headers(method="GET", path=SNAPSHOT_PATH, body=b"")
    headers = [pair for pair in headers if pair[0] != b"content-length"]
    assert_response_contract(
        invoke(
            make_api(), method="GET", path=SNAPSHOT_PATH, body=b"", headers=headers
        ),
        status=200,
        nonce="1" * 64,
    )

    missing_cache = [pair for pair in headers if pair[0] != b"cache-control"]
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="GET",
            path=SNAPSHOT_PATH,
            body=b"",
            headers=missing_cache,
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"

    headers = signed_headers(method="GET", path=SNAPSHOT_PATH, body=b"x", nonce="2" * 64)
    payload = assert_response_contract(
        invoke(
            make_api(), method="GET", path=SNAPSHOT_PATH, body=b"x", headers=headers
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"


def test_content_length_mismatch_and_streaming_overflow_stop_without_root_call() -> None:
    root = FakeRoot()
    body = compact(valid_body(DESKTOP_BIND_PATH))
    headers = signed_headers(method="POST", path=DESKTOP_BIND_PATH, body=body)
    index = next(i for i, pair in enumerate(headers) if pair[0] == b"content-length")
    headers[index] = (b"content-length", str(len(body) - 1).encode("ascii"))
    assert_response_contract(
        invoke(
            make_api(root),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=headers,
        ),
        status=400,
        nonce=None,
    )
    assert root.calls == []

    oversized = b" " * (JSON_BYTE_LIMIT + 1)
    headers = signed_headers(
        method="POST", path=DESKTOP_BIND_PATH, body=oversized
    )
    # Declare the maximum but stream one extra byte.  The second message is the
    # exact point at which the adapter must stop reading.
    index = next(i for i, pair in enumerate(headers) if pair[0] == b"content-length")
    headers[index] = (b"content-length", str(JSON_BYTE_LIMIT).encode("ascii"))
    assert_response_contract(
        invoke(
            make_api(root),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=oversized,
            headers=headers,
            chunks=[
                (oversized[:JSON_BYTE_LIMIT], True),
                (oversized[JSON_BYTE_LIMIT:], False),
            ],
        ),
        status=400,
        nonce=None,
    )
    assert root.calls == []


def test_empty_frame_flood_and_total_body_timeout_are_rejected_before_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = FakeRoot()
    headers = signed_headers(method="GET", path=SNAPSHOT_PATH, body=b"")
    payload = assert_response_contract(
        invoke(
            make_api(root),
            method="GET",
            path=SNAPSHOT_PATH,
            body=b"",
            headers=headers,
            chunks=[(b"", True)] * 257 + [(b"", False)],
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"
    assert root.calls == []

    monkeypatch.setattr(installation_root_api, "_BODY_READ_TIMEOUT_SECONDS", 0.01)
    payload = assert_response_contract(
        invoke(
            make_api(root),
            method="GET",
            path=SNAPSHOT_PATH,
            body=b"",
            headers=headers,
            receive_delay=0.05,
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"
    assert root.calls == []


def test_exact_64k_is_read_then_dto_rejected_but_64k_plus_one_header_is_early_rejected() -> None:
    exact = b" " * JSON_BYTE_LIMIT
    headers = signed_headers(method="POST", path=DESKTOP_BIND_PATH, body=exact)
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=exact,
            headers=headers,
        ),
        status=400,
        nonce="1" * 64,
    )
    assert payload["code"] == "invalid_request"

    too_large = b" " * (JSON_BYTE_LIMIT + 1)
    headers = signed_headers(method="POST", path=DESKTOP_BIND_PATH, body=too_large)
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=too_large,
            headers=headers,
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"


def test_tamper_duplicate_unknown_root_header_and_token_smuggling_never_authenticate() -> None:
    body = compact(valid_body(DESKTOP_BIND_PATH))
    headers = signed_headers(method="POST", path=DESKTOP_BIND_PATH, body=body)
    tampered = list(headers)
    tampered[-1] = (tampered[-1][0], b"0" * 64)
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=tampered,
        ),
        status=401,
        nonce=None,
    )
    assert payload["code"] == "authentication_failed"

    duplicate = list(headers)
    signature = next(value for name, value in headers if name == HEADER_SIGNATURE.lower().encode())
    duplicate.append((HEADER_SIGNATURE.upper().encode(), signature))
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=duplicate,
        ),
        status=401,
        nonce=None,
    )
    assert payload["code"] == "authentication_failed"

    unknown = list(headers) + [(b"x-nachuan-root-authorization", b"not-a-token")]
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=unknown,
        ),
        status=401,
        nonce=None,
    )
    assert payload["code"] == "authentication_failed"

    smuggled_value = valid_body(DESKTOP_BIND_PATH)
    smuggled_value["identity"] = BOOT_TOKEN
    smuggled = compact(smuggled_value)
    smuggled_headers = signed_headers(
        method="POST", path=DESKTOP_BIND_PATH, body=smuggled
    )
    result = invoke(
        make_api(),
        method="POST",
        path=DESKTOP_BIND_PATH,
        body=smuggled,
        headers=smuggled_headers,
    )
    payload = assert_response_contract(result, status=400, nonce="1" * 64)
    assert payload["code"] == "invalid_request"
    assert BOOT_TOKEN.encode() not in result[2]


def test_json_escaped_boot_token_is_recursively_rejected_after_authentication() -> None:
    value = valid_body(DESKTOP_BIND_PATH)
    value["identity"] = BOOT_TOKEN
    direct = compact(value).decode("ascii")
    escaped_token = "".join(f"\\u{ord(char):04x}" for char in BOOT_TOKEN)
    encoded = direct.replace(BOOT_TOKEN, escaped_token).encode("ascii")
    assert BOOT_TOKEN.encode("ascii") not in encoded
    nonce = "9" * 64
    headers = signed_headers(
        method="POST", path=DESKTOP_BIND_PATH, body=encoded, nonce=nonce
    )
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=encoded,
            headers=headers,
        ),
        status=400,
        nonce=nonce,
    )
    assert payload["code"] == "invalid_request"


def test_boot_token_in_non_authorization_header_is_rejected_only_after_hmac() -> None:
    body = compact(valid_body(DESKTOP_BIND_PATH))
    nonce = "8" * 64
    headers = signed_headers(
        method="POST", path=DESKTOP_BIND_PATH, body=body, nonce=nonce
    )
    headers.append((b"x-debug-context", BOOT_TOKEN.encode("ascii")))
    payload = assert_response_contract(
        invoke(
            make_api(),
            method="POST",
            path=DESKTOP_BIND_PATH,
            body=body,
            headers=headers,
        ),
        status=400,
        nonce=nonce,
    )
    assert payload["code"] == "invalid_request"


def test_authenticated_nonce_replay_gets_a_signed_generic_rejection() -> None:
    api = make_api()
    nonce = "3" * 64
    method = "GET"
    body = b""
    headers = signed_headers(
        method=method, path=SNAPSHOT_PATH, body=body, nonce=nonce
    )
    kwargs = dict(
        method=method,
        path=SNAPSHOT_PATH,
        body=body,
        headers=headers,
    )
    assert_response_contract(invoke(api, **kwargs), status=200, nonce=nonce)
    payload = assert_response_contract(
        invoke(api, **kwargs), status=409, nonce=nonce
    )
    assert payload == {"schema": ERROR_SCHEMA, "code": "replay_rejected"}


def test_only_one_concurrent_api_request_consumes_a_nonce() -> None:
    root = FakeRoot()
    api = make_api(root)
    nonce = "4" * 64
    headers = signed_headers(
        method="GET", path=SNAPSHOT_PATH, body=b"", nonce=nonce
    )
    barrier = threading.Barrier(8)

    def attempt(_index: int):
        barrier.wait(timeout=5)
        return invoke(
            api,
            method="GET",
            path=SNAPSHOT_PATH,
            body=b"",
            headers=list(headers),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert [result[0] for result in results].count(200) == 1
    assert [result[0] for result in results].count(409) == 7
    for result in results:
        assert_response_contract(result, status=result[0], nonce=nonce)
    assert [call[0] for call in root.calls].count("snapshot") == 1


class RaisingRoot(FakeRoot):
    def __init__(self, kind: str) -> None:
        super().__init__()
        self.kind = kind

    def _raise(self):
        if self.kind == "locked":
            raise InstallationRootLocked("sensitive locked detail")
        if self.kind == "unavailable":
            try:
                raise OSError("sensitive filesystem detail")
            except OSError as cause:
                raise InstallationRootUnavailable("sensitive root detail") from cause
        if self.kind == "conflict":
            raise InstallationRootUnavailable("sensitive CAS detail")
        raise RuntimeError("sensitive unexpected detail")

    def snapshot(self):
        self._raise()

    def bind_component(self, *args, **kwargs):
        self._raise()


@pytest.mark.parametrize(
    ("kind", "path", "status", "code"),
    [
        ("locked", SNAPSHOT_PATH, 423, "root_locked"),
        ("unavailable", SNAPSHOT_PATH, 503, "root_unavailable"),
        ("conflict", DESKTOP_BIND_PATH, 503, "root_unavailable"),
        ("unexpected", SNAPSHOT_PATH, 500, "internal_error"),
    ],
)
def test_root_exceptions_map_by_type_and_cas_category_without_detail_leak(
    kind: str, path: str, status: int, code: str
) -> None:
    nonce = "5" * 64
    result = signed_call(make_api(RaisingRoot(kind)), path=path, nonce=nonce)
    payload = assert_response_contract(result, status=status, nonce=nonce)
    assert payload == {"schema": ERROR_SCHEMA, "code": code}
    assert b"sensitive" not in result[2]


def test_invalid_root_wire_state_fails_closed_as_signed_root_unavailable() -> None:
    root = FakeRoot()
    root.value = replace(root.value, root_revision=MAX_JS_SAFE_INTEGER + 1)
    nonce = "6" * 64
    payload = assert_response_contract(
        signed_call(make_api(root), path=SNAPSHOT_PATH, nonce=nonce),
        status=503,
        nonce=nonce,
    )
    assert payload["code"] == "root_unavailable"


def test_active_root_wire_requires_both_public_components_bound() -> None:
    root = FakeRoot()
    desktop = replace(
        root.value.component("desktop"),
        bound=False,
        sequence_floor=0,
        state_digest=None,
        recovery_floor=None,
        recovery_state_digest=None,
    )
    root.value = replace(
        root.value,
        components=(desktop, root.value.component("gateway")),
    )
    nonce = "a" * 64
    payload = assert_response_contract(
        signed_call(make_api(root), path=SNAPSHOT_PATH, nonce=nonce),
        status=503,
        nonce=nonce,
    )
    assert payload == {"schema": ERROR_SCHEMA, "code": "root_unavailable"}


def test_boot_token_configuration_is_exact_and_never_appears_in_errors_or_repr() -> None:
    with pytest.raises(InstallationRootAPIConfigurationError) as raised:
        create_installation_root_dispatcher(root=FakeRoot(), boot_token=BOOT_TOKEN.upper())
    assert BOOT_TOKEN.upper() not in str(raised.value)
    with pytest.raises(InstallationRootAPIConfigurationError):
        create_installation_root_dispatcher(root=FakeRoot(), boot_token=BOOT_TOKEN[:-1])
    api = make_api()
    assert BOOT_TOKEN not in repr(api)


@pytest.mark.parametrize("name", [b"x:smuggled", b"x\x00smuggled", b"x smuggled"])
def test_raw_header_names_must_be_exact_rfc_tokens(name: bytes) -> None:
    headers = signed_headers(method="GET", path=SNAPSHOT_PATH, body=b"")
    headers.append((name, b"value"))
    payload = assert_response_contract(
        invoke(
            make_api(), method="GET", path=SNAPSHOT_PATH, body=b"", headers=headers
        ),
        status=400,
        nonce=None,
    )
    assert payload["code"] == "invalid_request"


def test_route_map_is_immutable_closed_set() -> None:
    with pytest.raises(TypeError):
        installation_root_api.INSTALLATION_ROOT_ROUTES["/injected"] = "GET"  # type: ignore[index]


@pytest.mark.asyncio
async def test_send_failure_after_response_start_never_emits_a_second_status_line() -> None:
    api = make_api()
    body = b""
    headers = signed_headers(method="GET", path=SNAPSHOT_PATH, body=body)
    scope = {
        "type": "http",
        "method": "GET",
        "raw_path": SNAPSHOT_PATH.encode("ascii"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 49152),
    }
    sent: list[str] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def fail_after_start(message):
        sent.append(message["type"])
        if message["type"] == "http.response.body":
            raise OSError("simulated disconnected client")

    with pytest.raises(OSError, match="disconnected"):
        await api(scope, receive, fail_after_start)
    assert sent == ["http.response.start", "http.response.body"]


def test_ipv4_and_ipv6_loopback_are_accepted() -> None:
    for index, peer in enumerate(("127.0.0.1", "::1"), start=7):
        nonce = str(index) * 64
        body = b""
        headers = signed_headers(
            method="GET", path=SNAPSHOT_PATH, body=body, nonce=nonce
        )
        assert_response_contract(
            invoke(
                make_api(),
                method="GET",
                path=SNAPSHOT_PATH,
                body=body,
                headers=headers,
                client=(peer, 49152),
            ),
            status=200,
            nonce=nonce,
        )
