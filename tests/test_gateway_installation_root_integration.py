from __future__ import annotations

import asyncio
from hashlib import sha256
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException

import gateway.app as appmod
import gateway.installation_bootstrap as installation_bootstrap
import gateway.installation_root_gateway as root_gateway
from gateway.asset_installation_control import AssetInstallationControl
from gateway.channel_media_protocol import ChannelMediaFrame
from gateway.gateway_installation_control import (
    GatewayInstallationControlUnavailable,
)
from gateway.installation_root_api import ERROR_SCHEMA, SNAPSHOT_PATH
from gateway.installation_root_protocol import HEADER_SIGNATURE, sign_request
from gateway.installation_root import (
    InstallationRoot,
    InstallationRootDependencies,
    InstallationRootUnavailable,
)
from gateway.paid_media_asset_store import PaidMediaAssetStoreDependencies


BOOT_TOKEN = "0123456789abcdef" * 4


async def _invoke(
    asgi_app: Any,
    *,
    raw_path: bytes,
    path: str = SNAPSHOT_PATH,
    query: bytes = b"",
    duplicate_signature: bool = False,
) -> tuple[int, dict[str, str], bytes]:
    signed = sign_request(
        boot_token=BOOT_TOKEN,
        method="GET",
        path=SNAPSHOT_PATH,
        body=b"",
        nonce="1" * 64,
    )
    headers = [
        (b"host", b"127.0.0.1"),
        (b"cache-control", b"no-store"),
        (b"content-length", b"0"),
        *[
            (name.lower().encode("ascii"), value.encode("ascii"))
            for name, value in signed.headers.items()
        ],
    ]
    if duplicate_signature:
        headers.append(
            (
                HEADER_SIGNATURE.lower().encode("ascii"),
                signed.headers[HEADER_SIGNATURE].encode("ascii"),
            )
        )
    sent: list[dict[str, Any]] = []
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await asgi_app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": raw_path,
            "query_string": query,
            "headers": headers,
            "client": ("127.0.0.1", 51234),
            "server": ("127.0.0.1", 8765),
        },
        receive,
        send,
    )
    assert [message["type"] for message in sent] == [
        "http.response.start",
        "http.response.body",
    ]
    response_headers = {
        name.decode("ascii").lower(): value.decode("ascii")
        for name, value in sent[0]["headers"]
    }
    return sent[0]["status"], response_headers, sent[1]["body"]


def test_outer_raw_dispatcher_keeps_internal_routes_outside_fastapi(
    monkeypatch,
) -> None:
    monkeypatch.setenv("NACHUAN_ENGINE_BOOT_TOKEN", BOOT_TOKEN)
    downstream_calls: list[bytes] = []

    async def downstream(scope, _receive, send) -> None:  # noqa: ANN001
        downstream_calls.append(scope["raw_path"])
        await send(
            {
                "type": "http.response.start",
                "status": 418,
                "headers": [(b"content-length", b"0")],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    wrapped = root_gateway.InstallationRootGatewayApp(downstream)

    query_status, query_headers, query_body = asyncio.run(
        _invoke(
            wrapped,
            raw_path=SNAPSHOT_PATH.encode("ascii"),
            query=b"x=1",
        )
    )
    duplicate_status, _, duplicate_body = asyncio.run(
        _invoke(
            wrapped,
            raw_path=SNAPSHOT_PATH.encode("ascii"),
            duplicate_signature=True,
        )
    )
    aliases = [
        (b"/internal/v1/installation-root/%73napshot", SNAPSHOT_PATH),
        (b"/internal/v1/installation-root%2fsnapshot", SNAPSHOT_PATH),
        (b"/internal/v1/installation%2droot/snapshot", SNAPSHOT_PATH),
        (
            b"/internal/v1/installation-root//snapshot",
            "/internal/v1/installation-root//snapshot",
        ),
        (
            b"/internal/v1/installation-root/../installation-root/snapshot",
            "/internal/v1/installation-root/../installation-root/snapshot",
        ),
        (b"/internal/v1/installation-root", "/internal/v1/installation-root"),
    ]
    alias_responses = [
        asyncio.run(_invoke(wrapped, raw_path=raw_path, path=decoded_path))
        for raw_path, decoded_path in aliases
    ]
    lookalike = b"/internal/v1/installation-root-evil/snapshot"
    lookalike_status, _, _ = asyncio.run(
        _invoke(wrapped, raw_path=lookalike, path=lookalike.decode("ascii"))
    )

    assert query_status == 400
    assert query_headers["cache-control"] == "no-store"
    assert query_body == (
        b'{"schema":"' + ERROR_SCHEMA.encode("ascii") + b'","code":"invalid_request"}'
    )
    assert duplicate_status == 401
    assert b"authentication_failed" in duplicate_body
    assert all(response[0] == 400 for response in alias_responses)
    assert all(response[1]["cache-control"] == "no-store" for response in alias_responses)
    assert all(response[2] == query_body for response in alias_responses)
    assert lookalike_status == 418
    assert downstream_calls == [lookalike]


def test_outer_dispatcher_captures_only_a_valid_boot_environment_token(
    monkeypatch,
) -> None:
    monkeypatch.delenv("NACHUAN_ENGINE_BOOT_TOKEN", raising=False)
    downstream_calls: list[bytes] = []

    async def downstream(scope, _receive, _send) -> None:  # noqa: ANN001
        downstream_calls.append(scope["raw_path"])

    wrapped = root_gateway.InstallationRootGatewayApp(downstream)
    # Changing the process environment after construction cannot grant this
    # already-running boot a private protocol capability.
    monkeypatch.setenv("NACHUAN_ENGINE_BOOT_TOKEN", BOOT_TOKEN)

    status, headers, body = asyncio.run(
        _invoke(wrapped, raw_path=SNAPSHOT_PATH.encode("ascii"))
    )

    assert status == 503
    assert headers["cache-control"] == "no-store"
    assert body == (
        b'{"schema":"' + ERROR_SCHEMA.encode("ascii") + b'","code":"root_unavailable"}'
    )
    assert downstream_calls == []


def test_private_root_provider_strictly_reopens_the_fixed_path_per_request(
    monkeypatch,
) -> None:
    monkeypatch.setenv("NACHUAN_ENGINE_BOOT_TOKEN", BOOT_TOKEN)
    expected = Path("C:/ProgramData/Nachuan/StateRoot/installation-root.db")
    opens: list[Path] = []
    providers: list[Any] = []

    monkeypatch.setattr(root_gateway, "default_installation_root_path", lambda: expected)

    class FakeInstallationRoot:
        @classmethod
        def open(cls, path):  # noqa: ANN001, ANN206
            opens.append(Path(path))
            return object()

    class ProbeDispatcher:
        def __init__(self, provider) -> None:  # noqa: ANN001
            self.provider = provider

        async def __call__(self, _scope, _receive, send) -> None:  # noqa: ANN001
            self.provider()
            await send(
                {
                    "type": "http.response.start",
                    "status": 204,
                    "headers": [(b"content-length", b"0")],
                }
            )
            await send({"type": "http.response.body", "body": b""})

    def dispatcher_factory(*, root, boot_token):  # noqa: ANN001, ANN202
        assert boot_token == BOOT_TOKEN
        providers.append(root)
        return ProbeDispatcher(root)

    monkeypatch.setattr(root_gateway, "InstallationRoot", FakeInstallationRoot)
    monkeypatch.setattr(
        root_gateway, "create_installation_root_dispatcher", dispatcher_factory
    )

    wrapped = root_gateway.InstallationRootGatewayApp(FastAPI())
    first = asyncio.run(
        _invoke(wrapped, raw_path=SNAPSHOT_PATH.encode("ascii"))
    )
    second = asyncio.run(
        _invoke(wrapped, raw_path=SNAPSHOT_PATH.encode("ascii"))
    )

    assert first[0] == second[0] == 204
    assert len(providers) == 1
    assert opens == [expected, expected]


def test_packaged_paid_authority_failure_isolated_with_stable_reason(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    root = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(principal_digest="a" * 64)
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)

    def unavailable(*_args):  # noqa: ANN002, ANN202
        raise GatewayInstallationControlUnavailable("SECRET local path")

    monkeypatch.setattr(appmod.GatewayInstallationControl, "open_bound", unavailable)
    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state == {
        "mode": "disabled",
        "reason_code": "installation-control-unavailable",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": True,
    }
    assert target.state.media_requests is None
    assert target.state.paid_media_principal is None
    assert "SECRET" not in repr(state)


def test_packaged_runtime_uses_only_fixed_root_and_strict_open_bound(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    expected_root_path = Path(
        "C:/ProgramData/Nachuan/StateRoot/installation-root.db"
    )
    expected_ledger_path = Path(
        "C:/ProgramData/Nachuan/StateRoot/gateway-paid-media-requests.db"
    )
    expected_asset_path = Path(
        "C:/ProgramData/Nachuan/StateRoot/paid-media-assets"
    )
    installation_id = "1" * 64
    epoch = 7
    root = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(
            installation_id=installation_id,
            epoch=epoch,
            principal_digest="2" * 64,
            status="active",
        )
    )
    store = object()
    asset_store = object()
    control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            outbound_ready=True,
            installation_id=installation_id,
            epoch=epoch,
            paid_principal=appmod.stable_paid_principal("2" * 64),
        ),
        store=store,
    )
    opens: list[Path] = []
    binds: list[tuple[Any, Path]] = []
    asset_binds: list[tuple[Any, Path]] = []
    asset_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            installation_id=installation_id,
            epoch=epoch,
        ),
        store=asset_store,
    )
    monkeypatch.setattr(
        appmod, "default_installation_root_path", lambda: expected_root_path
    )
    monkeypatch.setattr(
        appmod, "default_gateway_ledger_path", lambda: expected_ledger_path
    )
    monkeypatch.setattr(
        appmod, "default_paid_media_asset_store_path", lambda: expected_asset_path
    )
    monkeypatch.setattr(
        appmod.InstallationRoot,
        "open",
        lambda path: (opens.append(Path(path)), root)[1],
    )
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(
            lambda _cls, root_value, path: (
                binds.append((root_value, Path(path))),
                control,
            )[1]
        ),
    )
    monkeypatch.setattr(
        appmod,
        "DurableMediaRequestStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("packaged runtime must not construct a dev store")
        ),
    )
    monkeypatch.setattr(
        appmod,
        "AssetInstallationControl",
        SimpleNamespace(
            open_bound=lambda root_value, path: (
                asset_binds.append((root_value, Path(path))),
                asset_control,
            )[1]
        ),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.PaidMediaAssetStore,
        "open_bound",
        classmethod(
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("packaged runtime must not open the asset store directly")
            )
        ),
    )

    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state["mode"] == "ready"
    assert state["new_operations_ready"] is True
    assert target.state.media_requests is store
    assert target.state.paid_media_assets is asset_store
    assert target.state.asset_installation_control is asset_control
    assert opens == [expected_root_path]
    assert binds == [(root, expected_ledger_path)]
    assert asset_binds == [(root, expected_asset_path)]


def test_packaged_channel_media_uses_only_fixed_root_and_strict_open_bound(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    expected_root_path = Path(
        "C:/ProgramData/Nachuan/StateRoot/installation-root.db"
    )
    expected_channel_path = Path(
        "C:/ProgramData/Nachuan/StateRoot/channel-media-requests.db"
    )
    installation_id = "6" * 64
    epoch = 12
    root = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(
            installation_id=installation_id,
            epoch=epoch,
            principal_digest="7" * 64,
            status="active",
        )
    )
    store = object()
    controller = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            installation_id=installation_id,
            epoch=epoch,
            provider_dispatch_ready=True,
        ),
        store=store,
    )
    opened: list[Path] = []
    bound: list[tuple[Any, Path]] = []
    target.state.paid_media_installation_id = installation_id
    target.state.paid_media_epoch = epoch
    monkeypatch.setattr(
        appmod, "default_installation_root_path", lambda: expected_root_path
    )
    monkeypatch.setattr(
        appmod, "default_channel_media_ledger_path", lambda: expected_channel_path
    )
    monkeypatch.setattr(
        appmod.InstallationRoot,
        "open",
        lambda path: (opened.append(Path(path)), root)[1],
    )
    monkeypatch.setattr(
        appmod.ChannelMediaInstallationControl,
        "open_bound",
        classmethod(
            lambda _cls, root_value, path: (
                bound.append((root_value, Path(path))),
                controller,
            )[1]
        ),
    )
    monkeypatch.setattr(
        appmod,
        "DurableChannelMediaRequestStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("packaged runtime must not construct a dev channel store")
        ),
    )

    state = appmod._initialize_channel_media_authority(target, tmp_path)

    assert state == {
        "mode": "ready",
        "reason_code": "authority-exact",
        "new_operations_ready": True,
        "replay_available": True,
        "packaged": True,
    }
    assert target.state.channel_media_installation_control is controller
    assert target.state.channel_media_requests is store
    assert opened == [expected_root_path]
    assert bound == [(root, expected_channel_path)]


def test_packaged_channel_waits_for_desktop_activation_then_reconciles_in_process(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    installation_id = "7" * 64
    epoch = 13
    root = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(
            installation_id=installation_id,
            epoch=epoch,
            status="provisioning",
        )
    )
    store = object()

    class Controller:
        def __init__(self) -> None:
            self.state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                installation_id=installation_id,
                epoch=epoch,
                provider_dispatch_ready=False,
            )
            self.reconciles = 0

        @property
        def store(self):  # noqa: ANN201
            if self.state.mode == "provisioned_not_active":
                raise AssertionError("waiting controller store must stay hidden")
            return store

        def reconcile_startup(self):  # noqa: ANN201
            self.reconciles += 1
            if self.reconciles == 1:
                raise appmod.ChannelMediaInstallationControlUnavailable(
                    "simulated transient Root read"
                )
            self.state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                installation_id=installation_id,
                epoch=epoch,
                provider_dispatch_ready=True,
            )
            return self.state

        def close(self) -> None:
            return None

    controller = Controller()
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_installation_id",
        installation_id,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    for name in (
        "channel_media_installation_control",
        "channel_media_requests",
        "channel_media_close_pending",
        "channel_media_authority",
    ):
        monkeypatch.setattr(
            appmod.app.state,
            name,
            getattr(appmod.app.state, name, None),
            raising=False,
        )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.ChannelMediaInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: controller),
    )

    waiting = appmod._initialize_channel_media_authority(appmod.app, tmp_path)

    assert waiting == {
        "mode": "provisioned_not_active",
        "reason_code": "awaiting-installation-activation",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": True,
    }
    assert appmod.app.state.channel_media_installation_control is controller
    assert appmod.app.state.channel_media_requests is None

    asyncio.run(appmod._refresh_waiting_channel_media_authority())

    assert controller.reconciles == 1
    assert appmod.app.state.channel_media_requests is None
    assert appmod.app.state.channel_media_authority == {
        "mode": "provisioned_not_active",
        "reason_code": "activation-reconcile-temporarily-unavailable",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": True,
    }

    asyncio.run(appmod._refresh_waiting_channel_media_authority())

    assert controller.reconciles == 2
    assert appmod.app.state.channel_media_requests is store
    assert appmod.app.state.channel_media_authority == {
        "mode": "ready",
        "reason_code": "authority-exact",
        "new_operations_ready": True,
        "replay_available": True,
        "packaged": True,
    }


def test_real_fresh_bootstrap_channel_claim_converges_after_desktop_bind_without_restart(
    tmp_path,
    monkeypatch,
) -> None:
    class IdentitySource:
        def __init__(self) -> None:
            self.value = 0
            self.lock = threading.Lock()

        def __call__(self, length: int) -> bytes:
            assert length == 32
            with self.lock:
                self.value += 1
                return self.value.to_bytes(32, "big")

    dependencies = InstallationRootDependencies(
        owner_sid=lambda: "S-1-5-21-1000-2000-3000-4000",
        random_bytes=IdentitySource(),
        assert_acl=lambda _path, _directory: None,
        harden_acl=lambda _path, _directory: None,
        trusted_boundary=lambda path: path.parent.parent,
    )
    boundary = tmp_path / "Nachuan"
    state_root = boundary / "StateRoot"
    root_path = state_root / "installation-root.db"
    gateway_path = state_root / "gateway-paid-media-requests.db"
    asset_path = state_root / "paid-media-assets"
    channel_path = state_root / "channel-media-requests.db"

    installed = installation_bootstrap._provision_authority_at_paths(
        root_path=root_path,
        ledger_path=gateway_path,
        asset_store_path=asset_path,
        channel_media_ledger_path=channel_path,
        dependencies=dependencies,
    )
    assert installed.root_status == "provisioning"
    assert installed.desktop_bound is False
    assert installed.gateway_bound is True
    assert installed.asset_store_bound is True
    assert installed.channel_media_bound is True

    real_root = InstallationRoot.open(root_path, dependencies=dependencies)
    before = real_root.snapshot()
    component_identities = {
        name: before.component(name).identity
        for name in ("desktop", "gateway", "gateway_assets", "channel_media")
    }
    authority_files = (
        root_path,
        gateway_path,
        Path(f"{gateway_path}.rollback-anchor"),
        asset_path / "asset-store.db",
        asset_path / "asset-store.db.rollback-anchor",
        channel_path,
        Path(f"{channel_path}.rollback-anchor"),
    )

    def file_identity(path: Path) -> tuple[int, int]:
        info = os.lstat(path)
        return int(info.st_dev), int(info.st_ino)

    original_file_identities = {
        path: file_identity(path) for path in authority_files
    }
    runtime = FastAPI()
    monkeypatch.setattr(appmod, "app", runtime)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(appmod, "default_installation_root_path", lambda: root_path)
    monkeypatch.setattr(appmod, "default_gateway_ledger_path", lambda: gateway_path)
    monkeypatch.setattr(
        appmod,
        "default_paid_media_asset_store_path",
        lambda: asset_path,
    )
    monkeypatch.setattr(
        appmod,
        "default_channel_media_ledger_path",
        lambda: channel_path,
    )

    class RootFacade:
        @staticmethod
        def open(path):  # noqa: ANN001, ANN205
            return InstallationRoot.open(path, dependencies=dependencies)

    asset_dependencies = PaidMediaAssetStoreDependencies(
        assert_acl=dependencies.assert_acl,
        harden_acl=dependencies.harden_acl,
        disk_free=lambda _path: 32 * 1024 * 1024 * 1024,
    )

    class AssetControlFacade:
        @staticmethod
        def open_bound(root, path):  # noqa: ANN001, ANN205
            return AssetInstallationControl.open_bound(
                root,
                path,
                store_dependencies=asset_dependencies,
            )

    monkeypatch.setattr(appmod, "InstallationRoot", RootFacade)
    monkeypatch.setattr(appmod, "AssetInstallationControl", AssetControlFacade)
    provider_calls: list[str] = []

    async def forbidden_provider(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        provider_calls.append("called")
        raise AssertionError("claim/reconcile must not invoke a provider")

    monkeypatch.setattr(appmod, "_await_channel_media_provider", forbidden_provider)

    claim = None
    store = None
    try:
        paid = appmod._initialize_paid_media_authority(runtime, tmp_path)
        channel = appmod._initialize_channel_media_authority(runtime, tmp_path)
        waiting_controller = runtime.state.channel_media_installation_control

        assert paid["mode"] == "provisioned_not_active"
        assert channel == {
            "mode": "provisioned_not_active",
            "reason_code": "awaiting-installation-activation",
            "new_operations_ready": False,
            "replay_available": False,
            "packaged": True,
        }
        assert waiting_controller is not None
        assert waiting_controller.state.mode == "provisioned_not_active"
        assert runtime.state.channel_media_requests is None

        current = real_root.snapshot()
        desktop = current.component("desktop")
        active = real_root.bind_component(
            "desktop",
            installation_id=current.installation_id,
            epoch=current.epoch,
            identity=desktop.identity,
            sequence_floor=0,
            state_digest=sha256(b"real-desktop-authority-state").hexdigest(),
            expected_root_revision=current.root_revision,
        ).snapshot
        assert active.status == "active"

        raw = b"real-bootstrap-channel-claim"
        frame = ChannelMediaFrame(
            channel="feishu",
            user_id="real-bootstrap-user",
            chat_id="real-bootstrap-chat",
            message_key=f"fsmsg-v1:{sha256(b'real-message').hexdigest()}",
            operation="vision.describe",
            pipeline_version="vision.describe/v1",
            params={"question": "describe", "model": ""},
            raw_sha256=sha256(raw).hexdigest(),
            raw_length=len(raw),
            raw=raw,
        )
        store, claim = asyncio.run(
            appmod._claim_bridge_channel_media(frame, max_success_bytes=4096)
        )

        assert claim.state == "claimed"
        assert runtime.state.channel_media_installation_control is waiting_controller
        assert waiting_controller.state.mode == "ready"
        assert runtime.state.channel_media_requests is store
        assert runtime.state.channel_media_authority == {
            "mode": "ready",
            "reason_code": "authority-exact",
            "new_operations_ready": True,
            "replay_available": True,
            "packaged": True,
        }
        assert provider_calls == []
        assert {
            path: file_identity(path) for path in authority_files
        } == original_file_identities
        after = real_root.snapshot()
        assert {
            name: after.component(name).identity
            for name in ("desktop", "gateway", "gateway_assets", "channel_media")
        } == component_identities
    finally:
        if store is not None and claim is not None and claim.state == "claimed":
            store.abandon_pre_provider(
                turn_id=claim.turn_id,
                fencing_token=claim.fencing_token,
            )
        appmod._close_channel_media_authority(runtime)
        appmod._close_paid_media_authority(runtime)


def test_packaged_channel_media_rejects_epoch_mismatch_and_closes_controller(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    installation_id = "8" * 64
    root = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(
            installation_id=installation_id,
            epoch=14,
        )
    )
    closed: list[str] = []
    controller = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            installation_id=installation_id,
            epoch=15,
            provider_dispatch_ready=True,
        ),
        store=object(),
        close=lambda: closed.append("channel"),
    )
    target.state.paid_media_installation_id = installation_id
    target.state.paid_media_epoch = 14
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.ChannelMediaInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: controller),
    )

    state = appmod._initialize_channel_media_authority(target, tmp_path)

    assert state == {
        "mode": "disabled",
        "reason_code": "channel-media-installation-control-unavailable",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": True,
    }
    assert target.state.channel_media_installation_control is None
    assert target.state.channel_media_requests is None
    assert closed == ["channel"]


def test_packaged_channel_media_missing_root_fails_closed_without_dev_fallback(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    target.state.paid_media_installation_id = "9" * 64
    target.state.paid_media_epoch = 16
    monkeypatch.setattr(
        appmod.InstallationRoot,
        "open",
        lambda _path: (_ for _ in ()).throw(
            InstallationRootUnavailable("SECRET missing root")
        ),
    )
    monkeypatch.setattr(
        appmod,
        "DurableChannelMediaRequestStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("packaged runtime must not fall back to a dev store")
        ),
    )

    state = appmod._initialize_channel_media_authority(target, tmp_path)

    assert state == {
        "mode": "disabled",
        "reason_code": "installation-root-unavailable",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": True,
    }
    assert target.state.channel_media_installation_control is None
    assert target.state.channel_media_requests is None
    assert "SECRET" not in repr(state)


def test_packaged_channel_media_requires_fresh_ready_proof_before_provider_phase(
    monkeypatch,
) -> None:
    entered: list[str] = []

    class Store:
        def enter_provider_phase(self, **_kwargs) -> bool:
            entered.append("provider-phase")
            return True

    controller = SimpleNamespace(
        assert_provider_dispatch_ready=lambda: (_ for _ in ()).throw(
            appmod.ChannelMediaInstallationControlUnavailable(
                "SECRET manual recovery path"
            )
        )
    )
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_authority",
        {"packaged": True, "mode": "manual_only"},
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_installation_control",
        controller,
        raising=False,
    )

    with pytest.raises(HTTPException) as unavailable:
        asyncio.run(
            appmod._enter_channel_media_provider_phase(
                Store(),
                SimpleNamespace(turn_id="turn", fencing_token=1),
                max_success_bytes=1024,
            )
        )

    assert unavailable.value.status_code == 503
    assert unavailable.value.detail == {
        "code": "channel_media_authority_unavailable",
        "retryable": False,
    }
    assert entered == []
    assert "SECRET" not in repr(unavailable.value.detail)


def test_packaged_channel_media_reproves_ready_after_provider_phase_commit(
    monkeypatch,
) -> None:
    events: list[str] = []
    installation_id = "a" * 64
    epoch = 21

    class Store:
        def enter_provider_phase(self, **_kwargs) -> bool:
            events.append("enter")
            return True

    store = Store()
    observed = SimpleNamespace(
        mode="ready",
        provider_dispatch_ready=True,
        installation_id=installation_id,
        epoch=epoch,
    )

    def prove_ready():  # noqa: ANN202
        events.append("proof")
        return observed

    controller = SimpleNamespace(
        store=store,
        assert_provider_dispatch_ready=prove_ready,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_authority",
        {"packaged": True, "mode": "ready"},
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_installation_control",
        controller,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_installation_id",
        installation_id,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_epoch",
        epoch,
        raising=False,
    )

    asyncio.run(
        appmod._enter_channel_media_provider_phase(
            store,
            SimpleNamespace(turn_id="turn", fencing_token=1),
            max_success_bytes=1024,
        )
    )

    assert events == ["proof", "enter", "proof"]


def test_packaged_channel_media_health_fails_closed_on_stale_store_handle(
    tmp_path, monkeypatch
) -> None:
    store = appmod.DurableChannelMediaRequestStore(tmp_path / "stale-channel.db")
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_requests",
        store,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_installation_control",
        None,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "channel_media_authority",
        {
            "mode": "disabled",
            "reason_code": "channel-media-installation-control-unavailable",
            "new_operations_ready": False,
            "replay_available": False,
            "packaged": True,
        },
        raising=False,
    )
    try:
        assert appmod._channel_media_request_readiness() == {
            "ready": False,
            "mode": "unavailable",
            "backup_supported": False,
            "reanchor_supported": False,
            "real_channel_e2e_verified": False,
        }
    finally:
        store.close()


def test_packaged_runtime_rejects_controller_principal_mismatch(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    root = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(
            installation_id="3" * 64,
            epoch=9,
            principal_digest="4" * 64,
        )
    )
    closed: list[bool] = []

    def close() -> None:
        closed.append(True)
        raise OSError("SECRET close failure")

    control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            outbound_ready=True,
            installation_id="3" * 64,
            epoch=9,
            paid_principal="5" * 64,
        ),
        store=object(),
        close=close,
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: control),
    )

    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state["mode"] == "disabled"
    assert state["reason_code"] == "installation-control-unavailable"
    assert target.state.paid_media_principal is None
    assert target.state.media_requests is None
    assert closed == [True]


def test_packaged_disable_and_shutdown_close_both_after_first_close_failure(
    monkeypatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    closed: list[str] = []

    def close_gateway() -> None:
        closed.append("gateway")
        raise OSError("SECRET gateway close failure")

    def close_asset() -> None:
        closed.append("asset")

    for action in ("disable", "shutdown"):
        target = FastAPI()
        target.state.installation_root_control = SimpleNamespace(close=close_gateway)
        target.state.asset_installation_control = SimpleNamespace(close=close_asset)
        target.state.media_requests = object()
        target.state.paid_media_assets = SimpleNamespace(
            close=lambda: closed.append("raw-asset-store")
        )

        if action == "disable":
            appmod._disable_paid_media_authority(target, "test-disable")
        else:
            appmod._close_paid_media_authority(target)

        assert target.state.installation_root_control is None
        assert target.state.asset_installation_control is None
        assert target.state.media_requests is None
        assert target.state.paid_media_assets is None

    assert closed == ["gateway", "asset", "gateway", "asset"]


def test_transient_controller_close_failure_is_retried_before_reference_is_lost(
) -> None:
    """A localized disable must not make a retryable ownership handle unreachable."""

    class RetryableControl:
        def __init__(self) -> None:
            self.close_attempts = 0
            self.closed = False

        def close(self) -> None:
            self.close_attempts += 1
            if self.close_attempts == 1:
                raise OSError("transient close interruption")
            self.closed = True

    target = FastAPI()
    gateway_control = RetryableControl()
    asset_closes: list[str] = []
    target.state.installation_root_control = gateway_control
    target.state.asset_installation_control = SimpleNamespace(
        close=lambda: asset_closes.append("asset")
    )
    target.state.media_requests = object()
    target.state.paid_media_assets = object()

    appmod._disable_paid_media_authority(target, "test-transient-close")
    # Ordinary Gateway work may continue after the paid subsystem is disabled;
    # its later shutdown is the final bounded chance to finish a transient
    # controller close before this process exits.
    appmod._close_paid_media_authority(target)

    assert gateway_control.closed, (
        "the failed controller was removed from app state before close could retry"
    )
    assert gateway_control.close_attempts >= 2
    assert asset_closes == ["asset"]


def test_persistent_controller_close_failure_is_bounded_and_reported() -> None:
    """Each lifecycle boundary gets one try and leaves an honest final state."""

    class PersistentFailureControl:
        def __init__(self) -> None:
            self.close_attempts = 0

        def close(self) -> None:
            self.close_attempts += 1
            raise OSError("persistent close interruption")

    target = FastAPI()
    gateway_control = PersistentFailureControl()
    asset_closes: list[str] = []
    target.state.installation_root_control = gateway_control
    target.state.asset_installation_control = SimpleNamespace(
        close=lambda: asset_closes.append("asset")
    )
    target.state.media_requests = object()
    target.state.paid_media_assets = object()

    appmod._disable_paid_media_authority(target, "test-persistent-close")

    assert gateway_control.close_attempts == 1
    assert asset_closes == ["asset"]
    pending = target.state.paid_media_close_pending
    assert len(pending) == 1 and pending[0] is gateway_control
    assert target.state.paid_media_authority["reason_code"] == "test-persistent-close"

    appmod._close_paid_media_authority(target)

    assert gateway_control.close_attempts == 2
    assert asset_closes == ["asset"]
    pending = target.state.paid_media_close_pending
    assert len(pending) == 1 and pending[0] is gateway_control
    assert target.state.paid_media_authority["reason_code"] == "store-close-incomplete"


def test_missing_asset_authority_closes_open_gateway_with_stable_reason(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    installation_id = "a" * 64
    epoch = 18
    snapshot = SimpleNamespace(
        installation_id=installation_id,
        epoch=epoch,
        principal_digest="b" * 64,
        status="active",
    )
    root = SimpleNamespace(snapshot=lambda: snapshot)
    closed: list[str] = []
    gateway_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            outbound_ready=True,
            installation_id=installation_id,
            epoch=epoch,
            paid_principal=appmod.stable_paid_principal(snapshot.principal_digest),
        ),
        store=object(),
        close=lambda: closed.append("gateway"),
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: gateway_control),
    )

    def missing_asset(*_args):  # noqa: ANN002, ANN202
        raise appmod.AssetInstallationControlUnavailable(
            "SECRET missing packaged asset directory"
        )

    monkeypatch.setattr(
        appmod.AssetInstallationControl,
        "open_bound",
        classmethod(lambda _cls, *args: missing_asset(*args)),
    )

    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state["reason_code"] == "asset-installation-control-unavailable"
    assert "SECRET" not in repr(state)
    assert closed == ["gateway"]
    assert target.state.installation_root_control is None
    assert target.state.asset_installation_control is None


def test_asset_controller_identity_mismatch_closes_both_controllers(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    installation_id = "c" * 64
    epoch = 19
    snapshot = SimpleNamespace(
        installation_id=installation_id,
        epoch=epoch,
        principal_digest="d" * 64,
        status="active",
    )
    root = SimpleNamespace(snapshot=lambda: snapshot)
    closed: list[str] = []
    gateway_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            outbound_ready=True,
            installation_id=installation_id,
            epoch=epoch,
            paid_principal=appmod.stable_paid_principal(snapshot.principal_digest),
        ),
        store=object(),
        close=lambda: (closed.append("gateway"), (_ for _ in ()).throw(OSError()))[1],
    )
    asset_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            installation_id="e" * 64,
            epoch=epoch,
        ),
        store=object(),
        close=lambda: closed.append("asset"),
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: gateway_control),
    )
    monkeypatch.setattr(
        appmod.AssetInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: asset_control),
    )

    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state["mode"] == "disabled"
    assert state["reason_code"] == "installation-control-unavailable"
    assert closed == ["gateway", "asset"]
    assert target.state.media_requests is None
    assert target.state.paid_media_assets is None


def test_packaged_startup_opens_asset_controller_only_after_root_reread(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    old = SimpleNamespace(
        installation_id="1" * 64,
        epoch=7,
        principal_digest="2" * 64,
        status="active",
    )
    current = SimpleNamespace(
        installation_id="1" * 64,
        epoch=8,
        principal_digest="3" * 64,
        status="active",
    )
    snapshots = iter((old, current, current))
    root = SimpleNamespace(snapshot=lambda: next(snapshots))
    control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            outbound_ready=True,
            installation_id=current.installation_id,
            epoch=current.epoch,
            paid_principal=appmod.stable_paid_principal(current.principal_digest),
        ),
        store=object(),
    )
    asset_store = object()
    asset_opens: list[tuple[Any, Path]] = []
    asset_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            installation_id=current.installation_id,
            epoch=current.epoch,
        ),
        store=asset_store,
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: control),
    )
    monkeypatch.setattr(
        appmod.AssetInstallationControl,
        "open_bound",
        classmethod(
            lambda _cls, root_value, path: (
                asset_opens.append((root_value, Path(path))),
                asset_control,
            )[1]
        ),
    )

    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state["mode"] == "ready"
    assert asset_opens == [(root, appmod.default_paid_media_asset_store_path())]
    assert target.state.asset_installation_control is asset_control
    assert target.state.paid_media_assets is asset_store
    assert target.state.paid_media_epoch == current.epoch


def test_activation_race_retains_both_controllers_then_refreshes_exact_pair(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    installation_id = "4" * 64
    epoch = 16
    provisioning = SimpleNamespace(
        installation_id=installation_id,
        epoch=epoch,
        principal_digest="5" * 64,
        status="provisioning",
    )
    active = SimpleNamespace(
        installation_id=installation_id,
        epoch=epoch,
        principal_digest="6" * 64,
        status="active",
    )
    snapshots = iter((provisioning, active))
    root = SimpleNamespace(snapshot=lambda: next(snapshots))
    request_store = object()
    asset_store = object()

    class GatewayControl:
        def __init__(self) -> None:
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                outbound_ready=False,
                installation_id=installation_id,
                epoch=epoch,
                paid_principal=None,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                outbound_ready=True,
                installation_id=installation_id,
                epoch=epoch,
                paid_principal=appmod.stable_paid_principal(active.principal_digest),
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            return request_store

        def close(self) -> None:
            return None

    gateway_control = GatewayControl()
    asset_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            installation_id=installation_id,
            epoch=epoch,
        ),
        store=asset_store,
        close=lambda: None,
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: gateway_control),
    )
    monkeypatch.setattr(
        appmod.AssetInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: asset_control),
    )

    initial = appmod._initialize_paid_media_authority(target, tmp_path)

    assert initial["mode"] == "provisioned_not_active"
    assert target.state.installation_root_control is gateway_control
    assert target.state.asset_installation_control is asset_control
    assert target.state.media_requests is None
    assert target.state.paid_media_assets is None

    for name in (
        "paid_media_authority_mode",
        "installation_root_control",
        "asset_installation_control",
        "media_requests",
        "paid_media_assets",
        "paid_media_installation_id",
        "paid_media_epoch",
        "paid_media_principal",
        "paid_media_root_principal",
        "paid_media_authority",
    ):
        monkeypatch.setattr(
            appmod.app.state,
            name,
            getattr(target.state, name),
            raising=False,
        )

    asyncio.run(appmod._refresh_waiting_paid_media_authority())

    assert appmod.app.state.media_requests is request_store
    assert appmod.app.state.paid_media_assets is asset_store
    assert appmod.app.state.paid_media_authority["mode"] == "ready"
    assert appmod.app.state.paid_media_principal == appmod.stable_paid_principal(
        active.principal_digest
    )


def test_packaged_asset_manual_only_exposes_replay_but_not_new_operations(
    tmp_path, monkeypatch
) -> None:
    target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    installation_id = "7" * 64
    epoch = 17
    snapshot = SimpleNamespace(
        installation_id=installation_id,
        epoch=epoch,
        principal_digest="8" * 64,
        status="active",
    )
    root = SimpleNamespace(snapshot=lambda: snapshot)
    request_store = object()
    asset_store = object()
    gateway_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            outbound_ready=True,
            installation_id=installation_id,
            epoch=epoch,
            paid_principal=appmod.stable_paid_principal(snapshot.principal_digest),
        ),
        store=request_store,
    )
    asset_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="manual_only",
            reason_code="manual-recovery-required",
            installation_id=installation_id,
            epoch=epoch,
        ),
        store=asset_store,
    )
    monkeypatch.setattr(appmod.InstallationRoot, "open", lambda _path: root)
    monkeypatch.setattr(
        appmod.GatewayInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: gateway_control),
    )
    monkeypatch.setattr(
        appmod.AssetInstallationControl,
        "open_bound",
        classmethod(lambda _cls, _root, _path: asset_control),
    )

    state = appmod._initialize_paid_media_authority(target, tmp_path)

    assert state == {
        "mode": "manual_only",
        "reason_code": "manual-recovery-required",
        "new_operations_ready": False,
        "replay_available": True,
        "packaged": True,
    }
    assert target.state.media_requests is request_store
    assert target.state.paid_media_assets is asset_store


def test_missing_packaged_root_and_development_store_failure_both_degrade(
    tmp_path, monkeypatch
) -> None:
    packaged_target = FastAPI()
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    def missing(_path):  # noqa: ANN001, ANN202
        raise InstallationRootUnavailable("SECRET missing root path")

    monkeypatch.setattr(appmod.InstallationRoot, "open", missing)
    packaged = appmod._initialize_paid_media_authority(packaged_target, tmp_path)
    assert packaged["reason_code"] == "installation-root-unavailable"
    assert packaged_target.state.media_requests is None

    monkeypatch.delattr(sys, "frozen", raising=False)
    development_target = FastAPI()
    monkeypatch.setattr(
        appmod,
        "DurableMediaRequestStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("SECRET development database path")
        ),
    )
    development = appmod._initialize_paid_media_authority(
        development_target, tmp_path
    )
    assert development == {
        "mode": "disabled",
        "reason_code": "paid-media-store-unavailable",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": False,
    }
    assert "SECRET" not in repr(development)


def test_health_paid_authority_does_not_lower_core_readiness(monkeypatch) -> None:
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority",
        {
            "mode": "disabled",
            "reason_code": "installation-root-unavailable",
            "new_operations_ready": False,
            "replay_available": False,
            "packaged": True,
        },
        raising=False,
    )
    monkeypatch.setattr(appmod, "_database_readiness", lambda: {"ready": True})
    monkeypatch.setattr(
        appmod,
        "_financial_ledger_readiness",
        lambda: {"ready": True},
    )
    monkeypatch.setattr(
        appmod,
        "_connection_store_readiness",
        lambda: {"ready": True},
    )
    request = SimpleNamespace(query_params={})

    result = asyncio.run(appmod.health(request))

    assert result["status"] == "ok"
    assert result["readiness"] == "ok"
    assert result["checks"]["paid_media_authority"]["reason_code"] == (
        "engine-session-capability-unavailable"
    )
    assert result["checks"]["paid_media_authority"]["new_operations_ready"] is False
    assert (
        result["checks"]["paid_media_authority"][
            "engine_session_verifier_ready"
        ]
        is False
    )
    assert (
        result["checks"]["paid_media_authority"][
            "desktop_v2_stage_authority_ready"
        ]
        is False
    )
    assert result["checks"]["paid_media_authority"]["backup_supported"] is False
    assert result["checks"]["paid_media_authority"]["backup_reason_code"] == (
        "paid-authority-backup-unsupported"
    )


def test_health_keeps_new_operations_closed_when_session_verifier_is_ready(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority",
        {
            "mode": "ready",
            "reason_code": "ok",
            "new_operations_ready": True,
            "replay_available": True,
            "packaged": True,
        },
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_engine_session_verifier",
        SimpleNamespace(
            ready=True,
            stage_ready=False,
            stage_vault_evidence_sha256=None,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_desktop_v2_stage_ready",
        False,
        raising=False,
    )
    monkeypatch.setattr(appmod, "_database_readiness", lambda: {"ready": True})
    monkeypatch.setattr(
        appmod,
        "_financial_ledger_readiness",
        lambda: {"ready": True},
    )
    monkeypatch.setattr(
        appmod,
        "_connection_store_readiness",
        lambda: {"ready": True},
    )

    result = asyncio.run(appmod.health(SimpleNamespace(query_params={})))
    paid = result["checks"]["paid_media_authority"]

    assert paid["engine_session_verifier_ready"] is True
    assert paid["desktop_v2_stage_authority_ready"] is False
    assert paid["new_operations_ready"] is False
    assert paid["reason_code"] == "desktop-v2-stage-authority-unavailable"


def test_health_reads_stage_from_boot_latch_not_mutable_fastapi_boolean(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority",
        {
            "mode": "ready",
            "reason_code": "authority-exact",
            "new_operations_ready": True,
            "replay_available": True,
            "packaged": True,
        },
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_engine_session_verifier",
        SimpleNamespace(
            ready=True,
            stage_ready=True,
            stage_vault_evidence_sha256="a" * 64,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_desktop_v2_stage_ready",
        False,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        SimpleNamespace(
            state=SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                outbound_ready=True,
            )
        ),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        SimpleNamespace(
            state=SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
            )
        ),
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", object(), raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", object(), raising=False)

    paid = appmod._paid_media_authority_readiness()

    assert paid["engine_session_verifier_ready"] is True
    assert paid["desktop_v2_stage_authority_ready"] is True
    assert "desktop_v2_stage_vault_evidence_sha256" not in paid
    assert paid["new_operations_ready"] is True
    assert paid["reason_code"] == "authority-exact"


def test_readiness_combines_gateway_and_asset_modes_without_identity_material(
    monkeypatch,
) -> None:
    gateway_state = SimpleNamespace(
        mode="ready",
        reason_code="authority-exact",
        outbound_ready=True,
    )
    asset_state = SimpleNamespace(
        mode="manual_only",
        reason_code="manual-recovery-required",
    )
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority",
        {
            "mode": "ready",
            "reason_code": "authority-exact",
            "new_operations_ready": True,
            "replay_available": True,
            "packaged": True,
        },
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        SimpleNamespace(state=gateway_state),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        SimpleNamespace(state=asset_state),
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", object(), raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", object(), raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_engine_session_verifier",
        SimpleNamespace(ready=True, stage_ready=True),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_installation_id", "9" * 64, raising=False
    )

    paid = appmod._paid_media_authority_readiness()

    assert paid["mode"] == "manual_only"
    assert paid["reason_code"] == "manual-recovery-required"
    assert paid["gateway_mode"] == "ready"
    assert paid["asset_mode"] == "manual_only"
    assert paid["new_operations_ready"] is False
    assert paid["replay_available"] is True
    assert paid["backup_supported"] is False
    assert paid["reanchor_supported"] is False
    assert "installation_id" not in paid
    assert "epoch" not in paid
    assert "state_digest" not in paid


def test_waiting_controller_reconciles_after_private_desktop_bind(monkeypatch) -> None:
    store = object()
    asset_store = object()
    principal = "6" * 64
    installation_id = "a" * 64
    epoch = 11

    class Control:
        def __init__(self) -> None:
            self.reconciles = 0
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="provisioned-not-active",
                outbound_ready=False,
                paid_principal=None,
                installation_id=installation_id,
                epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self.reconciles += 1
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                outbound_ready=True,
                paid_principal=principal,
                installation_id=installation_id,
                epoch=epoch,
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            if not self._state.outbound_ready:
                raise GatewayInstallationControlUnavailable("not active")
            return store

    class AssetControl:
        def __init__(self) -> None:
            self.reconciles = 0
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                installation_id=installation_id,
                epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self.reconciles += 1
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                installation_id=installation_id,
                epoch=epoch,
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            return asset_store

    control = Control()
    asset_control = AssetControl()
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority_mode",
        "installation-root",
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        control,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        asset_control,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "media_requests",
        None,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", None, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_installation_id",
        installation_id,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_principal",
        principal,
        raising=False,
    )

    asyncio.run(appmod._refresh_waiting_paid_media_authority())

    assert control.reconciles == 1
    assert asset_control.reconciles == 1
    assert appmod.app.state.media_requests is store
    assert appmod.app.state.paid_media_assets is asset_store
    assert appmod.app.state.paid_media_authority == {
        "mode": "ready",
        "reason_code": "authority-exact",
        "new_operations_ready": True,
        "replay_available": True,
        "packaged": True,
    }


def test_waiting_controller_reconcile_is_singleflight(monkeypatch) -> None:
    store = object()
    asset_store = object()
    principal = "7" * 64
    installation_id = "b" * 64
    epoch = 12

    class Control:
        def __init__(self) -> None:
            self.reconciles = 0
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="provisioned-not-active",
                outbound_ready=False,
                paid_principal=None,
                installation_id=installation_id,
                epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self.reconciles += 1
            time.sleep(0.05)
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                outbound_ready=True,
                paid_principal=principal,
                installation_id=installation_id,
                epoch=epoch,
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            return store

    class AssetControl:
        def __init__(self) -> None:
            self.reconciles = 0
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                installation_id=installation_id,
                epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self.reconciles += 1
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                installation_id=installation_id,
                epoch=epoch,
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            return asset_store

    control = Control()
    asset_control = AssetControl()
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority_mode",
        "installation-root",
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        control,
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        asset_control,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", None, raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", None, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_installation_id",
        installation_id,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_principal",
        principal,
        raising=False,
    )

    async def concurrently_refresh() -> None:
        await asyncio.gather(
            *(appmod._refresh_waiting_paid_media_authority() for _ in range(12))
        )

    asyncio.run(concurrently_refresh())

    assert control.reconciles == 1
    assert asset_control.reconciles == 1
    assert appmod.app.state.media_requests is store
    assert appmod.app.state.paid_media_assets is asset_store


def test_waiting_asset_reconcile_failure_exposes_neither_store_or_secret(
    monkeypatch,
) -> None:
    installation_id = "3" * 64
    epoch = 20
    principal = "4" * 64
    request_store = object()

    class GatewayControl:
        def __init__(self) -> None:
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                outbound_ready=False,
                paid_principal=None,
                installation_id=installation_id,
                epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                outbound_ready=True,
                paid_principal=principal,
                installation_id=installation_id,
                epoch=epoch,
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            return request_store

    class AssetControl:
        def __init__(self) -> None:
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="awaiting-installation-activation",
                installation_id=installation_id,
                epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self._state = SimpleNamespace(
                mode="fused",
                reason_code="authority-reconciliation-failed",
                installation_id=installation_id,
                epoch=epoch,
            )
            raise appmod.AssetInstallationControlUnavailable(
                "SECRET asset activation failure"
            )

    gateway_control = GatewayControl()
    asset_control = AssetControl()
    monkeypatch.setattr(
        appmod.app.state, "paid_media_authority_mode", "installation-root", raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "installation_root_control", gateway_control, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "asset_installation_control", asset_control, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", None, raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", None, raising=False)
    monkeypatch.setattr(
        appmod.app.state, "paid_media_installation_id", installation_id, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state, "paid_media_principal", principal, raising=False
    )

    asyncio.run(appmod._refresh_waiting_paid_media_authority())

    assert appmod.app.state.media_requests is None
    assert appmod.app.state.paid_media_assets is None
    assert appmod.app.state.paid_media_authority == {
        "mode": "fused",
        "reason_code": "activation-reconcile-failed",
        "new_operations_ready": False,
        "replay_available": False,
        "packaged": True,
    }
    assert "SECRET" not in repr(appmod.app.state.paid_media_authority)


def test_waiting_controller_principal_mismatch_never_exposes_store(
    monkeypatch,
) -> None:
    store = object()
    installation_id = "2" * 64
    epoch = 15

    class Control:
        def __init__(self) -> None:
            self._state = SimpleNamespace(
                mode="provisioned_not_active",
                reason_code="provisioned-not-active",
                    outbound_ready=False,
                    paid_principal=None,
                    installation_id=installation_id,
                    epoch=epoch,
            )

        @property
        def state(self):  # noqa: ANN201
            return self._state

        def reconcile_startup(self):  # noqa: ANN201
            self._state = SimpleNamespace(
                mode="ready",
                reason_code="authority-exact",
                    outbound_ready=True,
                    paid_principal="9" * 64,
                    installation_id=installation_id,
                    epoch=epoch,
            )
            return self._state

        @property
        def store(self):  # noqa: ANN201
            return store

    asset_store = object()
    asset_control = SimpleNamespace(
        state=SimpleNamespace(
            mode="ready",
            reason_code="authority-exact",
            installation_id=installation_id,
            epoch=epoch,
        ),
        store=asset_store,
    )

    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_authority_mode",
        "installation-root",
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        Control(),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        asset_control,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", None, raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", None, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_installation_id",
        installation_id,
        raising=False,
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state,
        "paid_media_principal",
        "8" * 64,
        raising=False,
    )

    asyncio.run(appmod._refresh_waiting_paid_media_authority())

    assert appmod.app.state.media_requests is None
    assert appmod.app.state.paid_media_principal is None
    assert appmod.app.state.paid_media_authority["mode"] == "fused"
    assert appmod.app.state.paid_media_authority["reason_code"] == (
        "installation-principal-mismatch"
    )


def test_asset_manual_only_keeps_replay_but_rejects_new_claim_before_write(
    monkeypatch,
) -> None:
    installation_id = "c" * 64
    epoch = 13
    principal = "d" * 64
    claim_calls: list[str] = []
    gateway_checks: list[str] = []
    asset_checks: list[str] = []
    def reject_new_claim(**kwargs):  # noqa: ANN003, ANN202
        claim_calls.append("claim")
        kwargs["admission_hook"]()

    request_store = SimpleNamespace(claim=reject_new_claim)
    asset_store = object()
    gateway_state = SimpleNamespace(
        mode="ready",
        reason_code="authority-exact",
        outbound_ready=True,
        paid_principal=principal,
        installation_id=installation_id,
        epoch=epoch,
    )
    asset_state = SimpleNamespace(
        mode="manual_only",
        reason_code="manual-recovery-required",
        installation_id=installation_id,
        epoch=epoch,
    )
    gateway_control = SimpleNamespace(
        state=gateway_state,
        assert_local_mutation_ready=lambda: gateway_checks.append("gateway"),
    )
    asset_control = SimpleNamespace(
        state=asset_state,
        assert_local_mutation_ready=lambda: asset_checks.append("asset"),
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_authority_mode", "installation-root", raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "installation_root_control", gateway_control, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "asset_installation_control", asset_control, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_installation_id", installation_id, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state, "paid_media_principal", principal, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", request_store, raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", asset_store, raising=False)

    with pytest.raises(HTTPException) as caught:
        asyncio.run(
            appmod._claim_paid_media_request(
                principal_hash="e" * 64,
                operation="images.create",
                idempotency_key="desktop-11111111-1111-4111-8111-111111111111",
                payload={"model": "paid-model", "prompt": "must stay closed"},
            )
        )

    assert caught.value.status_code == 503
    assert caught.value.detail["code"] == "paid_media_authority_unavailable"
    assert gateway_checks == []
    assert asset_checks == []
    assert claim_calls == ["claim"]


def test_new_claim_admission_progresses_while_outbound_pair_lock_is_held(
    tmp_path,
    monkeypatch,
) -> None:
    """A new claim must not invert the ledger and outbound-pair lock order."""

    installation_id = "5" * 64
    epoch = 15
    principal = "6" * 64
    outbound_holds_pair_lock = threading.Event()
    release_outbound = threading.Event()
    claim_started = threading.Event()
    claim_results: list[Any] = []
    claim_errors: list[BaseException] = []
    outbound_errors: list[BaseException] = []
    claim_pair_lock_attempts: list[str] = []
    gateway_state = SimpleNamespace(
        mode="ready",
        reason_code="authority-exact",
        outbound_ready=True,
        paid_principal=principal,
        installation_id=installation_id,
        epoch=epoch,
    )
    asset_state = SimpleNamespace(
        mode="ready",
        reason_code="authority-exact",
        installation_id=installation_id,
        epoch=epoch,
    )

    class GatewayControl:
        @property
        def state(self):  # noqa: ANN201
            return gateway_state

        def assert_outbound_ready(self):  # noqa: ANN201
            # _assert_paid_media_outbound_pair holds the process pair lock
            # while this fresh proof runs.  The finite wait guarantees cleanup
            # even if the assertion below or the test runner is interrupted.
            outbound_holds_pair_lock.set()
            if not release_outbound.wait(timeout=15.0):
                raise TimeoutError("outbound pair-lock test watchdog expired")
            return gateway_state

    class AssetControl:
        @property
        def state(self):  # noqa: ANN201
            return asset_state

        def assert_local_mutation_ready(self) -> None:
            return None

    gateway_control = GatewayControl()
    asset_control = AssetControl()
    store = appmod.DurableMediaRequestStore(tmp_path / "lock-order-claim.db")

    class InstrumentedReconcileLock:
        """Fail immediately if ledger admission tries the outbound pair lock."""

        def __init__(self) -> None:
            self._lock = threading.Lock()

        def __enter__(self):  # noqa: ANN204
            current_name = threading.current_thread().name
            if current_name == "test-paid-claim-admission" and self._lock.locked():
                claim_pair_lock_attempts.append(current_name)
                raise AssertionError(
                    "ledger admission attempted the outbound pair lock"
                )
            if not self._lock.acquire(timeout=15.0):
                raise TimeoutError("instrumented reconcile-lock watchdog expired")
            return self

        def __exit__(self, _exc_type, _exc, _traceback) -> bool:
            self._lock.release()
            return False

    monkeypatch.setattr(
        appmod,
        "_PAID_ACTIVATION_RECONCILE_LOCK",
        InstrumentedReconcileLock(),
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_authority_mode", "installation-root", raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "installation_root_control", gateway_control, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "asset_installation_control", asset_control, raising=False
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_installation_id", installation_id, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state, "paid_media_principal", principal, raising=False
    )

    def hold_outbound_pair_lock() -> None:
        try:
            appmod._assert_paid_media_outbound_pair(
                gateway_control,
                asset_control,
                installation_id=installation_id,
                epoch=epoch,
                paid_principal=principal,
            )
        except BaseException as exc:  # surfaced after both threads are joined
            outbound_errors.append(exc)

    def claim_new_operation() -> None:
        claim_started.set()
        try:
            claim_results.append(
                store.claim(
                    principal_hash="7" * 64,
                    operation="images.create",
                    idempotency_key=(
                        "desktop-lock-order-1111-4111-8111-111111111111"
                    ),
                    request_sha256="8" * 64,
                    admission_hook=appmod._assert_paid_media_new_operation_ready,
                    now=1_000.0,
                )
            )
        except BaseException as exc:  # surfaced after both threads are joined
            claim_errors.append(exc)

    outbound_thread = threading.Thread(
        target=hold_outbound_pair_lock,
        name="test-outbound-pair-lock-holder",
        daemon=True,
    )
    claim_thread = threading.Thread(
        target=claim_new_operation,
        name="test-paid-claim-admission",
        daemon=True,
    )
    try:
        outbound_thread.start()
        assert outbound_holds_pair_lock.wait(timeout=5.0)
        claim_thread.start()
        assert claim_started.wait(timeout=5.0)
        # This is only a deadlock watchdog.  Lock-order correctness is observed
        # directly by InstrumentedReconcileLock, not inferred from elapsed time.
        claim_thread.join(timeout=10.0)
    finally:
        release_outbound.set()
        outbound_thread.join(timeout=10.0)
        claim_thread.join(timeout=10.0)
        store.close()

    assert not outbound_thread.is_alive()
    assert not claim_thread.is_alive()
    assert claim_pair_lock_attempts == []
    assert outbound_errors == []
    assert claim_errors == []
    assert len(claim_results) == 1
    assert claim_results[0].state == "claimed"


def test_asset_drift_blocks_outbound_before_provider_even_when_gateway_is_fresh(
    monkeypatch,
) -> None:
    installation_id = "f" * 64
    epoch = 14
    principal = "1" * 64
    provider_calls: list[str] = []
    checks: list[str] = []
    gateway_state = SimpleNamespace(
        mode="ready",
        reason_code="authority-exact",
        outbound_ready=True,
        paid_principal=principal,
        installation_id=installation_id,
        epoch=epoch,
    )
    asset_state = SimpleNamespace(
        mode="ready",
        reason_code="authority-exact",
        installation_id=installation_id,
        epoch=epoch,
    )

    def assert_gateway():  # noqa: ANN202
        checks.append("gateway")
        return gateway_state

    def assert_asset() -> None:
        checks.append("asset")
        raise RuntimeError("SECRET asset Root drift")

    monkeypatch.setattr(
        appmod.app.state, "paid_media_authority_mode", "installation-root", raising=False
    )
    monkeypatch.setattr(
        appmod.app.state,
        "installation_root_control",
        SimpleNamespace(state=gateway_state, assert_outbound_ready=assert_gateway),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state,
        "asset_installation_control",
        SimpleNamespace(state=asset_state, assert_local_mutation_ready=assert_asset),
        raising=False,
    )
    monkeypatch.setattr(
        appmod.app.state, "paid_media_installation_id", installation_id, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "paid_media_epoch", epoch, raising=False)
    monkeypatch.setattr(
        appmod.app.state, "paid_media_principal", principal, raising=False
    )
    monkeypatch.setattr(appmod.app.state, "media_requests", object(), raising=False)
    monkeypatch.setattr(appmod.app.state, "paid_media_assets", object(), raising=False)

    async def cross_remote_boundary() -> None:
        await appmod._assert_paid_media_outbound_ready()
        provider_calls.append("provider")

    with pytest.raises(HTTPException) as caught:
        asyncio.run(cross_remote_boundary())

    assert caught.value.status_code == 503
    assert caught.value.detail["code"] == "paid_media_authority_unavailable"
    assert checks == ["gateway", "asset"]
    assert provider_calls == []
    assert "SECRET" not in repr(appmod.app.state.paid_media_authority)
