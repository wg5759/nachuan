from __future__ import annotations

import pytest

from orchestrator.plugin_kernel import (
    CapabilityDenied,
    EventDefinition,
    InProcessTrustError,
    PluginDisposalError,
    PluginInUseError,
    PluginKernel,
    PluginManifestError,
    PluginManifestV1,
    PluginMountError,
    ServiceDefinition,
    ServiceNotFound,
)


_DIGEST = "a" * 64


def _manifest(**overrides: object) -> PluginManifestV1:
    payload: dict[str, object] = {
        "schema": "nachuan.plugin.v1",
        "id": "com.nachuan.test.demo",
        "version": "1.0.0",
        "api_version": "1",
        "kind": "test",
        "capabilities": ["demo.read"],
        "artifact_sha256": _DIGEST,
        "execution": "in_process",
        "trust": "builtin",
        "publisher": "nachuan-tests",
    }
    payload.update(overrides)
    return PluginManifestV1.from_mapping(payload)


@pytest.mark.parametrize(
    ("overrides", "pattern"),
    [
        ({"unexpected": True}, "unknown"),
        ({"id": "BAD ID"}, "id"),
        ({"version": "latest"}, "version"),
        ({"artifact_sha256": "abc"}, "sha256"),
        ({"capabilities": ["demo.read", "demo.read"]}, "duplicate"),
        ({"capabilities": ["Demo Read"]}, "capability"),
    ],
)
def test_manifest_is_closed_and_versioned(overrides, pattern):
    with pytest.raises(PluginManifestError, match=pattern):
        _manifest(**overrides)


def test_untrusted_plugin_cannot_mount_in_process():
    kernel = PluginKernel()
    manifest = _manifest(
        execution="in_process",
        trust="verified_third_party",
    )

    with pytest.raises(InProcessTrustError):
        kernel.mount(manifest, lambda _ctx: None)

    assert kernel.active_plugin_ids() == ()


@pytest.mark.asyncio
async def test_mount_borrow_emit_unmount_and_capability_revocation():
    kernel = PluginKernel()
    kernel.services.define(ServiceDefinition("demo.service", "1"))
    kernel.events.define(EventDefinition("fact/demo", "durable"))
    seen: list[object] = []
    disposed: list[str] = []
    permit_holder = []

    def apply(ctx):
        ctx.provide_service("demo.service", {"ready": True})
        ctx.listen("fact/demo", lambda payload: seen.append(payload))
        ctx.effect(lambda: disposed.append("custom"))
        permit_holder.append(ctx.permit("demo.read"))

    kernel.mount(_manifest(), apply)
    assert kernel.active_plugin_ids() == ("com.nachuan.test.demo",)
    assert await kernel.events.emit("fact/demo", {"value": 1}) == 1
    assert seen == [{"value": 1}]
    kernel.require(permit_holder[0], "demo.read")

    lease = kernel.borrow_service("demo.service")
    assert lease.value == {"ready": True}
    with pytest.raises(PluginInUseError):
        await kernel.unmount("com.nachuan.test.demo")
    kernel.require(permit_holder[0], "demo.read")

    lease.release()
    await kernel.unmount("com.nachuan.test.demo")

    assert disposed == ["custom"]
    assert kernel.active_plugin_ids() == ()
    with pytest.raises(ServiceNotFound):
        kernel.borrow_service("demo.service")
    assert await kernel.events.emit("fact/demo", {"value": 2}) == 0
    with pytest.raises(CapabilityDenied):
        kernel.require(permit_holder[0], "demo.read")


def test_mount_failure_rolls_back_every_registration():
    kernel = PluginKernel()
    kernel.services.define(ServiceDefinition("demo.service", "1"))
    kernel.events.define(EventDefinition("runtime/demo", "live"))
    disposed: list[str] = []

    def broken(ctx):
        ctx.provide_service("demo.service", object())
        ctx.listen("runtime/demo", lambda _payload: None)
        ctx.effect(lambda: disposed.append("rolled-back"))
        raise ValueError("secret-adjacent plugin error")

    with pytest.raises(PluginMountError):
        kernel.mount(_manifest(), broken)

    assert disposed == ["rolled-back"]
    assert kernel.active_plugin_ids() == ()
    with pytest.raises(ServiceNotFound):
        kernel.borrow_service("demo.service")


@pytest.mark.asyncio
async def test_disposer_failure_still_clears_other_effects_and_quarantines():
    kernel = PluginKernel()
    kernel.services.define(ServiceDefinition("demo.service", "1"))
    cleaned: list[str] = []

    def apply(ctx):
        ctx.provide_service("demo.service", object())
        ctx.effect(lambda: cleaned.append("after-failure"))

        def fail():
            raise RuntimeError("do not expose this detail")

        ctx.effect(fail)

    manifest = _manifest()
    kernel.mount(manifest, apply)

    with pytest.raises(PluginDisposalError):
        await kernel.unmount(manifest.plugin_id)

    assert cleaned == ["after-failure"]
    assert kernel.active_plugin_ids() == ()
    assert kernel.quarantined_plugin_ids() == (manifest.plugin_id,)
    with pytest.raises(ServiceNotFound):
        kernel.borrow_service("demo.service")


@pytest.mark.asyncio
async def test_old_permit_stays_revoked_after_same_plugin_is_remounted():
    kernel = PluginKernel()
    permits = []
    manifest = _manifest()

    kernel.mount(manifest, lambda ctx: permits.append(ctx.permit("demo.read")))
    await kernel.unmount(manifest.plugin_id)
    kernel.mount(manifest, lambda ctx: permits.append(ctx.permit("demo.read")))

    assert permits[0].generation != permits[1].generation
    with pytest.raises(CapabilityDenied):
        kernel.require(permits[0], "demo.read")
    kernel.require(permits[1], "demo.read")
    await kernel.unmount(manifest.plugin_id)
