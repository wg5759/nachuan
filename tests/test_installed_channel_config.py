from __future__ import annotations

import json
import re
import hashlib
from concurrent.futures import ProcessPoolExecutor

import pytest

from gateway.installed_channel_config import (
    InstalledChannelConfigConflict,
    InstalledChannelConfigError,
    InstalledChannelSupervisorConfigStore,
)
from gateway.secure_store import assert_restricted_windows_acl
from gateway.installed_channel_supervisor import (
    InstalledChannelEpochAnchor,
    build_installed_channel_launches_from_config,
)
from gateway.installation_root import (
    InstallationRootSnapshot,
    UpdaterState,
    installation_principal,
)


def _rotate_once_in_process(path: str) -> tuple[str, int]:
    store = InstalledChannelSupervisorConfigStore(path)
    try:
        result = store.rotate_capabilities(expected_generation=1)
        return "rotated", result.generation
    except (InstalledChannelConfigConflict, InstalledChannelConfigError):
        return "conflict", 0


def _active_installation_snapshot() -> InstallationRootSnapshot:
    installation_id = "a" * 64
    epoch = 4
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest="b" * 64,
        epoch=epoch,
        root_revision=9,
        status="active",
        lock_kind="none",
        lock_reason_digest=None,
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=installation_principal(installation_id, epoch),
        components=(),
        updater=UpdaterState(
            release_sequence=1,
            keyring_sequence=1,
            artifact_digest="c" * 64,
            state_digest="d" * 64,
        ),
    )


def test_config_is_dpapi_protected_reopenable_and_rotates_all_capabilities(
    tmp_path,
) -> None:
    path = tmp_path / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(path)

    first = store.create(
        engine_port=43123,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="synthetic-feishu-secret-value",
    )
    reopened = InstalledChannelSupervisorConfigStore(path).load()

    assert first == reopened
    assert first.generation == 1
    assert first.engine_port == 43123
    assert re.fullmatch(r"sk-local-[0-9a-f]{64}", first.runtime_key)
    assert re.fullmatch(r"sk-approval-[0-9a-f]{64}", first.approval_key)
    assert re.fullmatch(r"sk-paid-media-[0-9a-f]{64}", first.paid_media_key)
    assert re.fullmatch(
        r"sk-bridge-v2-weixin-[0-9a-f]{64}", first.weixin_bridge_key
    )
    assert re.fullmatch(
        r"sk-bridge-v2-feishu-[0-9a-f]{64}", first.feishu_bridge_key
    )
    assert len(
        {
            first.runtime_key,
            first.approval_key,
            first.paid_media_key,
            first.weixin_bridge_key,
            first.feishu_bridge_key,
        }
    ) == 5

    safe = store.safe_status()
    assert safe == {
        "schema": "nachuan.installed-channel-supervisor-status.v1",
        "generation": 1,
        "engine_port": 43123,
        "capabilities_configured": True,
        "feishu_configured": True,
    }
    assert "synthetic-feishu-secret-value" not in repr(first)
    assert first.runtime_key not in repr(first)

    rotated = store.rotate_capabilities(expected_generation=1)
    assert rotated.generation == 2
    assert rotated.engine_port == first.engine_port
    assert rotated.feishu_app_id == first.feishu_app_id
    assert rotated.feishu_app_secret == first.feishu_app_secret
    assert rotated.runtime_key != first.runtime_key
    assert rotated.approval_key != first.approval_key
    assert rotated.paid_media_key != first.paid_media_key
    assert rotated.weixin_bridge_key != first.weixin_bridge_key
    assert rotated.feishu_bridge_key != first.feishu_bridge_key
    with pytest.raises(InstalledChannelConfigConflict, match="generation changed"):
        store.rotate_capabilities(expected_generation=1)

    verification_path = path.with_name(path.name + ".verification-key")
    for protected in (path, verification_path):
        raw = protected.read_text("utf-8")
        assert '"schema":"nachuan.protected-json.v1"' in raw
        assert "synthetic-feishu-secret-value" not in raw
        for value in (
            first.runtime_key,
            first.approval_key,
            first.paid_media_key,
            first.weixin_bridge_key,
            first.feishu_bridge_key,
            rotated.runtime_key,
            rotated.approval_key,
            rotated.paid_media_key,
            rotated.weixin_bridge_key,
            rotated.feishu_bridge_key,
        ):
            assert value not in raw
        assert_restricted_windows_acl(protected)


def test_missing_config_read_does_not_create_a_verification_key(tmp_path) -> None:
    path = tmp_path / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(path)

    with pytest.raises(InstalledChannelConfigError, match="configuration is unavailable"):
        store.load()

    assert not path.exists()
    assert not path.with_name(path.name + ".verification-key").exists()


def test_ciphertext_tamper_fails_closed_without_rewriting(tmp_path) -> None:
    path = tmp_path / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(path)
    created = store.create(
        engine_port=43123,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="synthetic-feishu-secret-value",
    )
    envelope = json.loads(path.read_text("utf-8"))
    ciphertext = envelope["ciphertext"]
    envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    path.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")
    tampered = path.read_bytes()

    with pytest.raises(InstalledChannelConfigError, match="configuration is unavailable"):
        store.load()

    assert path.read_bytes() == tampered
    assert created.runtime_key.encode("ascii") not in tampered


def test_verified_snapshot_drives_the_three_role_launch_generation(tmp_path) -> None:
    config_path = tmp_path / "config" / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(config_path)
    first = store.create(
        engine_port=43123,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="synthetic-feishu-secret-value",
    )
    engine_dir = tmp_path / "installed" / "resources" / "engine"
    data_dir = tmp_path / "user-data" / "data"
    vault_dir = tmp_path / "local-data" / "Nachuan" / "data"
    engine_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    vault_dir.mkdir(parents=True)
    engine = engine_dir / "engine.exe"
    engine.write_bytes(b"test-only-frozen-engine")
    vault = vault_dir / "connections.json"
    vault.write_text("{}", encoding="utf-8")
    (vault_dir / "connections.json.verification-key").write_text(
        "test-only", encoding="utf-8"
    )
    profile = tmp_path / "store-runtime-profile.v1.json"
    profile.write_text('{"schema":"nachuan.runtime-profile/v1"}', encoding="utf-8")
    profile_digest = hashlib.sha256(profile.read_bytes()).hexdigest()
    installation_snapshot = _active_installation_snapshot()

    first_launches = build_installed_channel_launches_from_config(
        config=store.load(),
        installation_snapshot=installation_snapshot,
        epoch_anchor=InstalledChannelEpochAnchor.from_snapshot(
            installation_snapshot, config_generation=first.generation
        ),
        engine_executable=engine,
        data_directory=data_dir,
        connections_path=vault,
        engine_boot_token="a" * 64,
        runtime_profile_manifest=profile,
        runtime_profile_sha256=profile_digest,
    )
    second = store.rotate_capabilities(expected_generation=1)
    second_launches = build_installed_channel_launches_from_config(
        config=second,
        installation_snapshot=installation_snapshot,
        epoch_anchor=InstalledChannelEpochAnchor.from_snapshot(
            installation_snapshot, config_generation=second.generation
        ),
        engine_executable=engine,
        data_directory=data_dir,
        connections_path=vault,
        engine_boot_token="b" * 64,
        runtime_profile_manifest=profile,
        runtime_profile_sha256=profile_digest,
    )

    assert first_launches["engine"].environment["NACHUAN_ENGINE_GENERATION"] == "1"
    assert second_launches["engine"].environment["NACHUAN_ENGINE_GENERATION"] == "2"
    assert first_launches["engine"].environment["GATEWAY_API_KEYS"] == first.runtime_key
    assert second_launches["engine"].environment["GATEWAY_API_KEYS"] == second.runtime_key
    assert (
        second_launches["weixin"].environment["BRIDGE_API_KEY"]
        == second.weixin_bridge_key
    )
    assert (
        second_launches["feishu"].environment["BRIDGE_API_KEY"]
        == second.feishu_bridge_key
    )


def test_two_processes_cannot_both_rotate_the_same_generation(tmp_path) -> None:
    path = tmp_path / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(path)
    store.create(
        engine_port=43123,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="synthetic-feishu-secret-value",
    )

    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_rotate_once_in_process, (str(path), str(path))))

    assert sorted(results) == [("conflict", 0), ("rotated", 2)]
    assert store.load().generation == 2


def test_verification_key_tamper_fails_closed_without_rekeying(tmp_path) -> None:
    path = tmp_path / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(path)
    store.create(
        engine_port=43123,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="synthetic-feishu-secret-value",
    )
    key_path = path.with_name(path.name + ".verification-key")
    envelope = json.loads(key_path.read_text("utf-8"))
    ciphertext = envelope["ciphertext"]
    envelope["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    key_path.write_text(
        json.dumps(envelope, separators=(",", ":")), encoding="utf-8"
    )
    tampered = key_path.read_bytes()

    with pytest.raises(
        InstalledChannelConfigError, match="verification key is unavailable"
    ):
        store.load()

    assert key_path.read_bytes() == tampered


def test_feishu_credential_update_rotates_every_capability(tmp_path) -> None:
    path = tmp_path / "installed-channel-supervisor.json"
    store = InstalledChannelSupervisorConfigStore(path)
    first = store.create(
        engine_port=43123,
        feishu_app_id="cli_test_app_id",
        feishu_app_secret="synthetic-feishu-secret-value",
    )

    updated = store.update_feishu_credentials(
        expected_generation=1,
        feishu_app_id="cli_replaced_app_id",
        feishu_app_secret="synthetic-replaced-feishu-secret",
    )

    assert updated.generation == 2
    assert updated.feishu_app_id == "cli_replaced_app_id"
    assert updated.feishu_app_secret == "synthetic-replaced-feishu-secret"
    assert updated.engine_port == first.engine_port
    for name in (
        "runtime_key",
        "approval_key",
        "paid_media_key",
        "weixin_bridge_key",
        "feishu_bridge_key",
    ):
        assert getattr(updated, name) != getattr(first, name)
    with pytest.raises(InstalledChannelConfigConflict, match="generation changed"):
        store.update_feishu_credentials(
            expected_generation=1,
            feishu_app_id="cli_stale_app_id",
            feishu_app_secret="synthetic-stale-feishu-secret",
        )
