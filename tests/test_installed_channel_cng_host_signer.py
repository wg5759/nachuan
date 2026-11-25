from __future__ import annotations

import os
import uuid

import pytest

from gateway.installation_root import (
    ComponentState,
    InstallationRootSnapshot,
    UpdaterState,
    installation_principal,
)
from gateway.installed_channel_cng_host_signer import (
    InstalledChannelCngHostSignerError,
    WindowsCngHostSignerStore,
)


def _snapshot(seed: str) -> InstallationRootSnapshot:
    installation_id = seed * 64
    epoch = 3
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest="f" * 64,
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
        components=tuple(
            ComponentState(
                component=name,
                identity=f"{index + 10:064x}",
                epoch=epoch,
                bound=True,
                sequence_floor=0,
                state_digest=f"{index + 20:064x}",
                recovery_floor=None,
                recovery_state_digest=None,
            )
            for index, name in enumerate(
                ("desktop", "gateway", "gateway_assets", "channel_media")
            )
        ),
        updater=UpdaterState(
            release_sequence=5,
            keyring_sequence=2,
            artifact_digest="a" * 64,
            state_digest="b" * 64,
        ),
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows CNG host signer")
def test_cng_host_signer_is_machine_unique_persistent_and_nonexportable() -> None:
    prefix = "NachuanTestHostSigner-" + uuid.uuid4().hex
    stores = [
        WindowsCngHostSignerStore(
            key_prefix=prefix,
            machine_scope=True,
            provider="Microsoft Software Key Storage Provider",
            hardware_backed=False,
            test_only_allow_delete=True,
        )
        for _ in range(2)
    ]
    snapshots = (_snapshot("5"), _snapshot("6"))
    signers = []
    try:
        first = stores[0].open_or_create(
            installation_snapshot=snapshots[0],
            allow_create=True,
        )
        reopened = stores[0].open_or_create(
            installation_snapshot=snapshots[0],
            allow_create=False,
        )
        second = stores[1].open_or_create(
            installation_snapshot=snapshots[1],
            allow_create=True,
        )
        signers.extend((first, reopened, second))
        payload = b"nachuan-host-anchor-test"
        signature = first.sign(payload)

        assert first.key_id == reopened.key_id
        assert first.public_key_spki_der == reopened.public_key_spki_der
        assert first.key_id != second.key_id
        assert first.algorithm == "ecdsa-p256-sha256"
        assert first.hardware_backed is False
        assert first.private_acl_verified is True
        assert first.verify(payload, signature) is True
        assert first.verify(payload + b"!", signature) is False
        assert first.private_export_blocked() is True
        assert second.private_export_blocked() is True
    finally:
        for signer in signers:
            signer.close()
        stores[0].delete_for_test_only(snapshots[0])
        stores[1].delete_for_test_only(snapshots[1])
    for store, snapshot in zip(stores, snapshots, strict=True):
        with pytest.raises(
            InstalledChannelCngHostSignerError,
            match="host signer is unavailable",
        ):
            store.open_or_create(
                installation_snapshot=snapshot,
                allow_create=False,
            )
