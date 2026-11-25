from __future__ import annotations

import os

import pytest

from gateway.installed_channel_supervisor import InstalledChannelEpochAnchor
from gateway.installation_root import installation_principal
from gateway.installed_channel_supervisor_control import (
    InstalledChannelControlConflict,
    InstalledChannelControlError,
    InstalledChannelSupervisorControlStore,
)


def _anchor(*, epoch: int = 4, config_generation: int = 7) -> InstalledChannelEpochAnchor:
    installation_id = "a" * 64
    principal = installation_principal(installation_id, epoch)
    return InstalledChannelEpochAnchor(
        installation_id=installation_id,
        installation_epoch=epoch,
        installation_principal=principal,
        config_generation=config_generation,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI control store")
def test_stop_latch_survives_reopen_and_uses_generation_cas(tmp_path) -> None:
    path = (tmp_path / "installed-channel-supervisor-control.json").resolve()
    created = InstalledChannelSupervisorControlStore(path).initialize(anchor=_anchor())
    assert created.control_generation == 1
    assert created.stop_requested is False

    stopped = InstalledChannelSupervisorControlStore(path).request_stop(
        anchor=_anchor(), expected_control_generation=1
    )
    assert stopped.control_generation == 2
    assert stopped.stop_requested is True

    reopened = InstalledChannelSupervisorControlStore(path)
    assert reopened.load(anchor=_anchor()) == stopped
    with pytest.raises(
        InstalledChannelControlConflict, match="control generation changed"
    ):
        reopened.request_resume(anchor=_anchor(), expected_control_generation=1)
    assert reopened.load(anchor=_anchor()) == stopped


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI control store")
def test_control_store_rejects_anchor_drift_and_ciphertext_tamper(tmp_path) -> None:
    path = (tmp_path / "installed-channel-supervisor-control.json").resolve()
    store = InstalledChannelSupervisorControlStore(path)
    store.initialize(anchor=_anchor())

    with pytest.raises(
        InstalledChannelControlConflict,
        match="differs from installation anchor",
    ):
        store.load(anchor=_anchor(epoch=5))

    encoded = path.read_bytes()
    path.write_bytes(encoded[: len(encoded) // 2] + b"!" + encoded[len(encoded) // 2 + 1 :])
    with pytest.raises(InstalledChannelControlError, match="unavailable"):
        store.load(anchor=_anchor())
