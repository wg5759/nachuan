from __future__ import annotations

import os

import pytest

from gateway.installation_root import installation_principal
from gateway.installed_channel_supervisor import InstalledChannelEpochAnchor
from gateway.installed_channel_supervisor_control import (
    InstalledChannelSupervisorControlStore,
)
from gateway.installed_channel_supervisor_status import (
    InstalledChannelProcessReceipt,
    InstalledChannelStatusConflict,
    InstalledChannelStatusError,
    InstalledChannelSupervisorStatusStore,
)


def _anchor() -> InstalledChannelEpochAnchor:
    installation_id = "b" * 64
    epoch = 9
    return InstalledChannelEpochAnchor(
        installation_id=installation_id,
        installation_epoch=epoch,
        installation_principal=installation_principal(installation_id, epoch),
        config_generation=11,
    )


def _process(seed: int) -> InstalledChannelProcessReceipt:
    return InstalledChannelProcessReceipt(
        pid=1000 + seed,
        started_utc_ticks=132_000_000_000_000_000 + seed,
        command_line_sha256=f"{seed:064x}",
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI status store")
def test_status_receipt_binds_process_identities_and_control_generation(tmp_path) -> None:
    anchor = _anchor()
    control_path = (tmp_path / "installed-channel-supervisor-control.json").resolve()
    control = InstalledChannelSupervisorControlStore(control_path).initialize(anchor=anchor)
    status_path = (tmp_path / "installed-channel-supervisor-status.json").resolve()
    store = InstalledChannelSupervisorStatusStore(status_path)

    published = store.publish(
        anchor=anchor,
        control=control,
        expected_status_generation=0,
        supervisor=_process(1),
        roles={
            "engine": _process(2),
            "weixin": _process(3),
            "feishu": _process(4),
        },
        state="ready",
        restart_attempt=0,
    )

    assert published.status_generation == 1
    assert published.control_generation == control.control_generation
    assert published.ready is True
    assert tuple(published.roles) == ("engine", "weixin", "feishu")
    assert InstalledChannelSupervisorStatusStore(status_path).load(anchor=anchor) == published
    with pytest.raises(InstalledChannelStatusConflict, match="status generation changed"):
        store.publish(
            anchor=anchor,
            control=control,
            expected_status_generation=0,
            supervisor=_process(1),
            roles=published.roles,
            state="ready",
            restart_attempt=0,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI status store")
def test_stop_latch_cannot_be_published_as_ready_and_status_tamper_fails(tmp_path) -> None:
    anchor = _anchor()
    control_path = (tmp_path / "installed-channel-supervisor-control.json").resolve()
    control_store = InstalledChannelSupervisorControlStore(control_path)
    control_store.initialize(anchor=anchor)
    stopped = control_store.request_stop(
        anchor=anchor, expected_control_generation=1
    )
    status_path = (tmp_path / "installed-channel-supervisor-status.json").resolve()
    store = InstalledChannelSupervisorStatusStore(status_path)

    with pytest.raises(InstalledChannelStatusError, match="ready status is invalid"):
        store.publish(
            anchor=anchor,
            control=stopped,
            expected_status_generation=0,
            supervisor=_process(1),
            roles={
                "engine": _process(2),
                "weixin": _process(3),
                "feishu": _process(4),
            },
            state="ready",
            restart_attempt=0,
        )
    assert status_path.exists() is False

    published = store.publish(
        anchor=anchor,
        control=stopped,
        expected_status_generation=0,
        supervisor=_process(1),
        roles={},
        state="stopped",
        restart_attempt=0,
    )
    assert published.ready is False
    assert published.stop_requested is True

    encoded = status_path.read_bytes()
    status_path.write_bytes(encoded[:-1] + b"!")
    with pytest.raises(InstalledChannelStatusError, match="unavailable"):
        store.load(anchor=anchor)


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI status store")
def test_status_store_rejects_a_wall_clock_rollback(tmp_path) -> None:
    anchor = _anchor()
    control_path = (tmp_path / "installed-channel-supervisor-control.json").resolve()
    control = InstalledChannelSupervisorControlStore(control_path).initialize(anchor=anchor)
    status_path = (tmp_path / "installed-channel-supervisor-status.json").resolve()
    store = InstalledChannelSupervisorStatusStore(
        status_path, wall_clock_ns=iter((100, 99)).__next__
    )
    first = store.publish(
        anchor=anchor,
        control=control,
        expected_status_generation=0,
        supervisor=_process(1),
        roles={"engine": _process(2), "weixin": _process(3), "feishu": _process(4)},
        state="ready",
        restart_attempt=0,
    )

    with pytest.raises(InstalledChannelStatusConflict, match="clock moved backwards"):
        store.publish(
            anchor=anchor,
            control=control,
            expected_status_generation=1,
            supervisor=_process(1),
            roles=first.roles,
            state="ready",
            restart_attempt=0,
        )
    assert InstalledChannelSupervisorStatusStore(status_path).load(anchor=anchor) == first


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI status store")
def test_safe_status_requires_a_fresh_identity_receipt(tmp_path) -> None:
    anchor = _anchor()
    control_path = (tmp_path / "installed-channel-supervisor-control.json").resolve()
    control = InstalledChannelSupervisorControlStore(control_path).initialize(anchor=anchor)
    status_path = (tmp_path / "installed-channel-supervisor-status.json").resolve()
    InstalledChannelSupervisorStatusStore(
        status_path, wall_clock_ns=lambda: 100
    ).publish(
        anchor=anchor,
        control=control,
        expected_status_generation=0,
        supervisor=_process(1),
        roles={"engine": _process(2), "weixin": _process(3), "feishu": _process(4)},
        state="ready",
        restart_attempt=0,
    )

    fresh = InstalledChannelSupervisorStatusStore(
        status_path, wall_clock_ns=lambda: 150
    ).safe_status(anchor=anchor, maximum_age_ns=100)
    assert fresh["fresh"] is True
    assert fresh["ready"] is True
    assert fresh["role_pids"] == {"engine": 1002, "weixin": 1003, "feishu": 1004}

    stale = InstalledChannelSupervisorStatusStore(
        status_path, wall_clock_ns=lambda: 250
    ).safe_status(anchor=anchor, maximum_age_ns=100)
    assert stale["fresh"] is False
    assert stale["ready"] is False
