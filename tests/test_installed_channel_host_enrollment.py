from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from gateway.installation_root import (
    ComponentState,
    InstallationRootSnapshot,
    UpdaterState,
    installation_principal,
)
from gateway.installed_channel_host_enrollment import (
    InstalledChannelHostSignerEnrollmentStore,
)
from gateway.installed_channel_host_anchor import InstalledChannelHostAnchorStore


def _snapshot(seed: str) -> InstallationRootSnapshot:
    installation_id = seed * 64
    epoch = 2
    components = tuple(
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
    )
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest="f" * 64,
        epoch=epoch,
        root_revision=8,
        status="active",
        lock_kind="none",
        lock_reason_digest=None,
        reanchor_pending=False,
        reanchor_operation_digest=None,
        reanchor_snapshot_digest=None,
        reanchor_source_epoch=None,
        principal_digest=installation_principal(installation_id, epoch),
        components=components,
        updater=UpdaterState(
            release_sequence=4,
            keyring_sequence=2,
            artifact_digest="a" * 64,
            state_digest="b" * 64,
        ),
    )


class _HostSigner:
    algorithm = "ecdsa-p256-sha256"
    provider = "test-software-ksp"
    hardware_backed = False

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_spki_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = hashlib.sha256(self.public_key_spki_der).hexdigest()

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload, ec.ECDSA(hashes.SHA256()))

    @property
    def private_scalar_bytes(self) -> bytes:
        value = self._key.private_numbers().private_value
        return value.to_bytes(32, "big")


def test_each_clean_install_enrolls_a_unique_host_signer_without_release_private_key(
    tmp_path: Path,
) -> None:
    receipts = []
    raw_documents = []
    for name, seed in (("host-a", "1"), ("host-b", "2")):
        boundary = (tmp_path / name / "InstallerTrust").resolve()
        boundary.mkdir(parents=True)
        signer = _HostSigner()
        snapshot = _snapshot(seed)
        store = InstalledChannelHostSignerEnrollmentStore(
            boundary / "installed-channel-supervisor.host-enrollment.json",
            trusted_boundary=boundary,
            assert_installer_acl=lambda _path, _directory: None,
        )
        first, created = store.create_if_absent(
            installation_snapshot=snapshot,
            signer=signer,
            embedded_trust_sha256="c" * 64,
            harden_installer_acl=lambda _path, _directory: None,
        )
        before = store.path.read_bytes()
        second, replay_created = store.create_if_absent(
            installation_snapshot=snapshot,
            signer=signer,
            embedded_trust_sha256="c" * 64,
            harden_installer_acl=lambda _path, _directory: None,
        )

        assert created is True
        assert replay_created is False
        assert second == first
        assert store.path.read_bytes() == before
        assert first.installation_id == snapshot.installation_id
        assert first.key_id == signer.key_id
        assert first.hardware_backed is False
        assert first.verify(b"host-local-anchor", signer.sign(b"host-local-anchor"))
        assert signer.private_scalar_bytes not in before
        assert "private" not in json.loads(before)["schema"]
        receipts.append(first)
        raw_documents.append(before)

    assert receipts[0].key_id != receipts[1].key_id
    assert raw_documents[0] != raw_documents[1]
    assert not (tmp_path / "release-authority").exists()


def test_host_anchor_v2_binds_enrollment_and_rejects_cross_install_copy(
    tmp_path: Path,
) -> None:
    hosts = []
    for name, seed in (("host-a", "3"), ("host-b", "4")):
        root = (tmp_path / name).resolve()
        boundary = root / "InstallerTrust"
        user_data = root / "user-data"
        boundary.mkdir(parents=True)
        user_data.mkdir()
        snapshot = _snapshot(seed)
        signer = _HostSigner()
        enrollment_store = InstalledChannelHostSignerEnrollmentStore(
            boundary / "installed-channel-supervisor.host-enrollment.json",
            trusted_boundary=boundary,
            assert_installer_acl=lambda _path, _directory: None,
        )
        enrollment, _created = enrollment_store.create_if_absent(
            installation_snapshot=snapshot,
            signer=signer,
            embedded_trust_sha256="d" * 64,
            harden_installer_acl=lambda _path, _directory: None,
        )
        config = user_data / "installed-channel-supervisor.json"
        verification_key = user_data / (
            "installed-channel-supervisor.json.verification-key"
        )
        config.write_bytes(b"protected-config-envelope")
        verification_key.write_bytes(b"protected-verification-key-envelope")
        anchor_store = InstalledChannelHostAnchorStore(
            boundary / "installed-channel-supervisor.anchor.json",
            trusted_boundary=boundary,
            user_config_boundary=user_data,
            assert_installer_acl=lambda _path, _directory: None,
            assert_user_acl=lambda _path, _directory: None,
        )
        anchor, created = anchor_store.create_if_absent(
            installation_snapshot=snapshot,
            config_generation=1,
            config_path=config,
            verification_key_path=verification_key,
            enrollment=enrollment,
            signer=signer,
            harden_installer_acl=lambda _path, _directory: None,
        )
        assert created is True
        assert anchor.host_signer_key_id == enrollment.key_id
        assert anchor.host_enrollment_sha256 == enrollment.document_sha256
        assert anchor_store.load(
            installation_snapshot=snapshot,
            config_path=config,
            verification_key_path=verification_key,
            enrollment=enrollment,
        ) == anchor
        hosts.append(
            (
                snapshot,
                enrollment,
                config,
                verification_key,
                anchor_store,
            )
        )

    copied = hosts[0][4].path.read_bytes()
    hosts[1][4].path.write_bytes(copied)
    try:
        hosts[1][4].load(
            installation_snapshot=hosts[1][0],
            config_path=hosts[1][2],
            verification_key_path=hosts[1][3],
            enrollment=hosts[1][1],
        )
    except ValueError as error:
        assert "differs from active installation" in str(error)
    else:
        raise AssertionError("cross-installation anchor copy must fail closed")
