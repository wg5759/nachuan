from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.installation_root import (
    ComponentState,
    InstallationRootSnapshot,
    UpdaterState,
    installation_principal,
)
from gateway.installed_channel_installer_anchor import (
    Ed25519InstallerAnchorVerifier,
    InstalledChannelInstallerAnchorDependencies,
    InstalledChannelInstallerAnchorError,
    InstalledChannelInstallerAnchorStore,
)


def test_ed25519_installer_anchor_verifier_binds_spki_and_domain() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier = Ed25519InstallerAnchorVerifier(public_der)
    payload = b'{"schema":"test-anchor"}'
    signature = private_key.sign(
        b"nachuan-installed-channel-supervisor-anchor-v1\0" + payload
    )

    assert verifier.key_id == hashlib.sha256(public_der).hexdigest()
    assert verifier.verify(payload, signature) is True
    assert verifier.verify(payload + b"!", signature) is False


def _snapshot() -> InstallationRootSnapshot:
    installation_id = "1" * 64
    epoch = 4
    components = tuple(
        ComponentState(
            component=name,
            identity=f"{index + 2:064x}",
            epoch=epoch,
            bound=True,
            sequence_floor=0,
            state_digest=f"{index + 10:064x}",
            recovery_floor=None,
            recovery_state_digest=None,
        )
        for index, name in enumerate(
            ("desktop", "gateway", "gateway_assets", "channel_media")
        )
    )
    return InstallationRootSnapshot(
        installation_id=installation_id,
        owner_sid_digest="9" * 64,
        epoch=epoch,
        root_revision=12,
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
            release_sequence=7,
            keyring_sequence=3,
            artifact_digest="a" * 64,
            state_digest="b" * 64,
        ),
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def test_installer_anchor_binds_epoch_and_exact_protected_config_bytes(tmp_path) -> None:
    boundary = (tmp_path / "ProgramData" / "Nachuan" / "InstallerTrust").resolve()
    boundary.mkdir(parents=True)
    user_boundary = (tmp_path / "LocalAppData" / "Nachuan" / "data").resolve()
    user_boundary.mkdir(parents=True)
    config_path = user_boundary / "installed-channel-supervisor.json"
    key_path = user_boundary / "installed-channel-supervisor.json.verification-key"
    config_path.write_bytes(b"protected-config-envelope")
    key_path.write_bytes(b"protected-verification-key-envelope")
    snapshot = _snapshot()
    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier = Ed25519InstallerAnchorVerifier(public_der)
    body = {
        "schema": "nachuan.installed-channel-supervisor-installer-anchor.v1",
        "installation_id": snapshot.installation_id,
        "installation_epoch": snapshot.epoch,
        "installation_principal": snapshot.principal_digest,
        "installer_release_sequence": snapshot.updater.release_sequence,
        "installer_keyring_sequence": snapshot.updater.keyring_sequence,
        "config_generation": 5,
        "config_ciphertext_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "verification_key_ciphertext_sha256": hashlib.sha256(
            key_path.read_bytes()
        ).hexdigest(),
        "signature_algorithm": "ed25519",
        "signer_key_id": verifier.key_id,
    }
    signature = private_key.sign(
        b"nachuan-installed-channel-supervisor-anchor-v1\0" + _canonical(body)
    )
    anchor_path = boundary / "installed-channel-supervisor.anchor.json"
    anchor_path.write_text(
        json.dumps(
            {
                **body,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    installer_checked: list[tuple[str, bool]] = []
    user_checked: list[tuple[str, bool]] = []
    dependencies = InstalledChannelInstallerAnchorDependencies(
        assert_installer_acl=lambda path, directory: installer_checked.append(
            (path.name, directory)
        ),
        assert_user_acl=lambda path, directory: user_checked.append(
            (path.name, directory)
        ),
        signer_key_id=verifier.key_id,
        verify_signature=verifier.verify,
    )

    anchor = InstalledChannelInstallerAnchorStore(
        anchor_path,
        trusted_boundary=boundary,
        user_config_boundary=user_boundary,
        dependencies=dependencies,
    ).load(
        installation_snapshot=snapshot,
        config_path=config_path,
        verification_key_path=key_path,
    )

    assert anchor.config_generation == 5
    assert anchor.installation_epoch == 4
    assert anchor.installer_release_sequence == 7
    assert anchor.installer_keyring_sequence == 3
    assert installer_checked == [
        ("InstallerTrust", True),
        ("installed-channel-supervisor.anchor.json", False),
    ]
    assert user_checked == [
        ("data", True),
        ("installed-channel-supervisor.json", False),
        ("installed-channel-supervisor.json.verification-key", False),
    ]

    config_path.write_bytes(b"historical-protected-config-envelope")
    with pytest.raises(
        InstalledChannelInstallerAnchorError,
        match="differs from active installation",
    ):
        InstalledChannelInstallerAnchorStore(
            anchor_path,
            trusted_boundary=boundary,
            user_config_boundary=user_boundary,
            dependencies=dependencies,
        ).load(
            installation_snapshot=snapshot,
            config_path=config_path,
            verification_key_path=key_path,
        )
