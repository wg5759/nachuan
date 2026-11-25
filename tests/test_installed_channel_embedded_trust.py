from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gateway.installed_channel_embedded_trust import (
    InstalledChannelEmbeddedTrustError,
    PRODUCTION_EMBEDDED_TRUST_SHA256,
    load_installed_channel_embedded_trust,
)
from gateway.installed_channel_supervisor_entrypoint import run_embedded_trust_gate


def test_repository_embedded_trust_has_the_production_public_identity() -> None:
    path = Path("config/installed-channel-supervisor-trust.v1.json").resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        PRODUCTION_EMBEDDED_TRUST_SHA256
    )
    trust = load_installed_channel_embedded_trust(
        path,
        expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )

    assert trust.enabled is True
    assert trust.signer_key_id == (
        "881f71d8ae177eb2bbb793c8ec5fa05319897fa531a4776fe928894ad1730ba9"
    )
    assert trust.minimum_installer_release_sequence == 0
    assert trust.minimum_keyring_sequence == 0
    assert trust.require_verifier() is not None
    continued: list[object] = []
    result = run_embedded_trust_gate(
        Path("config/installed-channel-supervisor-trust.v1.json").resolve(),
        continuation=lambda enabled: continued.append(enabled) or 42,
    )
    assert result == 42
    assert len(continued) == 1


def test_embedded_trust_rejects_a_different_frozen_asset_digest() -> None:
    path = Path("config/installed-channel-supervisor-trust.v1.json").resolve()

    with pytest.raises(
        InstalledChannelEmbeddedTrustError,
        match="digest differs from frozen policy",
    ):
        load_installed_channel_embedded_trust(
            path,
            expected_sha256="0" * 64,
        )


def test_disabled_embedded_trust_fails_before_continuation(tmp_path) -> None:
    path = (tmp_path / "installed-channel-supervisor-trust.v1.json").resolve()
    path.write_bytes(
        b'{"algorithm":"ed25519","enabled":false,'
        b'"minimum_installer_release_sequence":0,"minimum_keyring_sequence":0,'
        b'"public_key_spki_base64":"",'
        b'"schema":"nachuan.installed-channel-supervisor-embedded-trust.v1",'
        b'"signer_key_id":""}\n'
    )
    trust = load_installed_channel_embedded_trust(path)
    assert trust.enabled is False
    with pytest.raises(
        InstalledChannelEmbeddedTrustError,
        match="production trust root is disabled",
    ):
        trust.require_verifier()
    continued: list[object] = []
    assert run_embedded_trust_gate(
        path,
        continuation=lambda enabled: continued.append(enabled) or 0,
    ) == 69
    assert continued == []


def test_enabled_embedded_trust_verifies_spki_identity_and_floors(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = hashlib.sha256(public_der).hexdigest()
    document = {
        "algorithm": "ed25519",
        "enabled": True,
        "minimum_installer_release_sequence": 7,
        "minimum_keyring_sequence": 3,
        "public_key_spki_base64": base64.b64encode(public_der).decode("ascii"),
        "schema": "nachuan.installed-channel-supervisor-embedded-trust.v1",
        "signer_key_id": key_id,
    }
    path = (tmp_path / "installed-channel-supervisor-trust.v1.json").resolve()
    path.write_bytes(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
        + b"\n"
    )

    trust = load_installed_channel_embedded_trust(path)
    payload = b'{"release_policy":"test"}'
    signature = private_key.sign(
        b"nachuan-installed-channel-release-policy-v1\0" + payload
    )

    assert trust.enabled is True
    assert trust.signer_key_id == key_id
    assert trust.minimum_installer_release_sequence == 7
    assert trust.minimum_keyring_sequence == 3
    assert trust.require_verifier().verify(payload, signature) is True
    assert not hasattr(trust, "anchor_dependencies")
    continued: list[object] = []
    result = run_embedded_trust_gate(
        path,
        continuation=lambda enabled: continued.append(enabled) or 42,
    )
    assert result == 42
    assert len(continued) == 1
    assert continued[0].enabled is True
    assert continued[0].signer_key_id == trust.signer_key_id
