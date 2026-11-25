from __future__ import annotations

import hashlib
import json
import os

import pytest

from gateway.installed_channel_embedded_trust import (
    load_installed_channel_embedded_trust,
)
from gateway.installed_channel_release_authority import (
    Ed25519ReleasePolicyVerifier,
    InstalledChannelReleaseAuthorityConflict,
    InstalledChannelReleaseAuthorityStore,
)


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI release authority")
def test_release_authority_is_dpapi_persistent_and_never_overwritten(tmp_path) -> None:
    path = (
        tmp_path
        / "release-authority"
        / "installer-anchor-signing-key.protected.json"
    ).resolve()
    store = InstalledChannelReleaseAuthorityStore(path)

    created = store.initialize()
    envelope_before = path.read_bytes()
    loaded = InstalledChannelReleaseAuthorityStore(path).load()
    payload = b'{"schema":"test-installer-anchor"}'
    signature = loaded.sign_release_policy(payload)

    assert loaded.key_id == created.key_id
    assert loaded.public_key_spki_der == created.public_key_spki_der
    assert Ed25519ReleasePolicyVerifier(
        loaded.public_key_spki_der
    ).verify(payload, signature)
    assert not hasattr(loaded, "sign")
    assert created.key_id.encode("ascii") not in envelope_before
    with pytest.raises(
        InstalledChannelReleaseAuthorityConflict,
        match="already exists",
    ):
        store.initialize()
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(
        envelope_before
    ).digest()

    trust_path = (
        tmp_path / "config" / "installed-channel-supervisor-trust.v1.json"
    ).resolve()
    trust_path.parent.mkdir()
    trust_path.write_bytes(
        json.dumps(
            created.embedded_trust_document(
                minimum_installer_release_sequence=7,
                minimum_keyring_sequence=3,
            ),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    trust = load_installed_channel_embedded_trust(trust_path)
    assert trust.enabled is True
    assert trust.signer_key_id == created.key_id
    assert trust.minimum_installer_release_sequence == 7
    assert trust.minimum_keyring_sequence == 3
