from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nachuan_sdk import (
    IsolatedTransformPluginSpecV1,
    build_signed_transform_bundle,
    default_isolated_limits,
)
from orchestrator.isolated_plugin import verify_isolated_plugin_bundle
from orchestrator.isolated_plugin import IsolatedPluginContractError, IsolatedPluginLimits


def _spec() -> IsolatedTransformPluginSpecV1:
    return IsolatedTransformPluginSpecV1(
        plugin_id="com.example.sdk-demo",
        version="1.0.0",
        publisher_key_id="example.publisher",
        license="Apache-2.0",
        limits=default_isolated_limits(),
    )


def test_sdk_builds_the_exact_runtime_verified_three_file_bundle(tmp_path) -> None:
    private = Ed25519PrivateKey.generate()
    source = b"def handle(value):\n    return value\n"
    root = tmp_path / "bundle"

    receipt = build_signed_transform_bundle(
        root,
        spec=_spec(),
        plugin_source=source,
        private_key=private,
    )
    bundle = verify_isolated_plugin_bundle(
        root,
        trusted_publishers={
            "example.publisher": private.public_key().public_bytes_raw()
        },
    )

    assert {item.name for item in root.iterdir()} == {
        "manifest.json",
        "plugin.py",
        "sbom.json",
    }
    assert receipt.files == ("manifest.json", "plugin.py", "sbom.json")
    assert receipt.artifact_sha256 == bundle.manifest.artifact_sha256
    assert receipt.sbom_sha256 == bundle.manifest.sbom_sha256
    assert receipt.as_mapping()["schema"] == "nachuan.sdk.bundle-build-receipt.v1"


def test_sdk_output_is_deterministic_and_never_serializes_the_private_key(tmp_path) -> None:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    source = b"def handle(value):\n    return {'ok': True}\n"
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_receipt = build_signed_transform_bundle(
        first,
        spec=_spec(),
        plugin_source=source,
        private_key=private,
    )
    second_receipt = build_signed_transform_bundle(
        second,
        spec=_spec(),
        plugin_source=source,
        private_key=private,
    )

    assert first_receipt == second_receipt
    for name in first_receipt.files:
        first_bytes = (first / name).read_bytes()
        assert first_bytes == (second / name).read_bytes()
        assert private_bytes not in first_bytes
    manifest = json.loads((first / "manifest.json").read_text("ascii"))
    assert set(manifest) == {
        "schema",
        "id",
        "version",
        "api_version",
        "execution",
        "capabilities",
        "entrypoint",
        "artifact_sha256",
        "sbom_sha256",
        "publisher_key_id",
        "limits",
        "signature",
    }


def test_sdk_refuses_overwrite_non_utf8_and_invalid_identity(tmp_path) -> None:
    private = Ed25519PrivateKey.generate()
    destination = tmp_path / "bundle"
    destination.mkdir()
    with pytest.raises(FileExistsError):
        build_signed_transform_bundle(
            destination,
            spec=_spec(),
            plugin_source=b"def handle(value):\n    return value\n",
            private_key=private,
        )
    with pytest.raises(ValueError, match="UTF-8"):
        build_signed_transform_bundle(
            tmp_path / "bad-source",
            spec=_spec(),
            plugin_source=b"\xff",
            private_key=private,
        )
    with pytest.raises(ValueError, match="plugin id"):
        IsolatedTransformPluginSpecV1(
            plugin_id="Bad Id",
            version="1.0.0",
            publisher_key_id="example.publisher",
            license="Apache-2.0",
            limits=default_isolated_limits(),
        )
    with pytest.raises(IsolatedPluginContractError, match="limit"):
        IsolatedTransformPluginSpecV1(
            plugin_id="com.example.sdk-demo",
            version="1.0.0",
            publisher_key_id="example.publisher",
            license="Apache-2.0",
            limits=IsolatedPluginLimits(
                timeout_ms=1,
                cpu_time_ms=1,
                memory_bytes=1,
                max_request_bytes=1,
                max_response_bytes=1,
            ),
        )
