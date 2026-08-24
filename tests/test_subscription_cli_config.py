from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from gateway.subscription_cli_config import (
    CodexAuthenticodeIdentity,
    KimiManifestFetchResult,
    SubscriptionCliConfigError,
    bind_codex_subscription_cli,
    bind_kimi_subscription_cli,
    load_subscription_cli_environment,
    subscription_cli_config_path,
    unbind_codex_subscription_cli,
    unbind_kimi_subscription_cli,
)


def _write_fake_pe(path: Path) -> None:
    header = bytearray(512)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\0\0"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header))


def _official_identity() -> CodexAuthenticodeIdentity:
    return CodexAuthenticodeIdentity(
        publisher="OpenAI OpCo, LLC",
        signer_thumbprint="A" * 40,
        timestamp_thumbprint="B" * 40,
    )


def _kimi_manifest(
    executable: Path,
    *,
    version: str = "0.27.0",
    extra_top_level: dict[str, object] | None = None,
) -> bytes:
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    document: dict[str, object] = {
        "version": version,
        "tag": f"@moonshot-ai/kimi-code@{version}",
        "platforms": {
            "darwin-arm64": {
                "filename": "kimi-code-darwin-arm64",
                "checksum": "1" * 64,
            },
            "darwin-x64": {
                "filename": "kimi-code-darwin-x64",
                "checksum": "2" * 64,
            },
            "linux-arm64": {
                "filename": "kimi-code-linux-arm64",
                "checksum": "3" * 64,
            },
            "linux-x64": {
                "filename": "kimi-code-linux-x64",
                "checksum": "4" * 64,
            },
            "win32-arm64": {
                "filename": "kimi-code-win32-arm64.exe",
                "checksum": "5" * 64,
            },
            "win32-x64": {
                "filename": "kimi-code-win32-x64.exe",
                "checksum": digest,
            },
        },
    }
    if extra_top_level:
        document.update(extra_top_level)
    return json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _kimi_fetch_result(
    executable: Path,
    *,
    version: str = "0.27.0",
    final_url: str | None = None,
    redirect_count: int = 1,
    body: bytes | None = None,
) -> KimiManifestFetchResult:
    return KimiManifestFetchResult(
        body=body if body is not None else _kimi_manifest(executable, version=version),
        final_url=final_url
        or f"https://cdn.kimi.com/kimi-code/binaries/{version}/manifest.json",
        redirect_count=redirect_count,
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
def test_codex_binding_is_dpapi_protected_and_restores_only_public_attestation(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "official" / "codex.exe"
    _write_fake_pe(executable)

    binding = bind_codex_subscription_cli(
        tmp_path / "data",
        executable,
        authenticode_probe=lambda _path: _official_identity(),
    )

    expected_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert binding.path == str(executable.resolve(strict=True))
    assert binding.sha256 == expected_hash
    assert binding.publisher == "OpenAI OpCo, LLC"
    protected = subscription_cli_config_path(tmp_path / "data").read_bytes()
    assert str(executable).encode() not in protected
    assert expected_hash.encode() not in protected
    assert json.loads(protected)["protection"] == "windows-dpapi-current-user"
    restored = load_subscription_cli_environment(tmp_path / "data")
    assert restored == {
        "CODEX_CLI_PATH": str(executable.resolve(strict=True)),
        "CODEX_CLI_SHA256": expected_hash,
        "CODEX_CLI_TEMP_ROOT": str(
            (tmp_path / "data" / "subscription-cli-runtime").resolve(strict=True)
        ),
    }
    assert Path(restored["CODEX_CLI_TEMP_ROOT"]).is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
def test_codex_binding_rejects_non_openai_publisher_without_writing(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "fake" / "codex.exe"
    _write_fake_pe(executable)

    with pytest.raises(SubscriptionCliConfigError, match="publisher"):
        bind_codex_subscription_cli(
            tmp_path / "data",
            executable,
            authenticode_probe=lambda _path: CodexAuthenticodeIdentity(
                publisher="Not OpenAI LLC",
                signer_thumbprint="A" * 40,
                timestamp_thumbprint="B" * 40,
            ),
        )

    assert not subscription_cli_config_path(tmp_path / "data").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
def test_codex_binding_rejects_invalid_signature_metadata(tmp_path: Path) -> None:
    executable = tmp_path / "fake" / "codex.exe"
    _write_fake_pe(executable)

    with pytest.raises(SubscriptionCliConfigError, match="signature"):
        bind_codex_subscription_cli(
            tmp_path / "data",
            executable,
            authenticode_probe=lambda _path: CodexAuthenticodeIdentity(
                publisher="OpenAI OpCo, LLC",
                signer_thumbprint="not-a-thumbprint",
                timestamp_thumbprint="B" * 40,
            ),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
def test_unbind_removes_codex_from_runtime_environment(tmp_path: Path) -> None:
    executable = tmp_path / "official" / "codex.exe"
    _write_fake_pe(executable)
    data_dir = tmp_path / "data"
    bind_codex_subscription_cli(
        data_dir,
        executable,
        authenticode_probe=lambda _path: _official_identity(),
    )

    assert unbind_codex_subscription_cli(data_dir) is True
    assert load_subscription_cli_environment(data_dir) == {}
    assert unbind_codex_subscription_cli(data_dir) is False


def test_missing_binding_restores_no_environment(tmp_path: Path) -> None:
    assert load_subscription_cli_environment(tmp_path / "data") == {}


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
def test_kimi_binding_requires_official_manifest_and_uses_isolated_home(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "vendor-home" / ".kimi-code" / "bin" / "kimi.exe"
    _write_fake_pe(executable)
    data_dir = tmp_path / "data"
    requested_urls: list[str] = []

    def fetch_manifest(url: str) -> KimiManifestFetchResult:
        requested_urls.append(url)
        return _kimi_fetch_result(executable)

    binding = bind_kimi_subscription_cli(
        data_dir,
        executable,
        version="0.27.0",
        manifest_fetcher=fetch_manifest,
    )

    expected_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert requested_urls == [
        "https://code.kimi.com/kimi-code/binaries/0.27.0/manifest.json"
    ]
    assert binding.path == str(executable.resolve(strict=True))
    assert binding.sha256 == expected_hash
    assert binding.provenance == "official_https_manifest_v1"
    assert binding.version == "0.27.0"
    assert binding.platform == "win32-x64"
    assert binding.filename == "kimi-code-win32-x64.exe"
    assert binding.manifest_sha256 == hashlib.sha256(
        _kimi_manifest(executable)
    ).hexdigest()

    protected = subscription_cli_config_path(data_dir).read_bytes()
    assert str(executable).encode() not in protected
    assert expected_hash.encode() not in protected
    restored = load_subscription_cli_environment(data_dir)
    assert restored == {
        "KIMI_CLI_PATH": str(executable.resolve(strict=True)),
        "KIMI_CLI_SHA256": expected_hash,
        "KIMI_CLI_VERSION": "0.27.0",
        "KIMI_CLI_TEMP_ROOT": str(
            (
                data_dir / "subscription-cli-runtime" / "kimi-code"
            ).resolve(strict=True)
        ),
        "KIMI_CODE_HOME": str(
            (data_dir / "subscription-kimi-code-home").resolve(strict=True)
        ),
        "KIMI_DISABLE_TELEMETRY": "1",
        "KIMI_CODE_NO_AUTO_UPDATE": "1",
    }
    assert Path(restored["KIMI_CLI_TEMP_ROOT"]).is_dir()
    assert Path(restored["KIMI_CODE_HOME"]).is_dir()
    assert (
        Path(restored["KIMI_CODE_HOME"])
        != executable.parent.parent.resolve(strict=True)
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
@pytest.mark.parametrize(
    ("version", "result_factory", "message"),
    [
        (
            "0.27.0",
            lambda executable: _kimi_fetch_result(
                executable,
                final_url=(
                    "https://evil.example/kimi-code/binaries/0.27.0/manifest.json"
                ),
            ),
            "manifest",
        ),
        (
            "0.27.0",
            lambda executable: _kimi_fetch_result(
                executable,
                redirect_count=2,
            ),
            "manifest",
        ),
        (
            "0.27.0",
            lambda executable: _kimi_fetch_result(
                executable,
                body=_kimi_manifest(executable, version="0.27.1"),
            ),
            "version",
        ),
        (
            "0.27.0",
            lambda executable: _kimi_fetch_result(
                executable,
                body=_kimi_manifest(
                    executable,
                    extra_top_level={"unexpected": True},
                ),
            ),
            "manifest",
        ),
        (
            "0.27.0",
            lambda executable: _kimi_fetch_result(
                executable,
                body=_kimi_manifest(executable).replace(
                    b'{"version":"0.27.0",',
                    b'{"version":"0.27.0","version":"0.27.0",',
                    1,
                ),
            ),
            "manifest",
        ),
        (
            "0.27.0",
            lambda executable: _kimi_fetch_result(
                executable,
                body=_kimi_manifest(executable).replace(
                    hashlib.sha256(executable.read_bytes()).hexdigest().encode(),
                    b"f" * 64,
                    1,
                ),
            ),
            "checksum",
        ),
    ],
)
def test_kimi_binding_fails_closed_for_untrusted_manifest(
    tmp_path: Path,
    version: str,
    result_factory,
    message: str,
) -> None:
    executable = tmp_path / "vendor" / "kimi.exe"
    _write_fake_pe(executable)
    data_dir = tmp_path / "data"

    with pytest.raises(SubscriptionCliConfigError, match=message):
        bind_kimi_subscription_cli(
            data_dir,
            executable,
            version=version,
            manifest_fetcher=lambda _url: result_factory(executable),
        )

    assert not subscription_cli_config_path(data_dir).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows DPAPI binding")
def test_kimi_and_codex_bindings_coexist_and_kimi_unbind_is_scoped(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    codex = tmp_path / "official" / "codex.exe"
    kimi = tmp_path / "vendor-home" / ".kimi-code" / "bin" / "kimi.exe"
    _write_fake_pe(codex)
    _write_fake_pe(kimi)
    vendor_sentinel = kimi.parent.parent / "credentials" / "keep.json"
    vendor_sentinel.parent.mkdir(parents=True)
    vendor_sentinel.write_text("do-not-touch", encoding="utf-8")

    bind_codex_subscription_cli(
        data_dir,
        codex,
        authenticode_probe=lambda _path: _official_identity(),
    )
    bind_kimi_subscription_cli(
        data_dir,
        kimi,
        version="0.27.0",
        manifest_fetcher=lambda _url: _kimi_fetch_result(kimi),
    )

    both = load_subscription_cli_environment(data_dir)
    assert both["CODEX_CLI_PATH"] == str(codex.resolve(strict=True))
    assert both["KIMI_CLI_PATH"] == str(kimi.resolve(strict=True))
    assert unbind_kimi_subscription_cli(data_dir) is True
    codex_only = load_subscription_cli_environment(data_dir)
    assert codex_only["CODEX_CLI_PATH"] == str(codex.resolve(strict=True))
    assert "KIMI_CLI_PATH" not in codex_only
    assert vendor_sentinel.read_text(encoding="utf-8") == "do-not-touch"
    assert unbind_kimi_subscription_cli(data_dir) is False
