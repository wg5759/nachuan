from __future__ import annotations

import hashlib
import json

import pytest

from gateway.subscription_cli_discovery import (
    SubscriptionCliDiscovery,
    VersionProbeRequest,
    VersionProbeResult,
)


def test_discovery_ignores_path_and_requires_explicit_attestation(tmp_path) -> None:
    shim = tmp_path / "codex.cmd"
    shim.write_text("@echo fake codex", encoding="utf-8")
    probe_calls: list[object] = []

    discovery = SubscriptionCliDiscovery(
        environment={"PATH": str(tmp_path)},
        version_probe=lambda request: probe_calls.append(request),
    )

    assert discovery.list_public() == [
        {
            "id": "codex",
            "label": "Codex",
            "state": "not_installed",
            "auth": "device_code",
            "transport": "stdio_jsonl",
            "version": None,
            "capabilities": ["chat", "code"],
            "login_supported": True,
            "logout_supported": True,
        },
        {
            "id": "kimi-code",
            "label": "Kimi Code",
            "state": "not_installed",
            "auth": "device_code",
            "transport": "acp_stdio",
            "version": None,
            "capabilities": ["chat", "code"],
            "login_supported": True,
            "logout_supported": False,
        },
    ]
    assert probe_calls == []


def _fake_pe(marker: bytes) -> bytes:
    payload = bytearray(128)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\0\0"
    payload[80 : 80 + len(marker)] = marker
    return bytes(payload)


def test_attested_pe_without_a_worker_probe_stays_installed_unprobed(tmp_path) -> None:
    codex = (tmp_path / "codex.exe").resolve()
    codex.write_bytes(_fake_pe(b"codex"))
    environment = {
        "CODEX_CLI_PATH": str(codex),
        "CODEX_CLI_SHA256": hashlib.sha256(codex.read_bytes()).hexdigest(),
    }

    public = SubscriptionCliDiscovery(environment=environment).list_public()

    assert public[0]["state"] == "installed_unprobed"
    assert public[0]["version"] is None


def test_attested_pe_versions_are_public_without_claiming_authentication(tmp_path) -> None:
    codex = (tmp_path / "codex.exe").resolve()
    kimi = (tmp_path / "kimi.exe").resolve()
    codex.write_bytes(_fake_pe(b"codex"))
    kimi.write_bytes(_fake_pe(b"kimi"))
    environment = {
        "CODEX_CLI_PATH": str(codex),
        "CODEX_CLI_SHA256": hashlib.sha256(codex.read_bytes()).hexdigest(),
        "KIMI_CLI_PATH": str(kimi),
        "KIMI_CLI_SHA256": hashlib.sha256(kimi.read_bytes()).hexdigest(),
    }
    requests: list[VersionProbeRequest] = []

    def fake_probe(request: VersionProbeRequest) -> VersionProbeResult:
        requests.append(request)
        if request.connector_id == "codex":
            return VersionProbeResult(
                returncode=0,
                stdout="codex-cli 0.144.5 token=do-not-return",
                stderr="",
            )
        return VersionProbeResult(
            returncode=0,
            stdout="kimi 0.27.0",
            stderr="credential_path=C:\\secret",
        )

    public = SubscriptionCliDiscovery(
        environment=environment,
        version_probe=fake_probe,
    ).list_public()

    assert [(item["id"], item["state"], item["version"]) for item in public] == [
        ("codex", "installed_unprobed", "0.144.5"),
        ("kimi-code", "installed_unprobed", "0.27.0"),
    ]
    assert [request.argv for request in requests] == [("--version",), ("--version",)]
    assert str(codex) not in repr(requests[0])
    assert environment["CODEX_CLI_SHA256"] not in repr(requests[0])
    serialized = json.dumps(public).lower()
    for forbidden in (
        str(tmp_path).lower(),
        "sha256",
        "token",
        "credential_path",
        "stdout",
        "stderr",
    ):
        assert forbidden not in serialized


def test_kimi_official_version_probe_accepts_bare_semver(tmp_path) -> None:
    kimi = (tmp_path / "kimi.exe").resolve()
    kimi.write_bytes(_fake_pe(b"kimi"))
    environment = {
        "KIMI_CLI_PATH": str(kimi),
        "KIMI_CLI_SHA256": hashlib.sha256(kimi.read_bytes()).hexdigest(),
    }

    public = SubscriptionCliDiscovery(
        environment=environment,
        version_probe=lambda _request: VersionProbeResult(
            returncode=0,
            stdout="0.27.0\n",
            stderr="",
        ),
    ).list_public()

    assert public[1]["state"] == "installed_unprobed"
    assert public[1]["version"] == "0.27.0"


def test_version_probe_rejects_a_banner_from_the_wrong_cli(tmp_path) -> None:
    codex = (tmp_path / "codex.exe").resolve()
    codex.write_bytes(_fake_pe(b"codex"))
    environment = {
        "CODEX_CLI_PATH": str(codex),
        "CODEX_CLI_SHA256": hashlib.sha256(codex.read_bytes()).hexdigest(),
    }

    public = SubscriptionCliDiscovery(
        environment=environment,
        version_probe=lambda _request: VersionProbeResult(
            returncode=0,
            stdout="some-other-cli 9.9.9",
            stderr="",
        ),
    ).list_public()

    assert public[0]["state"] == "unavailable"
    assert public[0]["version"] is None


@pytest.mark.parametrize("suffix", [".cmd", ".ps1"])
def test_script_shims_are_untrusted_even_with_an_exact_hash(tmp_path, suffix) -> None:
    shim = (tmp_path / f"codex{suffix}").resolve()
    shim.write_text("Write-Output 'codex-cli 0.144.5'", encoding="utf-8")
    probe_calls: list[VersionProbeRequest] = []
    environment = {
        "CODEX_CLI_PATH": str(shim),
        "CODEX_CLI_SHA256": hashlib.sha256(shim.read_bytes()).hexdigest(),
    }

    public = SubscriptionCliDiscovery(
        environment=environment,
        version_probe=lambda request: probe_calls.append(request),
    ).list_public()

    assert public[0]["state"] == "untrusted_binary"
    assert public[0]["version"] is None
    assert probe_calls == []


def test_exe_extension_without_a_pe_image_is_untrusted(tmp_path) -> None:
    shim = (tmp_path / "codex.exe").resolve()
    shim.write_bytes(b"not a native PE image")
    environment = {
        "CODEX_CLI_PATH": str(shim),
        "CODEX_CLI_SHA256": hashlib.sha256(shim.read_bytes()).hexdigest(),
    }

    public = SubscriptionCliDiscovery(environment=environment).list_public()

    assert public[0]["state"] == "untrusted_binary"
    assert public[0]["version"] is None


def test_old_attested_cli_maps_to_version_unsupported(tmp_path) -> None:
    kimi = (tmp_path / "kimi.exe").resolve()
    kimi.write_bytes(_fake_pe(b"kimi"))
    environment = {
        "KIMI_CLI_PATH": str(kimi),
        "KIMI_CLI_SHA256": hashlib.sha256(kimi.read_bytes()).hexdigest(),
    }

    public = SubscriptionCliDiscovery(
        environment=environment,
        version_probe=lambda _request: VersionProbeResult(
            returncode=0,
            stdout="kimi 0.26.9",
            stderr="token=do-not-return",
        ),
    ).list_public()

    assert public[1]["state"] == "version_unsupported"
    assert public[1]["version"] == "0.26.9"
    assert "token" not in json.dumps(public).lower()
