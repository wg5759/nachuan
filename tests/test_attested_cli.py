from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.providers.attested_cli import file_sha256, from_environment, matches_attestation


def test_cli_attestation_requires_absolute_executable_and_exact_hash(
    monkeypatch, tmp_path
) -> None:
    executable = (tmp_path / "claude.exe").resolve()
    executable.write_bytes(b"reviewed executable")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    monkeypatch.setenv("CLAUDE_CLI_PATH", str(executable))
    monkeypatch.setenv("CLAUDE_CLI_SHA256", digest)
    attested = from_environment("CLAUDE_CLI_PATH", "CLAUDE_CLI_SHA256")
    assert attested is not None and attested.path == str(executable)

    executable.write_bytes(b"changed after startup")
    assert not matches_attestation(str(executable), digest)


def test_cli_attestation_rejects_script_shims_and_relative_paths(
    monkeypatch, tmp_path
) -> None:
    script = (tmp_path / "claude.cmd").resolve()
    script.write_text("@node mutable-target.js", encoding="utf-8")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    monkeypatch.setenv("CLAUDE_CLI_PATH", str(script))
    monkeypatch.setenv("CLAUDE_CLI_SHA256", digest)
    assert from_environment("CLAUDE_CLI_PATH", "CLAUDE_CLI_SHA256") is None

    monkeypatch.setenv("CLAUDE_CLI_PATH", "claude.exe")
    assert from_environment("CLAUDE_CLI_PATH", "CLAUDE_CLI_SHA256") is None


def test_cli_attestation_rejects_symlink(monkeypatch, tmp_path) -> None:
    target = tmp_path / "target.exe"
    target.write_bytes(b"target")
    link = tmp_path / "claude.exe"
    try:
        link.symlink_to(target)
    except OSError:
        return  # Windows may deny symlink creation to an unprivileged test process.
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    monkeypatch.setenv("CLAUDE_CLI_PATH", str(link.absolute()))
    monkeypatch.setenv("CLAUDE_CLI_SHA256", digest)
    assert from_environment("CLAUDE_CLI_PATH", "CLAUDE_CLI_SHA256") is None


def test_cli_hash_enforces_size_bound_while_streaming(monkeypatch, tmp_path) -> None:
    executable = (tmp_path / "growing.exe").resolve()
    executable.write_bytes(b"x" * 64)
    real_stat = Path.stat

    def stale_small_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path == executable:
            return SimpleNamespace(st_size=1)
        return result

    monkeypatch.setattr(Path, "stat", stale_small_stat)
    with pytest.raises(OSError, match="grew beyond"):
        file_sha256(executable, max_bytes=8)
