from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.ps1"


def test_installer_has_pinned_bootstrap_and_complete_lifecycle() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    assert "$UvVersion = '0.11.3'" in source
    assert "$PythonVersion = '3.12.9'" in source
    assert "AE681C0AAEC7CC96AF184648CB88D73F8393ED60FA5880ABDD6BDB910F9B227C" in source
    assert "OPEN_SOURCE_SNAPSHOT.json" in source
    assert "Test-SnapshotClosure" in source
    assert "distribution-channels.v1.json" in source
    for action in ("Install", "Update", "Doctor", "Start", "Uninstall"):
        assert f"'{action}'" in source


def test_installer_never_pipes_downloaded_text_into_execution() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", source).lower()

    assert "invoke-expression" not in compact
    assert "| iex" not in compact
    assert "start-process" not in compact or "-verb runas" not in compact
    assert "https://codeload.github.com/" in source
    assert "https://api.github.com/repos/" in source


@pytest.mark.skipif(os.name != "nt", reason="PowerShell installer is Windows-only")
def test_install_dry_run_parses_without_network_or_mutation(tmp_path: Path) -> None:
    root = tmp_path / "Nachuan" / "community"
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INSTALLER),
            "-Action",
            "Install",
            "-InstallRoot",
            str(root),
            "-DryRun",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "[DRY-RUN]" in completed.stdout
    assert not root.exists()
