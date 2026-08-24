from __future__ import annotations

import builtins
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "视频工作流" / "scripts"
pytestmark = pytest.mark.skipif(not SCRIPTS.is_dir(), reason="local legacy workflow is not present")


def _load_doctor():
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location("legacy_story2video_doctor", SCRIPTS / "doctor.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


def test_doctor_fix_is_disabled_before_any_probe(monkeypatch, capsys):
    doctor = _load_doctor()

    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("doctor --fix must not launch a subprocess")

    monkeypatch.setattr(doctor.subprocess, "run", forbidden_run)
    assert doctor.main(["--fix"]) == 2
    assert "DOCTOR_FIX_DISABLED" in capsys.readouterr().out


def test_programmatic_fix_never_installs_missing_packages(monkeypatch):
    doctor = _load_doctor()
    real_import = builtins.__import__

    def missing_optional_packages(name, *args, **kwargs):
        if name in {"PIL", "numpy", "cv2", "edge_tts"}:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    def forbidden_run(*_args, **_kwargs):
        raise AssertionError("package checks must never install dependencies")

    monkeypatch.setattr(builtins, "__import__", missing_optional_packages)
    monkeypatch.setattr(doctor.subprocess, "run", forbidden_run)
    doctor.R = {"pass": 0, "warn": 0, "fail": 0}

    doctor.check_pkgs(fix=True, quick=True)

    assert doctor.R["fail"] == 4


def test_primary_entrypoint_is_blocked_without_explicit_local_opt_in():
    env = os.environ.copy()
    env.pop("NACHUAN_ENABLE_LEGACY_VIDEO_WORKFLOW", None)
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "run_episode.py")],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )

    assert result.returncode == 78
    assert "NON_PRODUCTION_BLOCKED" in result.stdout
