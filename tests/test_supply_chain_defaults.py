from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_build_scripts_never_pipe_remote_installers_or_use_npx_fallback():
    ps = _text("scripts/build-local.ps1").lower()
    sh = _text("scripts/build-local.sh").lower()
    workflows = _text(".github/workflows/ci.yml") + _text(".github/workflows/release.yml")

    assert "| iex" not in ps and "| invoke-expression" not in ps
    assert "curl -lssf https://astral.sh/uv/install.sh | sh" not in sh
    assert "npx " not in sh and "npx " not in ps and "npx " not in workflows
    assert 'npm_bin="$(resolve_tool npm)"' in sh
    assert '"$npm_bin" exec --offline -- electron-builder' in sh
    assert "$npmbin = resolve-requiredtool 'npm.cmd'" in ps
    assert "invoke-checkednative 'electron-builder' $npmbin" in ps


def test_windows_local_build_cannot_ignore_native_failures_or_missing_engine():
    ps = _text("scripts/build-local.ps1")

    assert "function Invoke-CheckedNative" in ps
    assert "$null -eq $code -or $code -ne 0" in ps
    assert "Invoke-CheckedNative 'pytest'" in ps
    assert "Invoke-CheckedNative 'PyInstaller'" in ps
    assert "Invoke-CheckedNative 'package verifier'" in ps
    assert "PyInstaller returned success without engine.exe" in ps
    assert "Expected exactly one verified installer" in ps


def test_weixin_runtime_crypto_is_a_direct_locked_dependency():
    project = _text("pyproject.toml")
    bridge = _text("scripts/run_weixin_ilink_bridge.py")

    assert '"cryptography>=49.0.0"' in project
    assert "from cryptography.hazmat.primitives" in bridge


def test_runtime_model_paths_are_offline_and_no_floating_hub_downloads_remain():
    local = _text("gateway/local_model.py")
    audio = _text("gateway/audio.py")
    embedder = _text("orchestrator/embedder.py")
    coordinator = _text("orchestrator/neural_coordinator.py")

    assert "resolve/master" not in local
    assert "NACHUAN_ENABLE_VERIFIED_MODEL_DOWNLOAD" in local
    assert "local_files_only=True" in audio
    assert "snapshot_download" not in embedder
    assert "local_files_only=True" in embedder
    assert "NACHUAN_COORDINATOR_BACKBONE_DIR" in coordinator


def test_release_does_not_depend_on_unpinned_upx():
    spec = _text("engine.spec")
    assert "upx=False" in spec


def test_direct_desktop_engine_build_uses_shared_release_selector_before_pyinstaller():
    package = _text("desktop/package.json")
    policy = _text("desktop/scripts/python-release-policy.mjs")
    sync = "node scripts/python-release-policy.mjs sync"
    build = "node scripts/python-release-policy.mjs build-engine"

    assert sync in package and build in package
    assert package.index(sync) < package.index(build)
    assert "uv run" not in package
    assert "--no-default-groups" in policy
    assert "groups: Object.freeze(['dev'])" in policy
    assert "extras: Object.freeze(['dev'])" in policy
    assert "--all-extras" not in policy


def test_security_document_does_not_claim_malware_certification():
    doc = _text("docs/THIRD_PARTY_SECURITY.md")
    assert "不得宣传为“无病毒/无木马”" in doc
    assert "SBOM" in doc and "SHA-256" in doc and "代码签名" in doc
