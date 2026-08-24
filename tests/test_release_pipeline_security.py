from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_pipeline_is_manual_pinned_closed_and_publish_is_blocked() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8")

    assert "workflow_dispatch:" in workflow
    assert "push:" not in workflow
    assert "release_tag:" in workflow
    assert "PUBLISH-NACHUAN-PRODUCTION" in workflow
    assert "production-release" in workflow
    assert "publish-blocked-until-machine-gates-exist" in workflow
    assert "contents: write" not in workflow
    assert "action-gh-release" not in workflow
    for missing_machine_gate in (
        "independent anti-malware scan evidence",
        "SBOM",
        "third-party license gate",
        "clean-VM install",
        "real WeChat",
        "soak/SLO",
    ):
        assert missing_machine_gate in workflow

    assert "node desktop/scripts/python-release-policy.mjs sync" in workflow
    assert "node desktop/scripts/python-release-policy.mjs attest" in workflow
    assert "node desktop/scripts/python-release-policy.mjs test" in workflow
    assert "npm ci" in workflow
    assert "npm run typecheck" in workflow
    assert "npm test" in workflow
    assert "release-security.test.mjs" in workflow
    assert "_verify_pack.mjs" in workflow
    assert "release-output.mjs clean" in workflow
    assert "release-output.mjs prune lean" in workflow
    assert "release-evidence.mjs verify lean" in workflow
    assert "production-update-envelope.mjs verify lean" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "release-metadata.mjs lean" in workflow
    assert "release-candidate-archive.mjs create" in workflow
    assert "release-candidate-archive.mjs verify" in workflow
    assert "foreach ($field in @('archiveSha256', 'archiveSize', 'manifestSha256', 'targetCount'))" in workflow
    assert '"archive_sha256=$($created.archiveSha256)"' in workflow
    assert '"manifest_sha256=$($created.manifestSha256)"' in workflow

    upload_steps = re.findall(
        r"(?ms)^      - uses: actions/upload-artifact@[^\n]+\n"
        r"(?P<body>(?:^        .*?(?:\n|\Z))*)",
        workflow,
    )
    assert len(upload_steps) == 1
    upload_step = upload_steps[0]
    upload_paths = re.search(
        r"(?m)^          path: \|\n(?P<paths>(?:^            \S.*(?:\n|\Z))+)",
        upload_step,
    )
    assert upload_paths is not None
    assert tuple(line.strip() for line in upload_paths.group("paths").splitlines()) == (
        "${{ steps.candidate_archive.outputs.archive_path }}",
        "${{ steps.candidate_archive.outputs.manifest_path }}",
    )
    assert (
        "name: nachuan-windows-${{ needs.verify.outputs.release_tag }}-"
        "${{ steps.candidate_archive.outputs.archive_sha256 }}"
    ) in upload_step
    assert "desktop/release/SHA256SUMS" not in upload_step
    assert "desktop/release/" not in upload_step
    assert "Get-AuthenticodeSignature" in workflow
    assert "win-unpacked/纳川.exe" in workflow
    assert "desktop/release/nachuan-$version-lean-win.exe" in workflow
    assert "desktop/release/*.zip" not in workflow
    assert "desktop/release/*.yml" not in workflow
    assert "release/lean.yml" in workflow
    assert "releases/latest" not in workflow
    assert "--publish always" not in workflow
    assert "needs: verify" in workflow
    assert "runs-on: windows-latest" in workflow
    assert "runner: macos-latest" not in workflow
    assert "runner: ubuntu-latest" not in workflow
    assert "LLAMA_MACOS" not in workflow
    for exact_version in ("24.14.0", "11.12.1", "0.11.3", "3.12.9"):
        assert exact_version in workflow
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    # “full” without a verified model source is a misleading empty package.
    assert "Package and verify full" not in workflow
    assert workflow.index("node scripts/prepare-pack.mjs lean") < workflow.index(
        "node scripts/write-engine-digest.mjs"
    )


def test_ci_actions_are_immutable_and_dependencies_are_locked() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")

    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "node desktop/scripts/python-release-policy.mjs sync" in workflow
    assert "node desktop/scripts/python-release-policy.mjs attest" in workflow
    assert "node desktop/scripts/python-release-policy.mjs test" in workflow
    assert "npm ci" in workflow
    for exact_version in ("24.14.0", "11.12.1", "0.11.3", "3.12.9"):
        assert exact_version in workflow


def test_local_builds_require_a_pinned_llama_hash_and_verify_packages() -> None:
    powershell = (ROOT / "scripts" / "build-local.ps1").read_text("utf-8")
    shell = (ROOT / "scripts" / "build-local.sh").read_text("utf-8")

    for script in (powershell, shell):
        assert "LLAMA_URL" in script
        assert "LLAMA_SHA256" in script
        assert "releases/latest" not in script
        assert "_verify_pack.mjs" in script
        assert "https://registry.npmjs.org" in script
        assert "npmmirror" not in script
        assert "CSC_IDENTITY_AUTO_DISCOVERY=false" not in script
        assert "both" not in script
        assert "--ignore-scripts" in script
        assert "ESBUILD_BINARY_PATH" in script
        assert "ELECTRON_OVERRIDE_DIST_PATH" in script
        assert "NODE_OPTIONS" in script
        assert "npm_config_script_shell" in script
        for exact_version in ("24.14.0", "11.12.1", "0.11.3", "3.12.9"):
            assert exact_version in script
        assert script.index("prepare-pack.mjs") < script.index("write-engine-digest.mjs")
        assert script.index("--ignore-scripts") < script.index("electron-runtime-policy.mjs")
        assert script.index("electron-runtime-policy.mjs") < script.index("license-stage.mjs")

    assert "@('scripts/release-output.mjs', 'clean')" in powershell
    assert "@('scripts/release-output.mjs', 'prune', $Want)" in powershell
    assert "release-output.mjs clean" in shell
    assert "release-output.mjs prune" in shell

    assert "$UvBin" in powershell
    assert "UV_BIN" in shell
    assert "Invoke-CheckedNative 'locked npm dependency install without lifecycle scripts' $NpmBin" in powershell
    assert "[Environment]::SystemDirectory" in powershell
    assert "Join-Path $env:SystemRoot" not in powershell
    assert '"$NPM_BIN" ci --ignore-scripts' in shell
    assert "env:Path" not in powershell
    assert "export PATH" not in shell


def test_final_pack_gate_reads_asar_and_enumerates_engine_directory() -> None:
    verifier = (ROOT / "desktop" / "scripts" / "_verify_pack.mjs").read_text("utf-8")
    builder = (ROOT / "desktop" / "electron-builder.yml").read_text("utf-8")
    package = (ROOT / "desktop" / "package.json").read_text("utf-8")

    assert "from '@electron/asar'" in verifier
    assert "extractFile" in verifier
    assert "listPackage" in verifier
    assert "app.asar" in verifier
    assert "\n  verifyPackagedPaidMediaControlPlane({ resourcesRoot })\n" in verifier
    assert "packaged engine directory must contain only" in verifier
    assert "EXPECTED_LOCAL_RUNTIME_MANIFEST_SHA256" in verifier
    assert "local runtime manifest digest" in verifier
    assert "assertClosedReleaseOutput" in verifier
    assert "- nsis" in builder
    assert "- zip" not in builder
    assert "artifactName: nachuan-${version}-${env.DMX_VARIANT}-win.${ext}" in builder
    assert '"@electron/asar": "3.4.1"' in package
