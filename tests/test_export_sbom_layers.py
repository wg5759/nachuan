"""三层 SBOM 导出器合同测试（供应链终审，production_readiness）。

盘点对象：Python uv.lock、desktop/package-lock.json、第三方二进制 runtime lock。
纪律：SBOM 只做来源固定 + 哈希 + 许可证清点；许可证无登记证据时 NOASSERTION，
绝不猜测；FFmpeg 实文件复算与 lock 不一致时 fail-closed。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export_sbom_layers.py"
CYCLONEDX_15 = "http://cyclonedx.org/schema/bom-1.5.schema.json"
FFMPEG_BIN = (
    ROOT / "安装与维护" / "构建输入" / "ffmpeg-8.0.1-essentials_build" / "bin"
)
HAS_REVIEWED_FFMPEG = (FFMPEG_BIN / "ffmpeg.exe").is_file() and (
    FFMPEG_BIN / "ffprobe.exe"
).is_file()


def run_export(out: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    arguments = list(extra)
    if (
        not HAS_REVIEWED_FFMPEG
        and "--skip-binary-verify" not in arguments
        and "--verify-ffmpeg" not in arguments
    ):
        arguments.append("--skip-binary-verify")
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--root",
            str(ROOT),
            "--out",
            str(out),
            *arguments,
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("sbom")
    result = run_export(out)
    assert result.returncode == 0, f"exporter failed: {result.stderr}"
    return out


def load(out: Path, name: str) -> dict:
    return json.loads((out / name).read_text(encoding="utf-8"))


def components_by_name(bom: dict) -> dict[str, dict]:
    """(name, version) 复合键：uv.lock 同一名字可因 marker 分支并存多版本。"""
    return {(c["name"], c["version"]): c for c in bom["components"]}


def unique_names(bom: dict) -> dict[str, dict]:
    return {c["name"]: c for c in bom["components"]}


class TestLayersPresent:
    def test_three_layers_and_manifest_written(self, generated: Path):
        for name in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "thirdparty-binaries-sbom.cdx.json",
            "manifest.json",
        ):
            assert (generated / name).is_file(), name

    def test_cyclonedx_15_envelope(self, generated: Path):
        for name in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "thirdparty-binaries-sbom.cdx.json",
        ):
            bom = load(generated, name)
            assert bom["bomFormat"] == "CycloneDX"
            assert bom["specVersion"] == "1.5"
            assert bom["$schema"] == CYCLONEDX_15
            assert bom["version"] == 1
            assert bom["components"], name


class TestPythonLayer:
    def test_covers_every_uv_lock_package(self, generated: Path):
        lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
        bom = load(generated, "python-sbom.cdx.json")
        names = components_by_name(bom)
        assert len(bom["components"]) == len(lock["package"])
        for pkg in lock["package"]:
            key = (pkg["name"], pkg["version"])
            assert key in names, key
            component = names[key]
            assert component["purl"] == f"pkg:pypi/{pkg['name']}@{pkg['version']}"

    def test_pins_source_url_and_sha256(self, generated: Path):
        bom = load(generated, "python-sbom.cdx.json")
        component = unique_names(bom)["aliyun-python-sdk-core"]
        hashes = {h["alg"]: h["content"] for h in component["hashes"]}
        assert hashes["SHA-256"] == (
            "651caad597eb39d4fad6cf85133dffe92837d53bdf62db9d8f37dab6508bb8f9"
        )
        urls = [e["url"] for e in component["externalReferences"]]
        assert any("files.pythonhosted.org" in url for url in urls)

    def test_license_registry_mapping_and_noassertion_fallback(self, generated: Path):
        bom = load(generated, "python-sbom.cdx.json")
        names = unique_names(bom)
        antlr = names["antlr4-python3-runtime"]
        assert antlr["licenses"] == [{"expression": "BSD-3-Clause"}]
        uncovered = names["aliyun-python-sdk-core"]
        assert uncovered["licenses"] == [{"expression": "NOASSERTION"}]


class TestNpmLayer:
    def test_covers_every_lock_package_except_root(self, generated: Path):
        lock = json.loads((ROOT / "desktop" / "package-lock.json").read_text(encoding="utf-8"))
        bom = load(generated, "npm-sbom.cdx.json")
        expected = [key for key in lock["packages"] if key]
        assert len(bom["components"]) == len(expected)
        names = unique_names(bom)
        assert "electron" in names and "@vitejs/plugin-react" in names

    def test_scoped_purl_and_integrity_hash(self, generated: Path):
        bom = load(generated, "npm-sbom.cdx.json")
        babel = unique_names(bom)["@babel/compat-data"]
        assert babel["purl"] == "pkg:npm/%40babel/compat-data@7.29.7"
        hashes = {h["alg"]: h["content"] for h in babel["hashes"]}
        assert hashes["SHA-512"] == (
            "locTkQyKvwIEgBzVrn8693ebc97F2U8ZHjbXwDXJ5Fn2TCpNwTlKcaKLkdHop5c/icOFE7qt7Q9JC5hnKNa6Gg=="
        )
        assert babel["licenses"] == [{"expression": "MIT"}]

    def test_reviewed_metadata_reconstruction_survives_into_sbom(self, generated: Path):
        bom = load(generated, "npm-sbom.cdx.json")
        names = unique_names(bom)
        for name, version in (("html-parse-stringify", "3.0.1"), ("lazy-val", "1.0.5")):
            component = names[name]
            assert component["version"] == version
            assert component["licenses"] == [{"expression": "MIT"}]
            props = {p["name"]: p["value"] for p in component.get("properties", [])}
            assert props["nachuan:licenseEvidence"] == "metadata-reconstructed-reviewed", name
            assert props["nachuan:licenseReviewDecision"] == (
                "approved-for-binary-distribution-notice"
            ), name
            assert props["nachuan:licenseReviewScope"] == (
                "exact-version-metadata-and-standard-mit-notice"
            ), name
            assert props["nachuan:licenseReviewDate"] == "2026-08-24", name
            assert props["nachuan:upstreamLicenseFileCount"] == "0", name


class TestBinaryLayer:
    def test_ffmpeg_pair_with_gpl_license_and_hash(self, generated: Path):
        bom = load(generated, "thirdparty-binaries-sbom.cdx.json")
        names = unique_names(bom)
        ffmpeg = names["ffmpeg"]
        assert ffmpeg["version"] == "8.0.1-essentials_build-www.gyan.dev"
        assert ffmpeg["licenses"] == [{"expression": "GPL-3.0-or-later"}]
        hashes = {h["alg"]: h["content"] for h in ffmpeg["hashes"]}
        assert hashes["SHA-256"] == (
            "5af82a0d4fe2b9eae211b967332ea97edfc51c6b328ca35b827e73eac560dc0d"
        )
        props = {p["name"]: p["value"] for p in ffmpeg.get("properties", [])}
        assert props["nachuan:authenticodeStatus"] == "NotSigned"
        assert props["nachuan:releaseAdmission"] == "blocked"
        assert "ffprobe" in names

    def test_git_and_electron_declared_with_truthful_license_state(self, generated: Path):
        bom = load(generated, "thirdparty-binaries-sbom.cdx.json")
        names = unique_names(bom)
        git = names["PortableGit"]
        assert git["version"] == "2.55.0.windows.2"
        # git-runtime-lock.json 未登记许可证字段：清点层必须 NOASSERTION，不猜。
        assert git["licenses"] == [{"expression": "NOASSERTION"}]
        git_hashes = {h["alg"]: h["content"] for h in git["hashes"]}
        assert git_hashes["SHA-256"] == (
            "b20d42da3afa228e9fa6174480de820282667e799440d655e308f700dfa0d0df"
        )
        electron = names["electron"]
        assert electron["version"] == "39.8.10"
        electron_hashes = {h["alg"]: h["content"] for h in electron["hashes"]}
        assert electron_hashes["SHA-256"] == (
            "4478410a35a8399b7745085096695a37877f176755182a71e27eddc245cd98d5"
        )


class TestManifestAndReproducibility:
    def test_manifest_binds_outputs_and_inputs(self, generated: Path):
        manifest = load(generated, "manifest.json")
        assert manifest["binaryVerification"] == (
            "ffmpeg-recalculated" if HAS_REVIEWED_FFMPEG else "declared-only"
        )
        outputs = manifest["outputs"]
        for name in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "thirdparty-binaries-sbom.cdx.json",
        ):
            digest = hashlib.sha256((generated / name).read_bytes()).hexdigest()
            assert outputs[name] == digest, name
        inputs = manifest["inputs"]
        assert inputs["uv.lock"] == hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()
        assert inputs["desktop/package-lock.json"] == hashlib.sha256(
            (ROOT / "desktop" / "package-lock.json").read_bytes()
        ).hexdigest()

    def test_regeneration_is_byte_identical(self, generated: Path, tmp_path: Path):
        second = tmp_path / "second"
        result = run_export(second)
        assert result.returncode == 0, result.stderr
        for name in (
            "python-sbom.cdx.json",
            "npm-sbom.cdx.json",
            "thirdparty-binaries-sbom.cdx.json",
            "manifest.json",
        ):
            assert (generated / name).read_bytes() == (second / name).read_bytes(), name


class TestFailClosed:
    def test_missing_uv_lock_fails(self, tmp_path: Path):
        empty_root = tmp_path / "empty-root"
        empty_root.mkdir()
        result = run_export(tmp_path / "out", "--root", str(empty_root))
        assert result.returncode != 0
        assert "uv.lock" in result.stderr

    @pytest.mark.skipif(
        not HAS_REVIEWED_FFMPEG,
        reason="source-only checkout intentionally carries no reviewed FFmpeg bytes",
    )
    def test_ffmpeg_drift_fails_closed(self, tmp_path: Path):
        source = FFMPEG_BIN
        fake = tmp_path / "ffmpeg-8.0.1-essentials_build" / "bin"
        fake.mkdir(parents=True)
        shutil.copy2(source / "ffprobe.exe", fake / "ffprobe.exe")
        drifted = tmp_path / "ffmpeg.exe"
        drifted.write_bytes(b"drifted")
        shutil.move(str(drifted), str(fake / "ffmpeg.exe"))
        result = run_export(
            tmp_path / "out",
            "--verify-ffmpeg",
            str(tmp_path / "ffmpeg-8.0.1-essentials_build"),
        )
        assert result.returncode != 0
        assert "ffmpeg.exe" in result.stderr
