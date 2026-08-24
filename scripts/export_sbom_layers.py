"""三层 SBOM 导出器（供应链终审盘点层）。

输入：``uv.lock``、``desktop/package-lock.json``、第三方二进制 runtime lock
（media/git/electron）与两个许可证登记表。
输出：CycloneDX 1.5 JSON 三层（Python / npm / 第三方二进制）+ manifest.json
（输入输出 SHA-256 绑定，全部字节可重现——不含时间戳/随机 UUID）。

纪律：
- 只做来源固定 + 哈希 + 许可证清点；不宣称无漏洞、无后门。
- 许可证只来自登记表或 lock 明证；无证据一律 NOASSERTION，绝不猜测。
- 默认对 FFmpeg 候选实文件复算 SHA-256 并与 media-runtime-lock 比对；
  漂移/缺失即 fail-closed（非零退出）。``--skip-binary-verify`` 是显式豁免。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

CYCLONEDX_15_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
NOASSERTION = "NOASSERTION"
_NORMALIZED_NAME = re.compile(r"[-_.]+")

MEDIA_LOCK = "desktop/media-runtime-lock.json"
GIT_LOCK = "desktop/git-runtime-lock.json"
ELECTRON_LOCK = "desktop/electron-runtime-lock.json"
PYTHON_LICENSE_REGISTRY = "desktop/python-license-registry.json"
NPM_LICENSE_REGISTRY = "desktop/npm-license-registry.json"

DEFAULT_FFMPEG_DIR = "安装与维护/构建输入/ffmpeg-8.0.1-essentials_build"


def normalize_name(name: str) -> str:
    return _NORMALIZED_NAME.sub("-", name).lower()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(root: Path, rel: str) -> Any:
    target = root / rel
    if not target.is_file():
        raise SystemExit(f"missing required input: {rel}")
    return json.loads(target.read_text(encoding="utf-8"))


def bom_envelope(layer: str) -> dict[str, Any]:
    return {
        "$schema": CYCLONEDX_15_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "nachuan-aggregator"},
            "properties": [{"name": "nachuan:layer", "value": layer}],
        },
    }


def write_bom(out: Path, name: str, bom: dict[str, Any]) -> str:
    data = (json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    target = out / name
    target.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def license_expression(expression: str | None) -> list[dict[str, str]]:
    return [{"expression": expression if expression else NOASSERTION}]


def build_python_layer(root: Path) -> dict[str, Any]:
    lock_path = root / "uv.lock"
    if not lock_path.is_file():
        raise SystemExit("missing required input: uv.lock")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    registry = load_json(root, PYTHON_LICENSE_REGISTRY)
    licenses = {
        normalize_name(entry["name"]): entry["spdxExpression"]
        for entry in registry.get("entries", [])
        if isinstance(entry.get("name"), str)
    }
    bom = bom_envelope("python")
    components: list[dict[str, Any]] = []
    for package in lock["package"]:
        name = package["name"]
        version = package["version"]
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
            "licenses": license_expression(licenses.get(normalize_name(name))),
        }
        hashes: list[dict[str, str]] = []
        references: list[dict[str, str]] = []
        sdist = package.get("sdist")
        if isinstance(sdist, dict):
            digest = str(sdist.get("hash", ""))
            if digest.startswith("sha256:"):
                hashes.append({"alg": "SHA-256", "content": digest.split(":", 1)[1]})
            if isinstance(sdist.get("url"), str):
                references.append({"type": "distribution", "url": sdist["url"]})
        for wheel in package.get("wheels", [])[:1]:
            digest = str(wheel.get("hash", ""))
            if digest.startswith("sha256:"):
                hashes.append({"alg": "SHA-256", "content": digest.split(":", 1)[1]})
            if not references and isinstance(wheel.get("url"), str):
                references.append({"type": "distribution", "url": wheel["url"]})
        if hashes:
            component["hashes"] = hashes
        if references:
            component["externalReferences"] = references
        source = package.get("source", {})
        if "editable" in source:
            component["properties"] = [{"name": "nachuan:sourceKind", "value": "editable"}]
        components.append(component)
    bom["components"] = sorted(components, key=lambda c: c["name"])
    return bom


def npm_name_from_lock_path(lock_path: str) -> str:
    return lock_path.rsplit("node_modules/", 1)[-1]


def npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        return f"pkg:npm/%40{scope[1:]}/{rest}@{version}"
    return f"pkg:npm/{name}@{version}"


def build_npm_layer(root: Path) -> dict[str, Any]:
    lock = load_json(root, "desktop/package-lock.json")
    registry = load_json(root, NPM_LICENSE_REGISTRY)
    reviewed: dict[str, dict[str, Any]] = {}
    for entry in registry.get("components", []):
        if isinstance(entry.get("name"), str):
            reviewed[entry["name"]] = entry
    bom = bom_envelope("npm")
    components = []
    for lock_path, info in lock.get("packages", {}).items():
        if not lock_path:
            continue
        name = npm_name_from_lock_path(lock_path)
        version = str(info.get("version", ""))
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": npm_purl(name, version),
        }
        integrity = info.get("integrity")
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            component["hashes"] = [{"alg": "SHA-512", "content": integrity.split("-", 1)[1]}]
        if isinstance(info.get("resolved"), str):
            component["externalReferences"] = [
                {"type": "distribution", "url": info["resolved"]}
            ]
        expression: str | None = None
        license_field = info.get("license")
        if isinstance(license_field, str) and license_field.strip():
            expression = license_field.strip()
        review = reviewed.get(name)
        properties: list[dict[str, str]] = []
        if review is not None:
            registry_expression = review.get("spdxExpression")
            if isinstance(registry_expression, str) and registry_expression.strip():
                expression = registry_expression.strip()
            if review.get("manualLegalReviewRequired") is True:
                properties.append(
                    {"name": "nachuan:manualLegalReviewRequired", "value": "true"}
                )
            if review.get("licenseSource") == "metadata-reconstructed-reviewed":
                decision = review.get("review")
                if not isinstance(decision, dict):
                    raise ValueError(f"reviewed npm license record is incomplete: {name}")
                required_review = {
                    "decision",
                    "scope",
                    "reviewedAt",
                    "upstreamLicenseFileCount",
                }
                if not required_review <= set(decision):
                    raise ValueError(f"reviewed npm license fields are incomplete: {name}")
                properties.extend(
                    [
                        {
                            "name": "nachuan:licenseEvidence",
                            "value": "metadata-reconstructed-reviewed",
                        },
                        {
                            "name": "nachuan:licenseReviewDecision",
                            "value": str(decision["decision"]),
                        },
                        {
                            "name": "nachuan:licenseReviewScope",
                            "value": str(decision["scope"]),
                        },
                        {
                            "name": "nachuan:licenseReviewDate",
                            "value": str(decision["reviewedAt"]),
                        },
                        {
                            "name": "nachuan:upstreamLicenseFileCount",
                            "value": str(decision["upstreamLicenseFileCount"]),
                        },
                    ]
                )
        component["licenses"] = license_expression(expression)
        if info.get("dev") is True:
            properties.append({"name": "nachuan:devOnly", "value": "true"})
        if properties:
            component["properties"] = properties
        components.append(component)
    bom["components"] = sorted(components, key=lambda c: c["name"])
    return bom


def verify_ffmpeg_binaries(ffmpeg_dir: Path, media_lock: dict[str, Any]) -> None:
    expected = {
        artifact["sourcePath"]: artifact["sha256"]
        for artifact in media_lock.get("artifacts", [])
    }
    for source_path, sha256 in sorted(expected.items()):
        target = ffmpeg_dir / source_path
        if not target.is_file():
            raise SystemExit(f"ffmpeg candidate missing: {target}")
        actual = sha256_file(target)
        if actual != sha256:
            raise SystemExit(
                f"ffmpeg candidate drifted: {target} expected={sha256} actual={actual}"
            )


def build_binary_layer(root: Path, verify_ffmpeg: Path | None) -> dict[str, Any]:
    media_lock = load_json(root, MEDIA_LOCK)
    git_lock = load_json(root, GIT_LOCK)
    electron_lock = load_json(root, ELECTRON_LOCK)

    if verify_ffmpeg is not None:
        verify_ffmpeg_binaries(verify_ffmpeg, media_lock)

    bom = bom_envelope("thirdparty-binaries")
    components: list[dict[str, Any]] = []

    media_license = media_lock.get("license", {})
    admission = media_lock.get("releaseAdmission", {})
    authenticode = media_lock.get("authenticode", {})
    for artifact in media_lock.get("artifacts", []):
        components.append(
            {
                "type": "application",
                "name": artifact["role"],
                "version": media_lock["version"],
                "hashes": [{"alg": "SHA-256", "content": artifact["sha256"]}],
                "licenses": license_expression(media_license.get("spdx")),
                "externalReferences": [
                    {"type": "distribution", "url": media_lock["archive"]["url"]}
                ],
                "properties": [
                    {
                        "name": "nachuan:authenticodeStatus",
                        "value": str(authenticode.get("status", "unknown")),
                    },
                    {
                        "name": "nachuan:releaseAdmission",
                        "value": str(admission.get("production", "unknown")),
                    },
                    {
                        "name": "nachuan:trustClass",
                        "value": str(admission.get("trustClass", "unknown")),
                    },
                ],
            }
        )

    git_archive = git_lock["archive"]
    git_authenticode = git_lock.get("authenticode", {})
    components.append(
        {
            "type": "application",
            "name": "PortableGit",
            "version": git_lock["version"],
            "hashes": [{"alg": "SHA-256", "content": git_archive["sha256"]}],
            "licenses": license_expression(None),
            "externalReferences": [{"type": "distribution", "url": git_archive["url"]}],
            "properties": [
                {
                    "name": "nachuan:authenticodeStatus",
                    "value": str(git_authenticode.get("status", "unknown")),
                },
                {
                    "name": "nachuan:licenseEvidence",
                    "value": "not-registered-in-lock",
                },
            ],
        }
    )

    electron_properties = [
        {
            "name": "nachuan:licenseFile",
            "value": f"{entry['path']}#sha256={entry['sha256']}",
        }
        for entry in electron_lock.get("licenseFiles", [])
    ]
    components.append(
        {
            "type": "framework",
            "name": "electron",
            "version": electron_lock["version"],
            "hashes": [{"alg": "SHA-256", "content": electron_lock["archiveSha256"]}],
            "licenses": license_expression(None),
            "externalReferences": [
                {"type": "distribution", "url": electron_lock["sourceUrl"]}
            ],
            "properties": electron_properties,
        }
    )

    bom["components"] = sorted(components, key=lambda c: c["name"])
    return bom


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--verify-ffmpeg",
        default=None,
        help="FFmpeg 候选目录（含 bin/）；默认 <root>/%s" % DEFAULT_FFMPEG_DIR,
    )
    parser.add_argument(
        "--skip-binary-verify",
        action="store_true",
        help="显式豁免实文件复算（记录 verification=declared-only）",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    verify_ffmpeg: Path | None
    if args.skip_binary_verify:
        verify_ffmpeg = None
    else:
        verify_ffmpeg = Path(args.verify_ffmpeg) if args.verify_ffmpeg else root / DEFAULT_FFMPEG_DIR

    layers = {
        "python-sbom.cdx.json": build_python_layer(root),
        "npm-sbom.cdx.json": build_npm_layer(root),
        "thirdparty-binaries-sbom.cdx.json": build_binary_layer(root, verify_ffmpeg),
    }

    outputs: dict[str, str] = {}
    for name, bom in layers.items():
        outputs[name] = write_bom(out, name, bom)

    input_files = [
        "uv.lock",
        "desktop/package-lock.json",
        MEDIA_LOCK,
        GIT_LOCK,
        ELECTRON_LOCK,
        PYTHON_LICENSE_REGISTRY,
        NPM_LICENSE_REGISTRY,
    ]
    manifest = {
        "schema": "nachuan.sbom-layers-manifest.v1",
        "generatedWith": {"tool": "scripts/export_sbom_layers.py"},
        "binaryVerification": (
            "declared-only" if verify_ffmpeg is None else "ffmpeg-recalculated"
        ),
        "inputs": {rel: sha256_file(root / rel) for rel in input_files},
        "outputs": outputs,
        "counts": {name: len(bom["components"]) for name, bom in layers.items()},
    }
    write_bom(out, "manifest.json", manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
