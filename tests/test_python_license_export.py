from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from scripts.export_python_licenses import PythonLicenseError, export_python_licenses, main


_BSD_3_CLAUSE_TEXT = """Copyright (c) 2010 Jonathan Hartley
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holders, nor those of its contributors
  may be used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
_BSD_3_CLAUSE_PALLETS_TEXT = """Copyright 2007 Pallets

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1.  Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def _write_distribution(
    root: Path,
    *,
    name: str,
    version: str,
    license_expression: str | None = "MIT",
    license_text: str = "MIT license text.\n",
) -> None:
    dist_info = root / f"{name.replace('-', '_')}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "LICENSE").write_text(license_text, encoding="utf-8")
    metadata = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    if license_expression is not None:
        metadata.append(f"License-Expression: {license_expression}")
    metadata.extend(["License-File: LICENSE", ""])
    (dist_info / "METADATA").write_text("\n".join(metadata), encoding="utf-8")


def _runtime_license(tmp_path: Path) -> Path:
    path = tmp_path / "LICENSE.runtime.txt"
    path.write_text("CPython license text.\n", encoding="utf-8")
    return path


def _reviewed_notice_case(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "reviewed_demo-4.5.dist-info"
    dist_info.mkdir(parents=True)
    metadata_bytes = (
        "Metadata-Version: 2.3\n"
        "Name: reviewed-demo\n"
        "Version: 4.5\n"
        "License: BSD\n"
    ).encode()
    (dist_info / "METADATA").write_bytes(metadata_bytes)

    notice_bytes = b"Reviewed three-clause BSD license text.\n"
    notice_path = tmp_path / "reviewed-notices" / "reviewed-demo-LICENSE.txt"
    notice_path.parent.mkdir()
    notice_path.write_bytes(notice_bytes)
    commit = "a" * 40
    artifact_sha256 = "4" * 64
    registry: dict[str, object] = {
        "entries": [
            {
                "lockedArtifact": {
                    "filename": "reviewed-demo-4.5.tar.gz",
                    "kind": "sdist",
                    "sha256": artifact_sha256,
                },
                "metadataSha256": _sha256(metadata_bytes),
                "name": "reviewed-demo",
                "notice": {
                    "gitBlobSha1": _git_blob_sha1(notice_bytes),
                    "path": "reviewed-notices/reviewed-demo-LICENSE.txt",
                    "sha256": _sha256(notice_bytes),
                    "sourceUrl": (
                        "https://raw.githubusercontent.com/example/reviewed-demo/"
                        f"{commit}/LICENSE.txt"
                    ),
                },
                "spdxExpression": "BSD-3-Clause",
                "upstream": {
                    "commit": commit,
                    "declaredLicense": "BSD",
                    "declaredName": "reviewed-demo",
                    "declaredVersion": "4.5",
                    "evidence": [
                        {
                            "gitBlobSha1": "2" * 40,
                            "path": "runtime/Python3/src/antlr4/Parser.py",
                            "role": "license-reference",
                            "sha256": "6" * 64,
                        },
                        {
                            "gitBlobSha1": "1" * 40,
                            "path": "runtime/Python3/setup.py",
                            "role": "package-metadata",
                            "sha256": "3" * 64,
                        },
                    ],
                    "licensePath": "LICENSE.txt",
                },
                "version": "4.5",
            }
        ],
        "schema": 3,
    }
    frozen_lock: dict[str, object] = {
        "package": [
            {
                "name": "reviewed-demo",
                "sdist": {
                    "hash": f"sha256:{artifact_sha256}",
                    "size": 123,
                    "url": "https://files.pythonhosted.org/reviewed-demo-4.5.tar.gz",
                },
                "version": "4.5",
            }
        ],
        "version": 1,
    }
    return site_packages, registry, frozen_lock


def test_exports_actual_distribution_metadata_and_wheel_license_text(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "demo_pkg-1.2.3.dist-info"
    license_path = dist_info / "licenses" / "LICENSE"
    license_path.parent.mkdir(parents=True)
    license_bytes = b"Demo MIT license text.\n"
    license_path.write_bytes(license_bytes)
    (dist_info / "METADATA").write_text(
        "\n".join(
            [
                "Metadata-Version: 2.4",
                "Name: demo_pkg",
                "Version: 1.2.3",
                "License-Expression: MIT",
                "License-File: licenses/LICENSE",
                "",
            ]
        ),
        encoding="utf-8",
    )
    runtime_license = tmp_path / "LICENSE.txt"
    runtime_bytes = b"CPython license text.\n"
    runtime_license.write_bytes(runtime_bytes)

    result = export_python_licenses(
        expected_components=[{"name": "demo-pkg", "version": "1.2.3"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=runtime_license,
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result == {
        "components": [
            {
                "licenseExpression": "MIT",
                "licenseFiles": [
                    {
                        "path": "demo_pkg-1.2.3.dist-info/licenses/LICENSE",
                        "sha256": _sha256(license_bytes),
                        "size": len(license_bytes),
                        "text": "Demo MIT license text.\n",
                    }
                ],
                "licenseSource": "metadata-license-expression",
                "name": "demo-pkg",
                "version": "1.2.3",
            }
        ],
        "runtime": {
            "implementation": "CPython",
            "licenseFile": {
                "path": "LICENSE.txt",
                "sha256": _sha256(runtime_bytes),
                "size": len(runtime_bytes),
                "text": "CPython license text.\n",
            },
            "version": "3.12.9",
        },
        "schema": 1,
        "tool": {"name": "nachuan-python-license-exporter", "version": "1.0.0"},
    }


def test_normalizes_an_unambiguous_legacy_license_classifier(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "legacy_demo-2.0.dist-info"
    license_path = dist_info / "LICENSE.txt"
    license_path.parent.mkdir(parents=True)
    license_path.write_text("Legacy MIT license text.\n", encoding="utf-8")
    (dist_info / "METADATA").write_text(
        "\n".join(
            [
                "Metadata-Version: 2.3",
                "Name: legacy_demo",
                "Version: 2.0",
                "Classifier: License :: OSI Approved :: MIT License",
                "License-File: LICENSE.txt",
                "",
            ]
        ),
        encoding="utf-8",
    )
    runtime_license = tmp_path / "LICENSE.runtime.txt"
    runtime_license.write_text("CPython license text.\n", encoding="utf-8")

    result = export_python_licenses(
        expected_components=[{"name": "legacy-demo", "version": "2.0"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=runtime_license,
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result["components"][0]["licenseExpression"] == "MIT"
    assert result["components"][0]["licenseSource"] == "metadata-classifier"


def test_identifies_complete_bsd_3_clause_wheel_text_with_only_a_generic_bsd_classifier(
    tmp_path: Path,
) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "colorama_demo-0.4.6.dist-info"
    (dist_info / "licenses").mkdir(parents=True)
    (dist_info / "licenses" / "LICENSE.txt").write_text(
        _BSD_3_CLAUSE_TEXT,
        encoding="utf-8",
    )
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: colorama-demo\n"
        "Version: 0.4.6\n"
        "Classifier: License :: OSI Approved :: BSD License\n"
        "License-File: LICENSE.txt\n",
        encoding="utf-8",
    )

    result = export_python_licenses(
        expected_components=[{"name": "colorama-demo", "version": "0.4.6"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result["components"][0]["licenseExpression"] == "BSD-3-Clause"
    assert result["components"][0]["licenseSource"] == "license-file"


def test_rejects_bsd_text_when_the_non_endorsement_clause_is_deleted(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "incomplete_bsd-1.0.dist-info"
    (dist_info / "licenses").mkdir(parents=True)
    non_endorsement = (
        "* Neither the name of the copyright holders, nor those of its contributors\n"
        "  may be used to endorse or promote products derived from this software without\n"
        "  specific prior written permission.\n\n"
    )
    incomplete_text = _BSD_3_CLAUSE_TEXT.replace(non_endorsement, "")
    assert incomplete_text != _BSD_3_CLAUSE_TEXT
    (dist_info / "licenses" / "LICENSE.txt").write_text(incomplete_text, encoding="utf-8")
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: incomplete-bsd\n"
        "Version: 1.0\n"
        "Classifier: License :: OSI Approved :: BSD License\n"
        "License-File: LICENSE.txt\n",
        encoding="utf-8",
    )

    with pytest.raises(PythonLicenseError, match="missing or ambiguous"):
        export_python_licenses(
            expected_components=[{"name": "incomplete-bsd", "version": "1.0"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry={"schema": 3, "entries": []},
        )


def test_rejects_a_classifier_that_conflicts_with_recognized_wheel_license_text(
    tmp_path: Path,
) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "conflicting_license-1.0.dist-info"
    (dist_info / "licenses").mkdir(parents=True)
    (dist_info / "licenses" / "LICENSE.txt").write_text(
        _BSD_3_CLAUSE_TEXT,
        encoding="utf-8",
    )
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: conflicting-license\n"
        "Version: 1.0\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
        "License-File: LICENSE.txt\n",
        encoding="utf-8",
    )

    with pytest.raises(PythonLicenseError, match="conflicts"):
        export_python_licenses(
            expected_components=[{"name": "conflicting-license", "version": "1.0"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry={"schema": 3, "entries": []},
        )


def test_identifies_the_complete_bsd_3_clause_holder_names_wording(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "pallets_demo-3.1.6.dist-info"
    (dist_info / "licenses").mkdir(parents=True)
    (dist_info / "licenses" / "LICENSE.txt").write_text(
        _BSD_3_CLAUSE_PALLETS_TEXT,
        encoding="utf-8",
    )
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: pallets-demo\n"
        "Version: 3.1.6\n"
        "Classifier: License :: OSI Approved :: BSD License\n"
        "License-File: LICENSE.txt\n",
        encoding="utf-8",
    )

    result = export_python_licenses(
        expected_components=[{"name": "pallets-demo", "version": "3.1.6"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result["components"][0]["licenseExpression"] == "BSD-3-Clause"
    assert result["components"][0]["licenseSource"] == "license-file"


def test_uses_only_an_exact_metadata_bound_legacy_registry_entry(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "ambiguous_demo-4.5.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "LICENSE").write_text("Three-clause BSD license text.\n", encoding="utf-8")
    metadata_bytes = "\n".join(
        [
            "Metadata-Version: 2.3",
            "Name: ambiguous_demo",
            "Version: 4.5",
            "Classifier: License :: OSI Approved :: BSD License",
            "License-File: LICENSE",
            "",
        ]
    ).encode()
    (dist_info / "METADATA").write_bytes(metadata_bytes)
    runtime_license = tmp_path / "LICENSE.runtime.txt"
    runtime_license.write_text("CPython license text.\n", encoding="utf-8")

    result = export_python_licenses(
        expected_components=[{"name": "ambiguous-demo", "version": "4.5"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=runtime_license,
        legacy_registry={
            "schema": 3,
            "entries": [
                {
                    "metadataSha256": _sha256(metadata_bytes),
                    "name": "ambiguous-demo",
                    "spdxExpression": "BSD-3-Clause",
                    "version": "4.5",
                }
            ],
        },
    )

    assert result["components"][0]["licenseExpression"] == "BSD-3-Clause"
    assert result["components"][0]["licenseSource"] == "registry"


def test_uses_only_a_hash_and_lock_bound_reviewed_upstream_notice(tmp_path: Path) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)

    result = export_python_licenses(
        expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry=registry,
        registry_root=tmp_path,
        frozen_lock=frozen_lock,
    )

    assert result["components"][0]["licenseExpression"] == "BSD-3-Clause"
    assert result["components"][0]["licenseSource"] == "registry"
    assert result["components"][0]["licenseFiles"] == [
        {
            "path": "reviewed-notices/reviewed-demo-LICENSE.txt",
            "sha256": _sha256(b"Reviewed three-clause BSD license text.\n"),
            "size": len(b"Reviewed three-clause BSD license text.\n"),
            "text": "Reviewed three-clause BSD license text.\n",
        }
    ]


def test_uses_a_reviewed_notice_when_exact_metadata_has_no_wheel_license_text(
    tmp_path: Path,
) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)
    metadata_bytes = (
        "Metadata-Version: 2.3\n"
        "Name: reviewed-demo\n"
        "Version: 4.5\n"
        "License: MIT\n"
    ).encode()
    metadata_path = site_packages / "reviewed_demo-4.5.dist-info" / "METADATA"
    metadata_path.write_bytes(metadata_bytes)
    notice_bytes = b"Reviewed MIT license text.\n"
    notice_path = tmp_path / "reviewed-notices" / "reviewed-demo-LICENSE.txt"
    notice_path.write_bytes(notice_bytes)
    entry = registry["entries"][0]
    entry["metadataSha256"] = _sha256(metadata_bytes)
    entry["notice"]["gitBlobSha1"] = _git_blob_sha1(notice_bytes)
    entry["notice"]["sha256"] = _sha256(notice_bytes)
    entry["spdxExpression"] = "MIT"
    entry["upstream"]["declaredLicense"] = "MIT"

    result = export_python_licenses(
        expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry=registry,
        registry_root=tmp_path,
        frozen_lock=frozen_lock,
    )

    assert result["components"][0]["licenseExpression"] == "MIT"
    assert result["components"][0]["licenseSource"] == "metadata-license"
    assert result["components"][0]["licenseFiles"][0]["text"] == "Reviewed MIT license text.\n"


def test_uses_exact_inline_notice_bytes_when_the_upstream_file_has_no_final_newline(
    tmp_path: Path,
) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)
    notice_path = tmp_path / "reviewed-notices" / "reviewed-demo-LICENSE.txt"
    notice_bytes = notice_path.read_bytes().rstrip(b"\n")
    notice_path.unlink()
    entry = registry["entries"][0]
    entry["notice"] = {
        "base64": base64.b64encode(notice_bytes).decode("ascii"),
        "displayPath": "reviewed-notices/reviewed-demo-LICENSE.txt",
        "gitBlobSha1": _git_blob_sha1(notice_bytes),
        "sha256": _sha256(notice_bytes),
        "sourceUrl": entry["notice"]["sourceUrl"],
    }

    result = export_python_licenses(
        expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry=registry,
        registry_root=tmp_path,
        frozen_lock=frozen_lock,
    )

    assert result["components"][0]["licenseFiles"][0] == {
        "path": "reviewed-notices/reviewed-demo-LICENSE.txt",
        "sha256": _sha256(notice_bytes),
        "size": len(notice_bytes),
        "text": notice_bytes.decode("utf-8"),
    }


def test_rejects_reviewed_notice_when_installed_metadata_hash_drifts(tmp_path: Path) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)
    metadata_path = site_packages / "reviewed_demo-4.5.dist-info" / "METADATA"
    metadata_path.write_bytes(metadata_path.read_bytes() + b"Summary: drifted\n")

    with pytest.raises(PythonLicenseError, match="METADATA hash drifted"):
        export_python_licenses(
            expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry=registry,
            registry_root=tmp_path,
            frozen_lock=frozen_lock,
        )


def test_rejects_reviewed_notice_when_checked_in_notice_hash_drifts(tmp_path: Path) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)
    notice_path = tmp_path / "reviewed-notices" / "reviewed-demo-LICENSE.txt"
    notice_path.write_bytes(notice_path.read_bytes() + b"drift")

    with pytest.raises(PythonLicenseError, match="notice SHA256 drifted"):
        export_python_licenses(
            expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry=registry,
            registry_root=tmp_path,
            frozen_lock=frozen_lock,
        )


def test_rejects_reviewed_notice_when_source_commit_drifts(tmp_path: Path) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)
    entry = registry["entries"][0]
    entry["upstream"]["commit"] = "b" * 40

    with pytest.raises(PythonLicenseError, match="source commit drifted"):
        export_python_licenses(
            expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry=registry,
            registry_root=tmp_path,
            frozen_lock=frozen_lock,
        )


def test_rejects_reviewed_notice_when_locked_artifact_hash_drifts(tmp_path: Path) -> None:
    site_packages, registry, frozen_lock = _reviewed_notice_case(tmp_path)
    frozen_lock["package"][0]["sdist"]["hash"] = f"sha256:{'5' * 64}"

    with pytest.raises(PythonLicenseError, match="locked artifact drifted"):
        export_python_licenses(
            expected_components=[{"name": "reviewed-demo", "version": "4.5"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry=registry,
            registry_root=tmp_path,
            frozen_lock=frozen_lock,
        )


@pytest.mark.parametrize(
    "expected",
    [
        [{"name": "alpha", "version": "1.0"}],
        [
            {"name": "alpha", "version": "1.0"},
            {"name": "beta", "version": "2.0"},
            {"name": "unexpected", "version": "9.9"},
        ],
        [
            {"name": "alpha", "version": "1.0"},
            {"name": "beta", "version": "2.1"},
        ],
    ],
    ids=["installed-extra-package", "installed-missing-package", "version-drift"],
)
def test_fails_closed_unless_expected_and_installed_packages_match_exactly(
    tmp_path: Path, expected: list[dict[str, str]]
) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(site_packages, name="alpha", version="1.0")
    _write_distribution(site_packages, name="beta", version="2.0")

    with pytest.raises(PythonLicenseError, match="exactly match"):
        export_python_licenses(
            expected_components=expected,
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry={"schema": 3, "entries": []},
        )


def test_excludes_only_the_exact_frozen_first_party_editable_distribution(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(site_packages, name="alpha", version="1.0")
    _write_distribution(site_packages, name="llm-aggregator", version="0.1.0")
    first_party_dist = site_packages / "llm_aggregator-0.1.0.dist-info"
    (first_party_dist / "direct_url.json").write_text(
        '{"dir_info":{"editable":true},"url":"file:///D:/project"}\n',
        encoding="utf-8",
    )
    frozen_lock = {
        "package": [
            {
                "name": "llm-aggregator",
                "source": {"editable": "."},
                "version": "0.1.0",
            }
        ],
        "version": 1,
    }

    result = export_python_licenses(
        expected_components=[{"name": "alpha", "version": "1.0"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
        frozen_lock=frozen_lock,
    )

    assert [(item["name"], item["version"]) for item in result["components"]] == [("alpha", "1.0")]


@pytest.mark.parametrize("bad_license", ["UNKNOWN", "NOASSERTION", "", "Made-Up-License-1.0"])
def test_rejects_unknown_or_empty_license_metadata(tmp_path: Path, bad_license: str) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(site_packages, name="demo", version="1.0", license_expression=bad_license)

    with pytest.raises(PythonLicenseError, match="license"):
        export_python_licenses(
            expected_components=[{"name": "demo", "version": "1.0"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry={"schema": 3, "entries": []},
        )


def test_rejects_empty_wheel_license_text(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(
        site_packages,
        name="demo",
        version="1.0",
        license_text="  \n",
    )

    with pytest.raises(PythonLicenseError, match="no usable text"):
        export_python_licenses(
            expected_components=[{"name": "demo", "version": "1.0"}],
            search_paths=[site_packages],
            runtime_version="3.12.9",
            runtime_license_path=_runtime_license(tmp_path),
            legacy_registry={"schema": 3, "entries": []},
        )


def test_cli_writes_canonical_schema_bound_json_from_a_cyclonedx_package_set(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(site_packages, name="demo", version="1.0")
    sbom = tmp_path / "python.cdx.json"
    sbom.write_text(
        '{"bomFormat":"CycloneDX","components":[{"name":"demo","purl":"pkg:pypi/demo@1.0","type":"library","version":"1.0"}],"specVersion":"1.5","version":1}\n',
        encoding="utf-8",
    )
    registry = tmp_path / "registry.json"
    registry.write_text('{"entries":[],"schema":3}\n', encoding="utf-8")
    frozen_lock = tmp_path / "uv.lock"
    frozen_lock.write_text("version = 1\n", encoding="utf-8")
    output = tmp_path / "PYTHON_LICENSES.json"

    exit_code = main(
        [
            "--sbom",
            str(sbom),
            "--registry",
            str(registry),
            "--lock",
            str(frozen_lock),
            "--site-packages",
            str(site_packages),
            "--runtime-version",
            "3.12.9",
            "--runtime-license",
            str(_runtime_license(tmp_path)),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert '"schema": 1' in text
    assert '"version": "1.0.0"' in text
    assert '"name": "demo"' in text


def test_accepts_one_installed_version_from_same_name_lock_marker_candidates(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(site_packages, name="conditional-demo", version="2.0")

    result = export_python_licenses(
        expected_components=[
            {"name": "conditional-demo", "version": "1.5"},
            {"name": "conditional-demo", "version": "2.0"},
        ],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
    )

    assert [(item["name"], item["version"]) for item in result["components"]] == [
        ("conditional-demo", "2.0")
    ]


def test_cli_excludes_a_lock_candidate_whose_pep508_marker_is_false(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    _write_distribution(site_packages, name="windows-demo", version="1.0")
    sbom = tmp_path / "python.cdx.json"
    sbom.write_text(
        """{
  "bomFormat": "CycloneDX",
  "components": [
    {"name": "windows-demo", "purl": "pkg:pypi/windows-demo@1.0", "type": "library", "version": "1.0"},
    {"name": "linux-only", "purl": "pkg:pypi/linux-only@9.0", "properties": [{"name": "uv:package:marker", "value": "sys_platform == 'linux'"}], "type": "library", "version": "9.0"}
  ],
  "specVersion": "1.5",
  "version": 1
}
""",
        encoding="utf-8",
    )
    registry = tmp_path / "registry.json"
    registry.write_text('{"entries":[],"schema":3}\n', encoding="utf-8")
    frozen_lock = tmp_path / "uv.lock"
    frozen_lock.write_text("version = 1\n", encoding="utf-8")
    output = tmp_path / "PYTHON_LICENSES.json"

    assert (
        main(
            [
                "--sbom",
                str(sbom),
                "--registry",
                str(registry),
                "--lock",
                str(frozen_lock),
                "--site-packages",
                str(site_packages),
                "--runtime-version",
                "3.12.9",
                "--runtime-license",
                str(_runtime_license(tmp_path)),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert [item["name"] for item in __import__("json").loads(output.read_text())["components"]] == [
        "windows-demo"
    ]


def test_discovers_an_undeclared_wheel_license_file_from_dist_info_record(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "fallback_demo-1.0.dist-info"
    dist_info.mkdir(parents=True)
    license_text = "Fallback MIT license.\n"
    (dist_info / "LICENSE.txt").write_bytes(license_text.encode())
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.3\nName: fallback-demo\nVersion: 1.0\nLicense: MIT\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "fallback_demo-1.0.dist-info/LICENSE.txt,,\n"
        "fallback_demo-1.0.dist-info/METADATA,,\n"
        "fallback_demo-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )

    result = export_python_licenses(
        expected_components=[{"name": "fallback-demo", "version": "1.0"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result["components"][0]["licenseFiles"][0]["path"] == (
        "fallback_demo-1.0.dist-info/LICENSE.txt"
    )
    assert result["components"][0]["licenseFiles"][0]["text"] == license_text


def test_normalizes_an_exact_legacy_license_field_when_classifier_is_ambiguous(tmp_path: Path) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "bsd_demo-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "LICENSE").write_bytes(b"Three-clause BSD license.\n")
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.3\n"
        "Name: bsd-demo\n"
        "Version: 1.0\n"
        "License: BSD-3-Clause\n"
        "Classifier: License :: OSI Approved :: BSD License\n"
        "License-File: LICENSE\n",
        encoding="utf-8",
    )

    result = export_python_licenses(
        expected_components=[{"name": "bsd-demo", "version": "1.0"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result["components"][0]["licenseExpression"] == "BSD-3-Clause"
    assert result["components"][0]["licenseSource"] == "metadata-license"


def test_resolves_pep639_license_file_basename_from_dist_info_licenses_directory(
    tmp_path: Path,
) -> None:
    site_packages = tmp_path / "site-packages"
    dist_info = site_packages / "pep639_demo-1.0.dist-info"
    (dist_info / "licenses").mkdir(parents=True)
    (dist_info / "licenses" / "LICENSE").write_bytes(b"PEP 639 MIT license.\n")
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.4\n"
        "Name: pep639-demo\n"
        "Version: 1.0\n"
        "License-Expression: MIT\n"
        "License-File: LICENSE\n",
        encoding="utf-8",
    )

    result = export_python_licenses(
        expected_components=[{"name": "pep639-demo", "version": "1.0"}],
        search_paths=[site_packages],
        runtime_version="3.12.9",
        runtime_license_path=_runtime_license(tmp_path),
        legacy_registry={"schema": 3, "entries": []},
    )

    assert result["components"][0]["licenseFiles"][0]["path"] == (
        "pep639_demo-1.0.dist-info/licenses/LICENSE"
    )
