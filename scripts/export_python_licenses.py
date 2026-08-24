"""Export fail-closed Python distribution license evidence.

The exporter deliberately reads the installed ``*.dist-info`` metadata and
wheel-provided license files.  It does not infer a license from a package name.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import stat
import sys
import sysconfig
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import unquote, urlsplit

from packaging.markers import InvalidMarker, Marker, default_environment


SCHEMA_VERSION = 1
TOOL_NAME = "nachuan-python-license-exporter"
TOOL_VERSION = "1.0.0"
_NORMALIZED_NAME = re.compile(r"[-_.]+")
_SPDX_EXPRESSION = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+WITH\s+[A-Za-z0-9][A-Za-z0-9.+-]*)?"
    r"(?:\s+(?:AND|OR)\s+[A-Za-z0-9][A-Za-z0-9.+-]*"
    r"(?:\s+WITH\s+[A-Za-z0-9][A-Za-z0-9.+-]*)?)*"
)
_BLOCKED_LICENSES = {"UNKNOWN", "NOASSERTION", "UNLICENSED", "NONE"}
_SPDX_LICENSES = {
    "0BSD",
    "Apache-1.1",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-4-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CNRI-Python",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1-or-later",
    "MIT",
    "MPL-2.0",
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "Zlib",
}
_SPDX_EXCEPTIONS = {"LLVM-exception"}
_MAX_LICENSE_FILE_BYTES = 2 * 1024 * 1024
_HEX_SHA1 = re.compile(r"[0-9a-f]{40}")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
_CLASSIFIER_TO_SPDX = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
}
_LICENSE_FIELD_TO_SPDX = {
    "3-clause bsd license": "BSD-3-Clause",
    "apache": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache 2.0 license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "bsd 3-clause license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "gpl-2.0-or-later": "GPL-2.0-or-later",
    "gplv2+": "GPL-2.0-or-later",
    "http://www.apache.org/licenses/license-2.0": "Apache-2.0",
    "https://opensource.org/license/mit/": "MIT",
    "isc": "ISC",
    "isc license": "ISC",
    "mit": "MIT",
    "mit license": "MIT",
    "mpl-2.0": "MPL-2.0",
    "mpl-2.0 and mit": "MPL-2.0 AND MIT",
    "the mit license": "MIT",
}
_GENERIC_BSD_CLASSIFIER = "License :: OSI Approved :: BSD License"
_BSD_3_CLAUSE_WORDS = (
    "redistribution and use in source and binary forms with or without modification are permitted "
    "provided that the following conditions are met redistributions of source code must retain the "
    "above copyright notice this list of conditions and the following disclaimer redistributions in "
    "binary form must reproduce the above copyright notice this list of conditions and the following "
    "disclaimer in the documentation and or other materials provided with the distribution neither the "
    "name of the copyright holders nor those of its contributors may be used to endorse or promote "
    "products derived from this software without specific prior written permission this software is "
    "provided by the copyright holders and contributors as is and any express or implied warranties "
    "including but not limited to the implied warranties of merchantability and fitness for a particular "
    "purpose are disclaimed in no event shall the copyright holder or contributors be liable for any "
    "direct indirect incidental special exemplary or consequential damages including but not limited to "
    "procurement of substitute goods or services loss of use data or profits or business interruption "
    "however caused and on any theory of liability whether in contract strict liability or tort including "
    "negligence or otherwise arising in any way out of the use of this software even if advised of the "
    "possibility of such damage"
)
_BSD_3_CLAUSE_HOLDER_NAMES_WORDS = _BSD_3_CLAUSE_WORDS.replace(
    "neither the name of the copyright holders nor those of its contributors",
    "neither the name of the copyright holder nor the names of its contributors",
)


class PythonLicenseError(RuntimeError):
    """The installed Python license inventory is incomplete or ambiguous."""


def _normalize_name(value: object) -> str:
    name = _NORMALIZED_NAME.sub("-", str(value or "").strip()).lower()
    if not name or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name):
        raise PythonLicenseError("Python distribution name is invalid")
    return name


def _checked_spdx(value: object) -> str:
    expression = " ".join(str(value or "").strip().split())
    if (
        not expression
        or expression.upper() in _BLOCKED_LICENSES
        or any(token in _BLOCKED_LICENSES for token in expression.upper().split())
        or not _SPDX_EXPRESSION.fullmatch(expression)
    ):
        raise PythonLicenseError("Python distribution license is unknown or not a canonical SPDX expression")
    tokens = expression.split()
    for index, token in enumerate(tokens):
        if token in {"AND", "OR", "WITH"}:
            continue
        if index > 0 and tokens[index - 1] == "WITH":
            if token not in _SPDX_EXCEPTIONS:
                raise PythonLicenseError("Python distribution license uses an unknown SPDX exception")
        elif token not in _SPDX_LICENSES:
            raise PythonLicenseError("Python distribution license uses an unknown SPDX license id")
    return expression


def _checked_text_file(path: Path, *, display_path: str) -> dict[str, object]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise PythonLicenseError(f"license file is not a regular file: {display_path}")
        if info.st_size <= 0 or info.st_size > _MAX_LICENSE_FILE_BYTES:
            raise PythonLicenseError(f"license file is empty or oversized: {display_path}")
        data = path.read_bytes()
    except PythonLicenseError:
        raise
    except OSError as exc:
        raise PythonLicenseError(f"license file is unavailable or not UTF-8: {display_path}") from exc
    return _checked_text_bytes(data, display_path=display_path)


def _checked_text_bytes(data: bytes, *, display_path: str) -> dict[str, object]:
    if len(data) <= 0 or len(data) > _MAX_LICENSE_FILE_BYTES:
        raise PythonLicenseError(f"license file is empty or oversized: {display_path}")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise PythonLicenseError(f"license file is unavailable or not UTF-8: {display_path}") from exc
    if not text.strip() or "\x00" in text:
        raise PythonLicenseError(f"license file has no usable text: {display_path}")
    return {
        "path": display_path.replace("\\", "/"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "text": text,
    }


def _checked_registry_path(value: object, *, label: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or path.as_posix() != text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PythonLicenseError(f"{label} path is unsafe")
    return text


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _distribution_path(distribution: importlib.metadata.Distribution, roots: Sequence[Path]) -> Path:
    raw = getattr(distribution, "_path", None)
    if raw is None:
        raise PythonLicenseError("installed distribution metadata path is unavailable")
    path = Path(raw).resolve(strict=True)
    if path.is_symlink() or not path.is_dir() or not path.name.lower().endswith(".dist-info"):
        raise PythonLicenseError("installed distribution metadata path is unsafe")
    for root in roots:
        try:
            path.relative_to(root)
            return path
        except ValueError:
            continue
    raise PythonLicenseError("installed distribution metadata escapes the selected environment")


def _metadata_license_files(
    distribution: importlib.metadata.Distribution,
    dist_info: Path,
    root: Path,
    *,
    required: bool = True,
) -> list[dict[str, object]]:
    references = [
        PurePosixPath(str(value).strip().replace("\\", "/"))
        for value in distribution.metadata.get_all("License-File") or []
    ]
    for installed_file in distribution.files or []:
        relative = PurePosixPath(str(installed_file).replace("\\", "/"))
        if (
            len(relative.parts) >= 2
            and relative.parts[0].casefold() == dist_info.name.casefold()
            and re.fullmatch(
                r"(?:licen[cs]e|copying|notice)(?:[._-].*)?",
                relative.name,
                flags=re.IGNORECASE,
            )
        ):
            references.append(PurePosixPath(*relative.parts[1:]))
    files: list[dict[str, object]] = []
    seen: dict[str, str] = {}
    for raw_reference in references:
        reference = raw_reference.as_posix()
        parts = reference.split("/")
        if not reference or any(part in {"", ".", ".."} for part in parts):
            raise PythonLicenseError("wheel License-File path is unsafe")
        unresolved = [dist_info / Path(*parts)]
        if parts[0].casefold() != "licenses":
            unresolved.append(dist_info / "licenses" / Path(*parts))
        candidates = []
        for path in unresolved:
            try:
                candidates.append(path.resolve(strict=True))
            except FileNotFoundError:
                continue
        unique_candidates = list(dict.fromkeys(candidates))
        if len(unique_candidates) != 1:
            raise PythonLicenseError(
                f"wheel License-File is missing or ambiguous after installation: {reference}"
            )
        candidate = unique_candidates[0]
        try:
            candidate.relative_to(dist_info)
        except ValueError as exc:
            raise PythonLicenseError("wheel License-File escapes distribution metadata") from exc
        display = candidate.relative_to(root).as_posix()
        folded = display.casefold()
        if folded in seen:
            if seen[folded] != display:
                raise PythonLicenseError(f"case-colliding wheel License-File: {display}")
            continue
        seen[folded] = display
        files.append(_checked_text_file(candidate, display_path=display))
    files.sort(key=lambda item: str(item["path"]))
    if required and not files:
        raise PythonLicenseError("installed distribution has no wheel license text")
    return files


def _normalized_license_words(text: object) -> str:
    retained_lines = []
    for line in str(text or "").casefold().splitlines():
        stripped = line.strip()
        if re.match(r"^(?:copyright\b|©)", stripped) or stripped.rstrip(".") == "all rights reserved":
            continue
        stripped = re.sub(r"^(?:[*+-]|\d+[.)]?)\s+", "", stripped)
        retained_lines.append(stripped)
    return " ".join(re.findall(r"[a-z0-9]+", "\n".join(retained_lines)))


def _license_file_expression(license_files: Sequence[Mapping[str, object]]) -> str | None:
    expressions = []
    for license_file in license_files:
        words = _normalized_license_words(license_file.get("text"))
        if words in {_BSD_3_CLAUSE_WORDS, _BSD_3_CLAUSE_HOLDER_NAMES_WORDS}:
            expressions.append("BSD-3-Clause")
        else:
            return None
    if expressions and len(set(expressions)) == 1:
        return expressions[0]
    return None


def _checked_registry(registry: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    if set(registry) != {"entries", "schema"} or registry.get("schema") != 3:
        raise PythonLicenseError("legacy license registry is not canonical")
    entries = registry.get("entries")
    if not isinstance(entries, list):
        raise PythonLicenseError("legacy license registry entries must be an array")
    parsed: dict[tuple[str, str], Mapping[str, Any]] = {}
    previous = ""
    for raw in entries:
        basic_fields = {
            "metadataSha256",
            "name",
            "spdxExpression",
            "version",
        }
        reviewed_fields = basic_fields | {"lockedArtifact", "notice", "upstream"}
        raw_fields = frozenset(raw) if isinstance(raw, Mapping) else frozenset()
        if not isinstance(raw, Mapping) or raw_fields not in {
            frozenset(basic_fields),
            frozenset(reviewed_fields),
        }:
            raise PythonLicenseError("legacy license registry entry fields are not canonical")
        name = _normalize_name(raw.get("name"))
        version = str(raw.get("version") or "").strip()
        metadata_sha256 = str(raw.get("metadataSha256") or "")
        expression = _checked_spdx(raw.get("spdxExpression"))
        key_text = f"{name}@{version}"
        if (
            not version
            or not _HEX_SHA256.fullmatch(metadata_sha256)
            or key_text <= previous
            or (name, version) in parsed
        ):
            raise PythonLicenseError("legacy license registry entries are invalid, duplicated, or unsorted")
        previous = key_text
        entry: dict[str, Any] = {
            "metadataSha256": metadata_sha256,
            "spdxExpression": expression,
        }
        if raw_fields == frozenset(reviewed_fields):
            locked_artifact = raw.get("lockedArtifact")
            notice = raw.get("notice")
            upstream = raw.get("upstream")
            if not isinstance(locked_artifact, Mapping) or set(locked_artifact) != {
                "filename",
                "kind",
                "sha256",
            }:
                raise PythonLicenseError("reviewed notice locked artifact is not canonical")
            artifact_filename = str(locked_artifact.get("filename") or "").strip()
            artifact_kind = str(locked_artifact.get("kind") or "").strip()
            artifact_sha256 = str(locked_artifact.get("sha256") or "")
            if (
                not artifact_filename
                or PurePosixPath(artifact_filename).name != artifact_filename
                or artifact_kind not in {"sdist", "wheel"}
                or not _HEX_SHA256.fullmatch(artifact_sha256)
            ):
                raise PythonLicenseError("reviewed notice locked artifact is invalid")
            notice_file_fields = {
                "gitBlobSha1",
                "path",
                "sha256",
                "sourceUrl",
            }
            notice_inline_fields = {
                "base64",
                "displayPath",
                "gitBlobSha1",
                "sha256",
                "sourceUrl",
            }
            notice_fields = frozenset(notice) if isinstance(notice, Mapping) else frozenset()
            if not isinstance(notice, Mapping) or notice_fields not in {
                frozenset(notice_file_fields),
                frozenset(notice_inline_fields),
            }:
                raise PythonLicenseError("reviewed notice descriptor is not canonical")
            notice_blob = str(notice.get("gitBlobSha1") or "")
            notice_sha256 = str(notice.get("sha256") or "")
            source_url = str(notice.get("sourceUrl") or "").strip()
            if not _HEX_SHA1.fullmatch(notice_blob) or not _HEX_SHA256.fullmatch(notice_sha256):
                raise PythonLicenseError("reviewed notice hashes are invalid")
            parsed_notice: dict[str, str] = {
                "gitBlobSha1": notice_blob,
                "sha256": notice_sha256,
                "sourceUrl": source_url,
            }
            if notice_fields == frozenset(notice_inline_fields):
                encoded = str(notice.get("base64") or "")
                display_path = _checked_registry_path(
                    notice.get("displayPath"),
                    label="reviewed inline notice",
                )
                try:
                    inline_bytes = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise PythonLicenseError("reviewed inline notice is not canonical base64") from exc
                if base64.b64encode(inline_bytes).decode("ascii") != encoded:
                    raise PythonLicenseError("reviewed inline notice is not canonical base64")
                _checked_text_bytes(inline_bytes, display_path=display_path)
                if (
                    hashlib.sha256(inline_bytes).hexdigest() != notice_sha256
                    or _git_blob_sha1(inline_bytes) != notice_blob
                ):
                    raise PythonLicenseError("reviewed inline notice hash drifted")
                parsed_notice.update({"base64": encoded, "displayPath": display_path})
            else:
                notice_path = _checked_registry_path(notice.get("path"), label="reviewed notice")
                parsed_notice["path"] = notice_path
            if not isinstance(upstream, Mapping) or set(upstream) != {
                "commit",
                "declaredLicense",
                "declaredName",
                "declaredVersion",
                "evidence",
                "licensePath",
            }:
                raise PythonLicenseError("reviewed notice upstream evidence is not canonical")
            commit = str(upstream.get("commit") or "")
            declared_license = str(upstream.get("declaredLicense") or "").strip()
            declared_name = _normalize_name(upstream.get("declaredName"))
            declared_version = str(upstream.get("declaredVersion") or "").strip()
            license_path = _checked_registry_path(upstream.get("licensePath"), label="upstream license")
            if (
                not _HEX_SHA1.fullmatch(commit)
                or not declared_license
                or declared_name != name
                or declared_version != version
            ):
                raise PythonLicenseError("reviewed notice upstream evidence is invalid or drifted")
            raw_evidence = upstream.get("evidence")
            if not isinstance(raw_evidence, list) or not raw_evidence:
                raise PythonLicenseError("reviewed notice upstream evidence files are missing")
            evidence_files = []
            previous_evidence = ""
            for raw_file in raw_evidence:
                if not isinstance(raw_file, Mapping) or set(raw_file) != {
                    "gitBlobSha1",
                    "path",
                    "role",
                    "sha256",
                }:
                    raise PythonLicenseError("reviewed notice upstream evidence file is not canonical")
                evidence_blob = str(raw_file.get("gitBlobSha1") or "")
                evidence_path = _checked_registry_path(
                    raw_file.get("path"),
                    label="upstream evidence",
                )
                evidence_role = str(raw_file.get("role") or "").strip()
                evidence_sha256 = str(raw_file.get("sha256") or "")
                evidence_key = f"{evidence_role}:{evidence_path}"
                if (
                    not _HEX_SHA1.fullmatch(evidence_blob)
                    or not re.fullmatch(r"[a-z][a-z0-9-]*", evidence_role)
                    or not _HEX_SHA256.fullmatch(evidence_sha256)
                    or evidence_key <= previous_evidence
                ):
                    raise PythonLicenseError("reviewed notice upstream evidence file is invalid or unsorted")
                previous_evidence = evidence_key
                evidence_files.append(
                    {
                        "gitBlobSha1": evidence_blob,
                        "path": evidence_path,
                        "role": evidence_role,
                        "sha256": evidence_sha256,
                    }
                )
            source_match = re.fullmatch(
                r"https://raw\.githubusercontent\.com/"
                r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/([0-9a-f]{40})/(.+)",
                source_url,
            )
            if not source_match or source_match.group(1) != commit:
                raise PythonLicenseError("reviewed notice source commit drifted")
            if unquote(source_match.group(2)) != license_path:
                raise PythonLicenseError("reviewed notice source path drifted")
            entry.update(
                {
                    "lockedArtifact": {
                        "filename": artifact_filename,
                        "kind": artifact_kind,
                        "sha256": artifact_sha256,
                    },
                    "notice": parsed_notice,
                    "upstream": {
                        "commit": commit,
                        "declaredLicense": declared_license,
                        "declaredName": declared_name,
                        "declaredVersion": declared_version,
                        "evidence": evidence_files,
                        "licensePath": license_path,
                    },
                }
            )
        parsed[(name, version)] = entry
    return parsed


def _reviewed_notice_file(
    entry: Mapping[str, Any],
    *,
    registry_root: str | os.PathLike[str] | None,
) -> list[dict[str, object]]:
    notice = entry["notice"]
    if "base64" in notice:
        try:
            data = base64.b64decode(notice["base64"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise PythonLicenseError("reviewed inline notice is not canonical base64") from exc
        evidence = _checked_text_bytes(data, display_path=notice["displayPath"])
        if (
            evidence["sha256"] != notice["sha256"]
            or _git_blob_sha1(data) != notice["gitBlobSha1"]
        ):
            raise PythonLicenseError("reviewed inline notice hash drifted")
        return [evidence]
    if registry_root is None:
        raise PythonLicenseError("reviewed notice registry root is unavailable")
    root = Path(registry_root).resolve(strict=True)
    if not root.is_dir():
        raise PythonLicenseError("reviewed notice registry root is invalid")
    display_path = notice["path"]
    candidate = root.joinpath(*PurePosixPath(display_path).parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise PythonLicenseError("reviewed notice file escapes its registry root") from exc
    evidence = _checked_text_file(candidate, display_path=display_path)
    if evidence["sha256"] != notice["sha256"]:
        raise PythonLicenseError("reviewed notice SHA256 drifted")
    notice_bytes = str(evidence["text"]).encode("utf-8")
    if _git_blob_sha1(notice_bytes) != notice["gitBlobSha1"]:
        raise PythonLicenseError("reviewed notice git blob hash drifted")
    return [evidence]


def _check_locked_artifact(
    frozen_lock: Mapping[str, Any] | None,
    *,
    name: str,
    version: str,
    locked_artifact: Mapping[str, str],
) -> None:
    if not isinstance(frozen_lock, Mapping) or frozen_lock.get("version") != 1:
        raise PythonLicenseError("reviewed notice requires a canonical uv lock")
    packages = frozen_lock.get("package")
    if not isinstance(packages, list):
        raise PythonLicenseError("reviewed notice requires uv lock packages")
    matches = []
    for package in packages:
        if not isinstance(package, Mapping):
            raise PythonLicenseError("uv lock package is invalid")
        if _normalize_name(package.get("name")) == name and str(package.get("version") or "") == version:
            matches.append(package)
    if len(matches) != 1:
        raise PythonLicenseError("reviewed notice locked package drifted")
    package = matches[0]
    artifact_kind = locked_artifact["kind"]
    if artifact_kind == "sdist":
        candidates = [package.get("sdist")]
    else:
        wheels = package.get("wheels")
        candidates = wheels if isinstance(wheels, list) else []
    expected_filename = locked_artifact["filename"]
    expected_hash = f"sha256:{locked_artifact['sha256']}"
    matching_artifacts = []
    for artifact in candidates:
        if not isinstance(artifact, Mapping):
            continue
        url = str(artifact.get("url") or "")
        parsed_url = urlsplit(url)
        filename = unquote(PurePosixPath(parsed_url.path).name)
        if (
            parsed_url.scheme == "https"
            and parsed_url.netloc
            and not parsed_url.query
            and not parsed_url.fragment
            and filename == expected_filename
            and artifact.get("hash") == expected_hash
        ):
            matching_artifacts.append(artifact)
    if len(matching_artifacts) != 1:
        raise PythonLicenseError("reviewed notice locked artifact drifted")


def _check_registry_metadata(entry: Mapping[str, Any], dist_info: Path) -> None:
    try:
        metadata_bytes = (dist_info / "METADATA").read_bytes()
    except OSError as exc:
        raise PythonLicenseError("installed distribution METADATA is unavailable") from exc
    if hashlib.sha256(metadata_bytes).hexdigest() != entry["metadataSha256"]:
        raise PythonLicenseError("legacy license registry METADATA hash drifted")


def _metadata_license(
    distribution: importlib.metadata.Distribution,
    *,
    name: str,
    version: str,
    dist_info: Path,
    registry: Mapping[tuple[str, str], Mapping[str, Any]],
    license_files: Sequence[Mapping[str, object]],
) -> tuple[str, str]:
    declared = str(distribution.metadata.get("License-Expression") or "").strip()
    if declared:
        return _checked_spdx(declared), "metadata-license-expression"
    classifiers = [
        value.strip()
        for value in distribution.metadata.get_all("Classifier") or []
        if value.strip().startswith("License ::")
    ]
    normalized = {_CLASSIFIER_TO_SPDX[value] for value in classifiers if value in _CLASSIFIER_TO_SPDX}
    unknown = [value for value in classifiers if value not in _CLASSIFIER_TO_SPDX]
    inferred = _license_file_expression(license_files)
    if len(normalized) == 1 and not unknown:
        classifier_expression = normalized.pop()
        if inferred is not None and inferred != classifier_expression:
            raise PythonLicenseError("wheel license text conflicts with its license classifier")
        return _checked_spdx(classifier_expression), "metadata-classifier"
    legacy_field = " ".join(str(distribution.metadata.get("License") or "").strip().split()).casefold()
    if legacy_field in _LICENSE_FIELD_TO_SPDX:
        return _checked_spdx(_LICENSE_FIELD_TO_SPDX[legacy_field]), "metadata-license"
    if inferred:
        for classifier in classifiers:
            mapped = _CLASSIFIER_TO_SPDX.get(classifier)
            if mapped is not None and mapped != inferred:
                raise PythonLicenseError("wheel license text conflicts with its license classifier")
            if mapped is None and not (
                classifier == _GENERIC_BSD_CLASSIFIER and inferred in {"BSD-2-Clause", "BSD-3-Clause"}
            ):
                raise PythonLicenseError("wheel license text has an unsupported classifier conflict")
        return _checked_spdx(inferred), "license-file"
    entry = registry.get((name, version))
    if entry:
        _check_registry_metadata(entry, dist_info)
        return entry["spdxExpression"], "registry"
    raise PythonLicenseError("Python distribution legacy license metadata is missing or ambiguous")


def export_python_licenses(
    *,
    expected_components: Iterable[Mapping[str, object]],
    search_paths: Sequence[str | os.PathLike[str]],
    runtime_version: str,
    runtime_license_path: str | os.PathLike[str],
    legacy_registry: Mapping[str, Any],
    registry_root: str | os.PathLike[str] | None = None,
    frozen_lock: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    """Return canonical evidence for exactly the expected installed packages."""

    roots = [Path(path).resolve(strict=True) for path in search_paths]
    if not roots:
        raise PythonLicenseError("at least one site-packages root is required")
    registry = _checked_registry(legacy_registry)
    expected: dict[str, set[str]] = {}
    for item in expected_components:
        name = _normalize_name(item.get("name"))
        version = str(item.get("version") or "").strip()
        if not version:
            raise PythonLicenseError("expected Python package set is invalid")
        versions = expected.setdefault(name, set())
        if version in versions:
            raise PythonLicenseError("expected Python package set is duplicated")
        versions.add(version)

    installed: dict[str, tuple[str, importlib.metadata.Distribution, Path, Path]] = {}
    for distribution in importlib.metadata.distributions(path=[str(path) for path in roots]):
        name = _normalize_name(distribution.metadata.get("Name"))
        version = str(distribution.version or "").strip()
        dist_info = _distribution_path(distribution, roots)
        root = next(path for path in roots if dist_info.is_relative_to(path))
        if not version or name in installed:
            raise PythonLicenseError("installed Python package set is invalid or duplicated")
        installed[name] = (version, distribution, dist_info, root)

    editable_roots = []
    if frozen_lock is not None:
        for package in frozen_lock.get("package", []):
            source = package.get("source") if isinstance(package, Mapping) else None
            if isinstance(source, Mapping) and source.get("editable") == ".":
                editable_roots.append(package)
    if len(editable_roots) > 1:
        raise PythonLicenseError("frozen lock contains multiple first-party editable roots")
    if editable_roots:
        root_package = editable_roots[0]
        root_name = _normalize_name(root_package.get("name"))
        root_version = str(root_package.get("version") or "").strip()
        if not root_version:
            raise PythonLicenseError("frozen first-party editable identity is invalid")
        installed_root = installed.get(root_name)
        if installed_root is not None:
            installed_version, _, dist_info, _ = installed_root
            if installed_version != root_version:
                raise PythonLicenseError("installed first-party editable version drifted from the frozen lock")
            direct_url_path = dist_info / "direct_url.json"
            try:
                direct_url_info = direct_url_path.lstat()
                direct_url_bytes = direct_url_path.read_bytes()
                direct_url = json.loads(direct_url_bytes.decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PythonLicenseError("installed first-party distribution is not an explicit editable") from exc
            if (
                stat.S_ISLNK(direct_url_info.st_mode)
                or not stat.S_ISREG(direct_url_info.st_mode)
                or not (0 < len(direct_url_bytes) <= 16 * 1024)
                or set(direct_url) != {"dir_info", "url"}
                or direct_url.get("dir_info") != {"editable": True}
            ):
                raise PythonLicenseError("installed first-party distribution is not an explicit editable")
            parsed_direct_url = urlsplit(str(direct_url.get("url") or ""))
            if (
                parsed_direct_url.scheme != "file"
                or parsed_direct_url.username
                or parsed_direct_url.password
                or parsed_direct_url.query
                or parsed_direct_url.fragment
                or not parsed_direct_url.path
            ):
                raise PythonLicenseError("installed first-party editable URL is invalid")
            installed.pop(root_name)

    missing = sorted(set(expected) - set(installed))
    extra = sorted(set(installed) - set(expected))
    drifted = sorted(
        f"{name}={item[0]} not-in {','.join(sorted(expected[name]))}"
        for name, item in installed.items()
        if name in expected and item[0] not in expected[name]
    )
    if missing or extra or drifted:
        details = "; ".join(
            [
                f"missing={','.join(missing[:20]) or '-'}",
                f"extra={','.join(extra[:20]) or '-'}",
                f"versionDrift={','.join(drifted[:20]) or '-'}",
            ]
        )
        raise PythonLicenseError(
            f"installed Python packages do not exactly match the expected frozen package set: {details}"
        )

    components = []
    used_registry: set[tuple[str, str]] = set()
    for name in sorted(installed):
        version, distribution, dist_info, root = installed[name]
        try:
            license_files = _metadata_license_files(
                distribution,
                dist_info,
                root,
                required=False,
            )
            expression, source = _metadata_license(
                distribution,
                name=name,
                version=version,
                dist_info=dist_info,
                registry=registry,
                license_files=license_files,
            )
            entry = registry.get((name, version))
            if entry is not None and "notice" in entry:
                if expression != entry["spdxExpression"]:
                    raise PythonLicenseError("reviewed notice conflicts with resolved license metadata")
                _check_registry_metadata(entry, dist_info)
                _check_locked_artifact(
                    frozen_lock,
                    name=name,
                    version=version,
                    locked_artifact=entry["lockedArtifact"],
                )
                license_files = _reviewed_notice_file(entry, registry_root=registry_root)
                used_registry.add((name, version))
            else:
                if not license_files:
                    raise PythonLicenseError("installed distribution has no wheel license text")
        except PythonLicenseError as exc:
            raise PythonLicenseError(f"{name}@{version}: {exc}") from exc
        if source == "registry":
            used_registry.add((name, version))
        components.append(
            {
                "licenseExpression": expression,
                "licenseFiles": license_files,
                "licenseSource": source,
                "name": name,
                "version": version,
            }
        )
    if used_registry != set(registry):
        raise PythonLicenseError("legacy license registry contains unused or stale entries")

    runtime_version = str(runtime_version or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", runtime_version):
        raise PythonLicenseError("CPython runtime version is invalid")
    runtime_path = Path(runtime_license_path).resolve(strict=True)
    runtime_file = _checked_text_file(runtime_path, display_path=runtime_path.name)
    return {
        "components": components,
        "runtime": {
            "implementation": "CPython",
            "licenseFile": runtime_file,
            "version": runtime_version,
        },
        "schema": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
    }


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 64 * 1024 * 1024:
            raise PythonLicenseError(f"{label} must be a bounded regular file")
        document = json.loads(path.read_text(encoding="utf-8"))
    except PythonLicenseError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PythonLicenseError(f"{label} is unavailable or invalid JSON") from exc
    if not isinstance(document, Mapping):
        raise PythonLicenseError(f"{label} must be a JSON object")
    return document


def _read_toml(path: Path, label: str) -> Mapping[str, Any]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 64 * 1024 * 1024:
            raise PythonLicenseError(f"{label} must be a bounded regular file")
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except PythonLicenseError:
        raise
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise PythonLicenseError(f"{label} is unavailable or invalid TOML") from exc
    if not isinstance(document, Mapping):
        raise PythonLicenseError(f"{label} must be a TOML document")
    return document


def _sbom_components(document: Mapping[str, Any]) -> list[dict[str, str]]:
    components = document.get("components")
    if (
        document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") != "1.5"
        or not isinstance(components, list)
        or not components
    ):
        raise PythonLicenseError("Python SBOM must be a non-empty CycloneDX 1.5 document")
    result = []
    seen: set[tuple[str, str]] = set()
    marker_environment = default_environment()
    for component in components:
        if not isinstance(component, Mapping):
            raise PythonLicenseError("Python SBOM contains an invalid component")
        name = _normalize_name(component.get("name"))
        version = str(component.get("version") or "").strip()
        purl = str(component.get("purl") or "").strip().lower()
        properties = component.get("properties", [])
        if not isinstance(properties, list):
            raise PythonLicenseError("Python SBOM component properties must be an array")
        markers = []
        for prop in properties:
            if not isinstance(prop, Mapping):
                raise PythonLicenseError("Python SBOM component property is invalid")
            if prop.get("name") == "uv:package:marker":
                marker = str(prop.get("value") or "").strip()
                if not marker:
                    raise PythonLicenseError("Python SBOM component marker is empty")
                markers.append(marker)
        if len(markers) > 1:
            raise PythonLicenseError("Python SBOM component has duplicate environment markers")
        if markers:
            try:
                active = Marker(markers[0]).evaluate(marker_environment)
            except InvalidMarker as exc:
                raise PythonLicenseError("Python SBOM component has an invalid PEP 508 marker") from exc
            if not active:
                continue
        if not version or not purl.startswith("pkg:pypi/") or (name, version) in seen:
            raise PythonLicenseError("Python SBOM contains an invalid or duplicate PyPI component")
        seen.add((name, version))
        result.append({"name": name, "version": version})
    result.sort(key=lambda item: (item["name"], item["version"]))
    return result


def _default_search_paths() -> list[str]:
    paths = []
    for key in ("purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value and value not in paths:
            paths.append(value)
    return paths


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export canonical installed Python license evidence")
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--site-packages", action="append")
    parser.add_argument("--runtime-version", default=platform.python_version())
    parser.add_argument("--runtime-license", default=str(Path(sys.base_prefix) / "LICENSE.txt"))
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)

    sbom = _read_json(Path(arguments.sbom), "Python SBOM")
    registry = _read_json(Path(arguments.registry), "legacy license registry")
    frozen_lock = _read_toml(Path(arguments.lock), "uv lock")
    result = export_python_licenses(
        expected_components=_sbom_components(sbom),
        search_paths=arguments.site_packages or _default_search_paths(),
        runtime_version=arguments.runtime_version,
        runtime_license_path=arguments.runtime_license,
        legacy_registry=registry,
        registry_root=Path(arguments.registry).resolve(strict=True).parent,
        frozen_lock=frozen_lock,
    )
    output = Path(arguments.output)
    if output.exists() or output.parent.is_symlink() or not output.parent.is_dir():
        raise PythonLicenseError("output path must be a new file in an existing real directory")
    payload = f"{json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)}\n"
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PythonLicenseError as exc:
        print(f"[python-license-export] BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
