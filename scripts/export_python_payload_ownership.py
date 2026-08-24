"""Export canonical ownership evidence from PyInstaller TOC files.

This helper is executed only by desktop/scripts/python-payload-provenance.mjs
through the fixed release Python with -I -S -B.  It intentionally uses only
the standard library and treats every source outside reviewed roots as fatal.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import platform
import re
import stat
from email.parser import BytesParser
from pathlib import Path, PurePosixPath


MAX_TOC_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 100_000
REPARSE_POINT = 0x400
_PATH_CACHE: dict[str, Path] = {}
_DESCRIPTOR_CACHE: dict[str, dict] = {}
_IDENTITIES: dict[str, tuple[int, int, int, int, int]] = {}


def _canonical(value):
    if isinstance(value, dict):
        return {key: _canonical(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonical(item) for item in value]
    return value


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _checked_path(path: Path, label: str) -> Path:
    cache_key = os.path.normcase(os.path.abspath(path))
    cached = _PATH_CACHE.get(cache_key)
    if cached is not None:
        return cached
    resolved = path.resolve(strict=True)
    cursor = resolved
    while True:
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE_POINT:
            raise ValueError(f"{label} traverses a filesystem redirect")
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular file")
    # 空的包标记（如 CPython 的 urllib/__init__.py）是合法载荷源，不拒绝。
    info = resolved.stat()
    _PATH_CACHE[cache_key] = resolved
    _IDENTITIES[os.path.normcase(str(resolved))] = (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        getattr(info, "st_file_attributes", 0),
    )
    return resolved


def _descriptor(path: Path) -> dict:
    key = os.path.normcase(str(path))
    cached = _DESCRIPTOR_CACHE.get(key)
    if cached is not None:
        return dict(cached)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    result = {"sha256": digest.hexdigest(), "size": size}
    _DESCRIPTOR_CACHE[key] = result
    return dict(result)


def _verify_cached_identities() -> None:
    for raw_path, expected in _IDENTITIES.items():
        path = Path(raw_path)
        info = path.stat()
        actual = (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            getattr(info, "st_file_attributes", 0),
        )
        if actual != expected or stat.S_ISLNK(path.lstat().st_mode) or actual[-1] & REPARSE_POINT:
            raise ValueError(f"payload evidence input changed during ownership export: {path}")


def _read_toc(path: Path):
    path = _checked_path(path, f"PyInstaller TOC {path.name}")
    if path.stat().st_size > MAX_TOC_BYTES:
        raise ValueError(f"PyInstaller TOC {path.name} is oversized")
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"PyInstaller TOC {path.name} is not UTF-8") from error
    if text.startswith("\ufeff") or "\0" in text:
        raise ValueError(f"PyInstaller TOC {path.name} contains unsafe text")
    try:
        return ast.literal_eval(text)
    except (SyntaxError, ValueError) as error:
        raise ValueError(f"PyInstaller TOC {path.name} is not a literal structure") from error


def _normalized_distribution_name(value: str) -> str:
    return "-".join(filter(None, value.lower().replace("_", "-").replace(".", "-").split("-")))


def _distribution_owners(site_packages: Path) -> dict[str, dict]:
    owners: dict[str, dict] = {}
    for metadata_root in sorted(site_packages.glob("*.dist-info"), key=lambda item: item.name.lower()):
        metadata_path = _checked_path(metadata_root / "METADATA", f"distribution metadata {metadata_root.name}")
        record_path = _checked_path(metadata_root / "RECORD", f"distribution RECORD {metadata_root.name}")
        metadata = BytesParser().parsebytes(metadata_path.read_bytes(), headersonly=True)
        name = _normalized_distribution_name(metadata.get("Name", ""))
        version = str(metadata.get("Version", "")).strip()
        if not name or not version:
            raise ValueError(f"distribution metadata identity is incomplete: {metadata_root.name}")
        owner = {"kind": "python-distribution", "name": name, "version": version}
        with record_path.open("r", encoding="utf-8", newline="") as source:
            for row in csv.reader(source):
                if len(row) != 3 or not row[0] or "\\" in row[0]:
                    raise ValueError(f"distribution RECORD row is invalid: {metadata_root.name}")
                pure = PurePosixPath(row[0])
                if pure.is_absolute() or any(part in {"", "."} for part in pure.parts):
                    raise ValueError(f"distribution RECORD path is invalid: {metadata_root.name}")
                candidate = Path(os.path.abspath(site_packages.joinpath(*pure.parts)))
                try:
                    inside = os.path.commonpath((os.path.normcase(candidate), os.path.normcase(site_packages))) == os.path.normcase(site_packages)
                except ValueError:
                    inside = False
                if not inside:
                    continue
                key = os.path.normcase(str(candidate))
                previous = owners.get(key)
                if previous is not None and previous != owner:
                    raise ValueError(f"installed file has ambiguous distribution ownership: {candidate}")
                owners[key] = owner
    if not owners:
        raise ValueError("installed distribution RECORD ownership map is empty")
    return owners


def _checked_toc_entries(value, label: str) -> list[tuple[str, str, str]]:
    if not isinstance(value, list) or len(value) > MAX_ENTRIES:
        raise ValueError(f"{label} entry set is invalid or oversized")
    output = []
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 3
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            or not isinstance(item[2], str)
            or not item[0]
            or not item[2]
        ):
            raise ValueError(f"{label} contains an invalid entry")
        output.append(item)
    return output


def _archive_destination(destination: str, typecode: str) -> str:
    """TOC 工作名带构建计数后缀（如 PYZ-00.pyz），最终归档名是 PYZ.pyz。"""

    if typecode == "PYZ":
        match = re.fullmatch(r"(.+)-\d+\.pyz", destination)
        if match:
            return match.group(1) + ".pyz"
    return destination


def _source_and_owner(
    source: str,
    typecode: str,
    *,
    destination: str,
    base_root: Path,
    os_root: Path,
    os_version: str,
    distribution_owners: dict[str, dict],
    distribution_versions: dict[str, str],
    project_root: Path,
    site_packages: Path,
    work_root: Path,
) -> tuple[dict | None, dict]:
    if not source:
        if typecode != "OPTION":
            raise ValueError("only a PyInstaller OPTION may omit its source")
        return None, {"kind": "build-option", "name": "pyinstaller", "version": "6.21.0"}
    if source == "-" and typecode == "PYMODULE":
        # 命名空间包标记（如 setuptools._vendor.*）没有源文件字节：
        # 归属取目标模块顶层包的分发版身份，锁定集外直接 fail-closed。
        top = destination.split(".", 1)[0].lower().replace("_", "-")
        version = distribution_versions.get(top, "")
        if not version:
            raise ValueError(
                f"namespace package marker has no owning distribution: {destination}"
            )
        return None, {"kind": "python-namespace-marker", "name": top, "version": version}
    if source == "-":
        raise ValueError("only a PyInstaller OPTION or a namespace PYMODULE marker may omit its source")
    path = _checked_path(Path(source), f"PyInstaller payload source {source}")
    key = os.path.normcase(str(path))
    if _within(path, work_root):
        relative_path = path.relative_to(work_root).as_posix()
        owner = {"kind": "build-output", "name": "pyinstaller", "version": "6.21.0"}
        display = f"build/engine/{relative_path}"
    elif _within(path, site_packages):
        owner = distribution_owners.get(key)
        if owner is None:
            raise ValueError(f"site-packages payload file has no RECORD owner: {path}")
        display = f"site-packages/{path.relative_to(site_packages).as_posix()}"
    elif _within(path, project_root):
        relative_path = path.relative_to(project_root).as_posix()
        if relative_path.split("/", 1)[0].lower() in {".venv", "build", "dist"}:
            raise ValueError(f"payload source entered an unowned project build area: {relative_path}")
        owner = {"kind": "project-source", "name": "nachuan", "version": "release-source-snapshot"}
        display = f"project/{relative_path}"
    elif _within(path, base_root):
        owner = {"kind": "python-runtime", "name": "cpython", "version": platform.python_version()}
        display = f"python-runtime/{path.relative_to(base_root).as_posix()}"
    elif _within(path, os_root):
        owner = {"kind": "os-runtime", "name": "windows", "version": os_version}
        display = f"os-runtime/{path.relative_to(os_root).as_posix()}"
    else:
        raise ValueError(f"payload source is owned by an unregistered ambient root: {path}")
    return {"path": display, **_descriptor(path)}, owner


def export(project_root: Path, work_root: Path) -> dict:
    project_root = project_root.resolve(strict=True)
    work_root = work_root.resolve(strict=True)
    expected_work_root = (project_root / "build" / "engine").resolve(strict=True)
    if os.path.normcase(str(work_root)) != os.path.normcase(str(expected_work_root)):
        raise ValueError("PyInstaller ownership export requires the fixed build/engine work root")
    site_packages = (project_root / ".venv" / "Lib" / "site-packages").resolve(strict=True)
    base_root = Path(os.path.realpath(os.sys.base_prefix))
    # Windows 系统运行时（UCRT/api-ms-win 转发 DLL）来自 OS 而不是锁定载荷
    os_root = Path(os.path.realpath(os.environ.get("SystemRoot", r"C:\Windows")))
    os_version = platform.version().strip() or "unknown"
    distribution_owners = _distribution_owners(site_packages)
    distribution_versions = {
        owner["name"]: owner["version"] for owner in distribution_owners.values()
    }

    analysis = _read_toc(work_root / "Analysis-00.toc")
    pyz = _read_toc(work_root / "PYZ-00.toc")
    package = _read_toc(work_root / "PKG-00.toc")
    executable = _read_toc(work_root / "EXE-00.toc")
    if not isinstance(analysis, tuple) or len(analysis) != 20:
        raise ValueError("Analysis-00.toc schema drifted")
    if not isinstance(pyz, tuple) or len(pyz) != 2:
        raise ValueError("PYZ-00.toc schema drifted")
    if not isinstance(package, tuple) or len(package) != 11:
        raise ValueError("PKG-00.toc schema drifted")
    if not isinstance(executable, tuple) or len(executable) != 22:
        raise ValueError("EXE-00.toc schema drifted")

    groups = [
        ("analysis-runtime-hook", analysis[13]),
        ("analysis-module", analysis[14]),
        ("analysis-binary", analysis[15]),
        ("analysis-data", analysis[18]),
        ("analysis-stdlib", analysis[19]),
        ("pyz", pyz[1]),
        ("package", package[2]),
        ("exe-bootstrap", executable[20]),
    ]
    script_entries = [(Path(path).name, path, "PYSOURCE") for path in analysis[0]]
    groups.append(("analysis-entry-script", script_entries))
    if executable[4]:
        groups.append(("exe-icon", [(Path(executable[4]).name, executable[4], "DATA")]))
    if executable[21]:
        groups.append(("exe-python-library", [(Path(executable[21]).name, executable[21], "BINARY")]))

    entries = []
    for scope, raw_entries in groups:
        for destination, source, typecode in _checked_toc_entries(raw_entries, scope):
            source_descriptor, owner = _source_and_owner(
                source,
                typecode,
                destination=destination,
                base_root=base_root,
                os_root=os_root,
                os_version=os_version,
                distribution_owners=distribution_owners,
                distribution_versions=distribution_versions,
                project_root=project_root,
                site_packages=site_packages,
                work_root=work_root,
            )
            entries.append(
                {
                    "destination": _archive_destination(destination, typecode),
                    "owner": owner,
                    "scope": scope,
                    "source": source_descriptor,
                    "type": typecode,
                }
            )
    entries.sort(
        key=lambda item: (
            item["scope"],
            item["destination"],
            item["type"],
            "" if item["source"] is None else item["source"]["path"],
        )
    )
    keys = [
        (item["scope"], item["destination"], item["type"], "" if item["source"] is None else item["source"]["path"])
        for item in entries
    ]
    if not entries or len(entries) > MAX_ENTRIES or len(set(keys)) != len(keys):
        raise ValueError("PyInstaller ownership entries are empty, duplicated, or oversized")
    _verify_cached_identities()
    return _canonical({"entries": entries, "schema": 1})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--work-root", required=True)
    args = parser.parse_args()
    document = export(Path(args.project_root), Path(args.work_root))
    print(json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
