"""export_python_payload_ownership 的源归属单元测试（2026-08-18 构建门禁修复）。

覆盖：合法空常规文件（CPython urllib/__init__.py 式包标记）、
setuptools 式命名空间标记（source '-'）、各类 fail-closed 拒绝。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.export_python_payload_ownership import _source_and_owner

_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@pytest.fixture
def roots(tmp_path):
    base = tmp_path / "py"
    site = tmp_path / "site-packages"
    proj = tmp_path / "proj"
    work = tmp_path / "build" / "engine"
    osroot = tmp_path / "Windows"
    for d in (base, site, proj, work, osroot):
        d.mkdir(parents=True, exist_ok=True)
    return {
        "base_root": base,
        "site_packages": site,
        "project_root": proj,
        "work_root": work,
        "os_root": osroot,
        "os_version": "10.0.22631",
        "distribution_owners": {},
        "distribution_versions": {"setuptools": "83.0.0"},
    }


def test_empty_regular_file_is_a_legitimate_source(roots):
    target = roots["site_packages"] / "demo" / "__init__.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"")
    key = str(target.resolve()).lower()
    roots["distribution_owners"][key] = {
        "kind": "python-distribution",
        "name": "demo",
        "version": "1.0.0",
    }
    descriptor, owner = _source_and_owner(
        str(target), "PYMODULE", destination="demo", **roots
    )
    assert descriptor is not None
    assert descriptor["size"] == 0
    assert descriptor["sha256"] == _EMPTY_SHA256
    assert owner == {"kind": "python-distribution", "name": "demo", "version": "1.0.0"}


def test_namespace_marker_binds_top_level_distribution(roots):
    descriptor, owner = _source_and_owner(
        "-", "PYMODULE", destination="setuptools._vendor.jaraco", **roots
    )
    assert descriptor is None
    assert owner == {
        "kind": "python-namespace-marker",
        "name": "setuptools",
        "version": "83.0.0",
    }


def test_namespace_marker_without_owning_distribution_fails_closed(roots):
    roots["distribution_versions"] = {}
    with pytest.raises(ValueError, match="namespace package marker"):
        _source_and_owner("-", "PYMODULE", destination="ghost.ns", **roots)


def test_dash_source_with_non_pymodule_type_is_rejected(roots):
    with pytest.raises(ValueError, match="omit its source"):
        _source_and_owner("-", "DATA", destination="demo.data", **roots)


def test_missing_source_file_is_rejected(roots):
    with pytest.raises(Exception):
        _source_and_owner(
            str(roots["site_packages"] / "nope.py"),
            "PYMODULE",
            destination="nope",
            **roots,
        )


def test_site_packages_file_without_record_owner_is_rejected(roots):
    target = roots["site_packages"] / "rogue" / "mod.py"
    target.parent.mkdir(parents=True)
    target.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no RECORD owner"):
        _source_and_owner(str(target), "PYMODULE", destination="rogue.mod", **roots)


def test_os_runtime_source_is_owned_by_host_windows(roots):
    system32 = roots["os_root"] / "System32"
    system32.mkdir(parents=True)
    dll = system32 / "api-ms-win-crt-convert-l1-1-0.dll"
    dll.write_bytes(b"MZ-fake")
    descriptor, owner = _source_and_owner(
        str(dll), "BINARY", destination="api-ms-win-crt-convert-l1-1-0.dll", **roots
    )
    assert owner["kind"] == "os-runtime"
    assert owner["name"] == "windows"
    assert descriptor["size"] == 7


def test_pyz_work_name_maps_to_final_archive_name():
    from scripts.export_python_payload_ownership import _archive_destination

    assert _archive_destination("PYZ-00.pyz", "PYZ") == "PYZ.pyz"
    assert _archive_destination("PYZ-07.pyz", "PYZ") == "PYZ.pyz"
    assert _archive_destination("struct", "PYMODULE") == "struct"
    assert _archive_destination("VCRUNTIME140.dll", "BINARY") == "VCRUNTIME140.dll"
