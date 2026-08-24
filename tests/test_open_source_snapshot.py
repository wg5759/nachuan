from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.export_open_source_snapshot import (
    SnapshotError,
    audit_content,
    export_snapshot,
    normalize_publish_bytes,
    verify_snapshot,
)


def _project(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "src" / "cache.log").write_text("not public\n", encoding="utf-8")
    (root / "src" / "generated.123.tmp").write_text("not public\n", encoding="utf-8")
    (root / "public.md").write_text("# Public\n", encoding="utf-8")
    (root / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
    manifest = {
        "schema": "nachuan.open-source-manifest.v1",
        "license": "Apache-2.0",
        "max_file_bytes": 1024,
        "files": ["LICENSE"],
        "mappings": [{"source": "public.md", "target": "README.md"}],
        "roots": ["src"],
        "exclude_prefixes": [],
        "exclude_globs": ["src/generated.*.tmp"],
        "exclude_parts": ["__pycache__"],
        "forbidden_suffixes": [".log", ".exe"],
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    return root, manifest_path, output


def test_export_is_allowlisted_new_history_and_verifiable(tmp_path, monkeypatch):
    root, manifest, output = _project(tmp_path)
    monkeypatch.setattr(
        "scripts.export_open_source_snapshot._git_head", lambda _root: "a" * 40
    )

    candidate = export_snapshot(root, manifest, output, "alpha-001")
    receipt = verify_snapshot(candidate)

    assert (candidate / "README.md").read_text(encoding="utf-8") == "# Public\n"
    assert (candidate / "src" / "main.py").is_file()
    assert not (candidate / "src" / "cache.log").exists()
    assert not (candidate / "src" / "generated.123.tmp").exists()
    assert receipt["history_included"] is False
    assert receipt["source_worktree_dirty"] is True
    assert receipt["file_count"] == 3


def test_existing_candidate_is_never_overwritten(tmp_path, monkeypatch):
    root, manifest, output = _project(tmp_path)
    monkeypatch.setattr(
        "scripts.export_open_source_snapshot._git_head", lambda _root: "a" * 40
    )
    export_snapshot(root, manifest, output, "alpha-001")

    with pytest.raises(SnapshotError, match="already exists"):
        export_snapshot(root, manifest, output, "alpha-001")


def test_snapshot_verifier_rejects_extra_or_changed_files(tmp_path, monkeypatch):
    root, manifest, output = _project(tmp_path)
    monkeypatch.setattr(
        "scripts.export_open_source_snapshot._git_head", lambda _root: "a" * 40
    )
    candidate = export_snapshot(root, manifest, output, "alpha-001")
    (candidate / "rogue.txt").write_text("rogue", encoding="utf-8")
    with pytest.raises(SnapshotError, match="closure"):
        verify_snapshot(candidate)


def test_git_metadata_is_not_part_of_the_published_source_closure(tmp_path, monkeypatch):
    root, manifest, output = _project(tmp_path)
    monkeypatch.setattr(
        "scripts.export_open_source_snapshot._git_head", lambda _root: "a" * 40
    )
    candidate = export_snapshot(root, manifest, output, "alpha-001")
    git_dir = candidate / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n", encoding="utf-8")

    assert verify_snapshot(candidate)["file_count"] == 3


@pytest.mark.parametrize(
    "payload",
    [
        b"-----BEGIN " + b"PRIVATE KEY-----\nsecret",
        b"ghp_" + b"abcdefghijklmnopqrstuvwxyz123456",
        b"AKIA" + b"ABCDEFGHIJKLMNOP",
        b"sk_live_" + b"abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_high_confidence_secrets_are_always_rejected(payload):
    with pytest.raises(SnapshotError, match="high-confidence"):
        audit_content("src/main.py", payload)


def test_fake_secret_is_allowed_only_in_test_fixture():
    payload = b"sk-" + b"a" * 40
    audit_content("tests/test_fake.py", payload)
    with pytest.raises(SnapshotError, match="outside fixtures"):
        audit_content("gateway/provider.py", payload)


def test_real_manifest_keeps_workflows_required_by_public_contract_tests():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "config" / "open-source-manifest.v1.json").read_text("utf-8")
    )

    assert {
        ".github/workflows/ci.yml",
        ".github/workflows/finalize-early-access.yml",
        ".github/workflows/publish-early-access.yml",
        ".github/workflows/release.yml",
    }.issubset(set(manifest["files"]))


def test_real_manifest_keeps_the_human_facing_chinese_maintenance_entry() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "config" / "open-source-manifest.v1.json").read_text("utf-8")
    )
    public_files = set(manifest["files"])

    assert "安装与维护/README.md" in public_files
    assert "install.ps1" in public_files
    assert "docs/CODE_SIGNING_POLICY.md" in public_files
    assert "安装与维护/安装开源版.cmd" in public_files
    assert "安装与维护/更新开源版.cmd" in public_files
    assert "安装与维护/诊断开源版.cmd" in public_files
    assert "安装与维护/卸载开源版.cmd" in public_files
    assert "安装与维护/检查三版本同步状态.cmd" in public_files
    assert "安装与维护/查看免费签名与交付状态.cmd" in public_files
    assert "安装与维护/恢复并启动纳川.cmd" in public_files
    assert "安装与维护/准备FFmpeg构建输入.ps1" in public_files


def test_publish_bytes_match_git_eol_policy() -> None:
    assert normalize_publish_bytes(
        "src/mixed.py", b"one\r\ntwo\rthree\n"
    ) == b"one\ntwo\nthree\n"
    assert normalize_publish_bytes(
        "安装与维护/start.cmd", b"one\ntwo\r\n"
    ) == b"one\r\ntwo\r\n"
    binary = b"\x89PNG\x00\r\n"
    assert normalize_publish_bytes("asset.png", binary) == binary
