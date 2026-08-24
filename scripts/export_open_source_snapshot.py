"""Generate and audit a new-history, allowlisted Nachuan source snapshot."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_MANIFEST = _PROJECT_ROOT / "config" / "open-source-manifest.v1.json"
_APPROVED_OUTPUT_ROOT = _PROJECT_ROOT / "安装与维护" / "开源发布" / "候选源码"
_CANDIDATE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_HIGH_CONFIDENCE_SECRETS = (
    ("private_key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github_token", re.compile(rb"gh[opusr]_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(rb"AIza[0-9A-Za-z_-]{30,}")),
    ("stripe_live_key", re.compile(rb"sk_live_[0-9A-Za-z]{16,}")),
    ("slack_token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{16,}")),
)
_GENERIC_SECRET = re.compile(rb"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{24,}")
_GENERIC_SECRET_ALLOWED_PREFIXES = (
    "tests/",
    "desktop/scripts/",
    "desktop/src/",
    "docs/adr/",
)


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    source: Path
    target: str


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _relative_posix(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SnapshotError("snapshot source escaped project root") from exc


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & 0x400)


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError("open-source manifest is unreadable") from exc
    expected = {
        "schema",
        "license",
        "max_file_bytes",
        "files",
        "mappings",
        "roots",
        "exclude_prefixes",
        "exclude_globs",
        "exclude_parts",
        "forbidden_suffixes",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise SnapshotError("open-source manifest shape is invalid")
    if raw["schema"] != "nachuan.open-source-manifest.v1":
        raise SnapshotError("open-source manifest schema is unsupported")
    if raw["license"] != "Apache-2.0":
        raise SnapshotError("open-source manifest license is invalid")
    if not isinstance(raw["max_file_bytes"], int) or not 1 <= raw["max_file_bytes"] <= 64 * 1024 * 1024:
        raise SnapshotError("open-source manifest size bound is invalid")
    for name in (
        "files",
        "mappings",
        "roots",
        "exclude_prefixes",
        "exclude_globs",
        "exclude_parts",
        "forbidden_suffixes",
    ):
        if not isinstance(raw[name], list):
            raise SnapshotError(f"open-source manifest {name} is invalid")
    return raw


def _excluded(relative: str, manifest: dict[str, Any]) -> bool:
    folded = relative.casefold()
    parts = {part.casefold() for part in Path(relative).parts}
    if parts & {str(part).casefold() for part in manifest["exclude_parts"]}:
        return True
    if any(
        fnmatch.fnmatchcase(folded, str(pattern).casefold())
        for pattern in manifest["exclude_globs"]
    ):
        return True
    return any(
        folded == str(prefix).casefold().rstrip("/")
        or folded.startswith(str(prefix).casefold().rstrip("/") + "/")
        for prefix in manifest["exclude_prefixes"]
    )


def collect_files(project_root: Path, manifest: dict[str, Any]) -> list[SnapshotFile]:
    candidates: dict[str, Path] = {}

    def add(source_relative: str, target_relative: str | None = None) -> None:
        source = (project_root / source_relative).resolve(strict=False)
        target = (target_relative or source_relative).replace("\\", "/")
        if target.startswith("/") or ".." in Path(target).parts:
            raise SnapshotError("snapshot target is unsafe")
        _relative_posix(project_root, source)
        if not source.is_file() or _is_reparse(source):
            raise SnapshotError(f"required source is missing or reparse: {source_relative}")
        if target in candidates and candidates[target] != source:
            raise SnapshotError("snapshot target is duplicated")
        candidates[target] = source

    for item in manifest["files"]:
        if not isinstance(item, str) or not item:
            raise SnapshotError("open-source file entry is invalid")
        add(item)
    for mapping in manifest["mappings"]:
        if not isinstance(mapping, dict) or set(mapping) != {"source", "target"}:
            raise SnapshotError("open-source mapping is invalid")
        add(str(mapping["source"]), str(mapping["target"]))
    for root_entry in manifest["roots"]:
        if not isinstance(root_entry, str) or not root_entry:
            raise SnapshotError("open-source root entry is invalid")
        root = (project_root / root_entry).resolve(strict=False)
        _relative_posix(project_root, root)
        if not root.is_dir() or _is_reparse(root):
            raise SnapshotError(f"open-source root is missing or reparse: {root_entry}")
        for source in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            if not source.is_file():
                continue
            relative = _relative_posix(project_root, source)
            if _excluded(relative, manifest):
                continue
            if relative.casefold().endswith(
                tuple(
                    str(value).casefold()
                    for value in manifest["forbidden_suffixes"]
                )
            ):
                continue
            if _is_reparse(source):
                raise SnapshotError(f"reparse source is not publishable: {relative}")
            if relative in candidates and candidates[relative] != source:
                raise SnapshotError("snapshot target is duplicated")
            candidates[relative] = source
    return [SnapshotFile(source, target) for target, source in sorted(candidates.items())]


def _validate_candidate_file(item: SnapshotFile, manifest: dict[str, Any]) -> bytes:
    suffixes = tuple(str(value).casefold() for value in manifest["forbidden_suffixes"])
    if item.target.casefold().endswith(suffixes):
        raise SnapshotError(f"forbidden source type: {item.target}")
    before = item.source.stat()
    if before.st_size > manifest["max_file_bytes"]:
        raise SnapshotError(f"source exceeds publish size bound: {item.target}")
    data = item.source.read_bytes()
    after = item.source.stat()
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(data) != before.st_size
    ):
        raise SnapshotError(f"source changed during snapshot: {item.target}")
    return data


def normalize_publish_bytes(target: str, data: bytes) -> bytes:
    """Match the repository's .gitattributes EOL policy before hashing.

    The public repository enforces LF for text and CRLF for Windows batch files.
    Hashing the private worktree bytes directly would make a GitHub source ZIP
    fail its own receipt whenever a Windows checkout contained CRLF or mixed EOL.
    Binary data is left byte-for-byte unchanged.
    """

    if b"\x00" in data:
        return data
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    normalized = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if Path(target).suffix.casefold() in {".bat", ".cmd"}:
        return normalized.replace(b"\n", b"\r\n")
    return normalized


def audit_content(target: str, data: bytes) -> None:
    for label, pattern in _HIGH_CONFIDENCE_SECRETS:
        if pattern.search(data):
            raise SnapshotError(f"high-confidence {label} found: {target}")
    if _GENERIC_SECRET.search(data) and not target.casefold().startswith(
        _GENERIC_SECRET_ALLOWED_PREFIXES
    ):
        raise SnapshotError(f"secret-like token found outside fixtures: {target}")
    if b"\x00" in data and Path(target).suffix.casefold() not in {
        ".ico",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".woff",
        ".woff2",
    }:
        raise SnapshotError(f"unexpected binary file: {target}")


def _git_head(project_root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def export_snapshot(
    project_root: Path,
    manifest_path: Path,
    output_root: Path,
    candidate_id: str,
) -> Path:
    if _CANDIDATE_RE.fullmatch(candidate_id) is None:
        raise SnapshotError("candidate id is invalid")
    project_root = project_root.resolve(strict=True)
    output_root = output_root.resolve(strict=False)
    approved_root = (_APPROVED_OUTPUT_ROOT if project_root == _PROJECT_ROOT else output_root).resolve(
        strict=False
    )
    candidate = (output_root / candidate_id).resolve(strict=False)
    try:
        candidate.relative_to(approved_root)
    except ValueError as exc:
        raise SnapshotError("snapshot output escaped approved root") from exc
    if candidate.exists():
        raise SnapshotError("snapshot candidate already exists")

    manifest = load_manifest(manifest_path)
    files = collect_files(project_root, manifest)
    if not files:
        raise SnapshotError("snapshot has no files")
    entries: list[dict[str, object]] = []
    candidate.mkdir(parents=True, exist_ok=False)
    try:
        for item in files:
            data = normalize_publish_bytes(
                item.target, _validate_candidate_file(item, manifest)
            )
            audit_content(item.target, data)
            destination = candidate / Path(item.target)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            entries.append(
                {"path": item.target, "size": len(data), "sha256": _sha256(data)}
            )
        receipt = {
            "schema": "nachuan.open-source-snapshot.v1",
            "candidate_id": candidate_id,
            "license": manifest["license"],
            "source_head": _git_head(project_root),
            "source_worktree_dirty": True,
            "history_included": False,
            "file_count": len(entries),
            "files": entries,
        }
        receipt_bytes = _canonical_json(receipt)
        (candidate / "OPEN_SOURCE_SNAPSHOT.json").write_bytes(receipt_bytes)
    except BaseException:
        # Never recursively delete a failed candidate here.  Preserve it for
        # forensic inspection and require a new candidate id on retry.
        raise
    return candidate


def verify_snapshot(candidate: Path) -> dict[str, object]:
    receipt_path = candidate / "OPEN_SOURCE_SNAPSHOT.json"
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError("snapshot receipt is unreadable") from exc
    if not isinstance(receipt, dict) or receipt.get("schema") != "nachuan.open-source-snapshot.v1":
        raise SnapshotError("snapshot receipt schema is invalid")
    expected = receipt.get("files")
    if not isinstance(expected, list):
        raise SnapshotError("snapshot file inventory is invalid")
    actual_paths = []
    for path in candidate.rglob("*"):
        if not path.is_file() or path == receipt_path:
            continue
        relative = path.relative_to(candidate)
        if relative.parts and relative.parts[0].casefold() == ".git":
            continue
        actual_paths.append(relative.as_posix())
    actual_paths.sort()
    expected_paths = [str(item.get("path")) for item in expected if isinstance(item, dict)]
    if actual_paths != expected_paths:
        raise SnapshotError("snapshot file closure differs from receipt")
    for item in expected:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise SnapshotError("snapshot file entry is invalid")
        path = candidate / str(item["path"])
        data = path.read_bytes()
        if len(data) != item["size"] or _sha256(data) != item["sha256"]:
            raise SnapshotError("snapshot file digest mismatch")
        audit_content(str(item["path"]), data)
    if receipt.get("file_count") != len(expected):
        raise SnapshotError("snapshot file count is invalid")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("export", "verify"))
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--project-root", type=Path, default=_PROJECT_ROOT)
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    parser.add_argument("--output-root", type=Path, default=_APPROVED_OUTPUT_ROOT)
    args = parser.parse_args()
    try:
        candidate = args.output_root / args.candidate_id
        if args.command == "export":
            candidate = export_snapshot(
                args.project_root, args.manifest, args.output_root, args.candidate_id
            )
            receipt = verify_snapshot(candidate)
        else:
            receipt = verify_snapshot(candidate)
    except (SnapshotError, OSError, subprocess.SubprocessError) as exc:
        print(f"[open-source-snapshot] FAIL {type(exc).__name__}")
        return 2
    print(
        "[open-source-snapshot] OK "
        f"candidate={args.candidate_id} files={receipt['file_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
