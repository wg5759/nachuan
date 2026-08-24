"""Build-time closed set for the reviewed third-party skill bundle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path


EXPECTED_MANIFEST_SHA256 = "b621b59d5bf8fe01cf07322eaca6b9973922fb92829462ae01b5da3d40de8b0e"
EXPECTED_SKILLS = (
    ("Content Creator", "content-creator/SKILL.md", "26ddce44f057068a3935c13d53becd3c57385fb47fcdcfdd891b80269070b3d5"),
    ("MCP Builder", "mcp-builder/SKILL.md", "3880031674ae2458552ad3c4da99c122469e85351ed57969db7f6f767befd7cb"),
    ("Product Manager", "product-manager/SKILL.md", "4a3fe4661e72e5173877bcba7c362392181774b20efc27ac1789171e98676c9d"),
    ("Application Security Engineer", "security-appsec-engineer/SKILL.md", "f3ee22350c9e0e7289d2d4747e7c1a8fe196d70340feec7b176b13bacc3deb77"),
    ("Video Optimization Specialist", "video-optimization-specialist/SKILL.md", "9cf82969be8898c96192617becf5e38e8de6b79650c362d840c53d2c10f2e8b9"),
    ("Xiaohongshu Specialist", "xiaohongshu-specialist/SKILL.md", "c0afe07b77d7795ff6c5ea928360f0e545d51a6df231d42d6282168ace027154"),
)
EXPECTED_NOTICES = (
    ("ATTRIBUTION.md", "27a23fe169f58002434e2787920410eca97bb53aab25031824229a19885a7010"),
    ("LICENSE.agency-agents", "9a45258434d5cedf0af73c9ad4771373701225038d246c49219026c33677f66f"),
    ("README.md", "1be0978aaf4856461a05a2fb7cc24afb99e7690ae5220ec7e3ccef5d320933d1"),
)
_SAFE_SKILL_PATH = re.compile(r"^[A-Za-z0-9_.-]+/SKILL\.md$")


class SkillBundleError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        check = getattr(path, "is_junction", None)
        if check and check():
            return True
        attributes = int(getattr(os.lstat(path), "st_file_attributes", 0))
        return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))
    except OSError:
        return True


def _exact_file(root: Path, relative: str, expected: str, *, max_bytes: int) -> Path:
    candidate = root / relative
    try:
        if _is_reparse(root) or _is_reparse(candidate) or _is_reparse(candidate.parent):
            raise SkillBundleError(f"reviewed skill path is redirected: {relative}")
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        info = candidate.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > max_bytes:
            raise SkillBundleError(f"reviewed skill file has unsafe shape: {relative}")
        resolved.relative_to(resolved_root)
    except SkillBundleError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise SkillBundleError(f"reviewed skill file is unavailable: {relative}") from exc
    if _sha256(resolved) != expected:
        raise SkillBundleError(f"reviewed skill digest mismatch: {relative}")
    return resolved


def verified_skill_bundle_datas(skills_root: str | Path) -> list[tuple[str, str]]:
    """Return only the exact files allowed into PyInstaller ``datas``."""

    root = Path(skills_root)
    manifest = _exact_file(
        root,
        "trusted-manifest.json",
        EXPECTED_MANIFEST_SHA256,
        max_bytes=64 * 1024,
    )
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SkillBundleError("reviewed skill manifest is invalid") from exc
    expected_entries = [
        {"name": name, "path": relative, "sha256": digest}
        for name, relative, digest in EXPECTED_SKILLS
    ]
    if document != {"schema": 1, "skills": expected_entries}:
        raise SkillBundleError("reviewed skill manifest does not match the build-time closed set")

    datas: list[tuple[str, str]] = [(str(manifest), "skills")]
    for _name, relative, digest in EXPECTED_SKILLS:
        if not _SAFE_SKILL_PATH.fullmatch(relative):
            raise SkillBundleError(f"unsafe build-time skill path: {relative}")
        source = _exact_file(root, relative, digest, max_bytes=256 * 1024)
        datas.append((str(source), f"skills/{Path(relative).parent.as_posix()}"))
    for relative, digest in EXPECTED_NOTICES:
        source = _exact_file(root, relative, digest, max_bytes=256 * 1024)
        datas.append((str(source), "skills"))
    return datas
