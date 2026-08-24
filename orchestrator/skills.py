"""Hash-allowlisted, project-local Agent Skills with progressive disclosure."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path

from orchestrator.skill_bundle import EXPECTED_MANIFEST_SHA256


_ROOT = Path(__file__).resolve().parent.parent / "skills"
_MANIFEST = _ROOT / "trusted-manifest.json"
_MAX_SKILL_BYTES = 256 * 1024
_SAFE_RELATIVE = re.compile(r"^[A-Za-z0-9_.-]+/SKILL\.md$")


def _parse_frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
    meta: dict[str, str] = {}
    if not match:
        return meta
    for line in match.group(1).splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            key, value = line.split(":", 1)
            meta[key.strip()] = value.strip().strip("\"'")
    return meta


def _is_reparse(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        check = getattr(path, "is_junction", None)
        return bool(check and check())
    except OSError:
        return True


def _trusted_entries() -> list[dict[str, str]]:
    try:
        if _is_reparse(_MANIFEST):
            return []
        raw = _MANIFEST.read_bytes()
        if len(raw) > 64 * 1024:
            return []
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), EXPECTED_MANIFEST_SHA256):
            return []
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    entries = doc.get("skills") if isinstance(doc, dict) and doc.get("schema") == 1 else None
    if not isinstance(entries, list) or len(entries) > 60:
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def list_skills() -> list[dict[str, str]]:
    """Return only SKILL.md files whose bytes match the signed project manifest."""

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    root = _ROOT.resolve(strict=False)
    for entry in _trusted_entries():
        relative = str(entry.get("path") or "")
        expected = str(entry.get("sha256") or "").lower()
        declared_name = str(entry.get("name") or "").strip()
        if not _SAFE_RELATIVE.fullmatch(relative) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            continue
        candidate = _ROOT / relative
        try:
            resolved = candidate.resolve(strict=True)
            if resolved.parent.parent != root or _is_reparse(candidate) or _is_reparse(candidate.parent):
                continue
            raw = candidate.read_bytes()
        except (OSError, RuntimeError):
            continue
        if len(raw) > _MAX_SKILL_BYTES:
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(digest, expected):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            continue
        meta = _parse_frontmatter(text)
        name = str(meta.get("name") or "").strip()
        if not name or name != declared_name or name in seen:
            continue
        seen.add(name)
        out.append(
            {
                "name": name,
                "description": str(meta.get("description") or ""),
                "path": str(resolved),
            }
        )
    return out


def load_skill(name: str) -> str:
    for skill in list_skills():
        if skill["name"] == name:
            try:
                return Path(skill["path"]).read_text(encoding="utf-8")
            except OSError:
                return "(读取技能失败：受信文件不可用)"
    return f"(未找到或未通过哈希准入的技能：{name})"


def manifest_text(max_skills: int = 60) -> str:
    trusted = list_skills()[: max(0, min(int(max_skills), 60))]
    if not trusted:
        return ""
    lines = [f"- {skill['name']}：{skill['description']}" for skill in trusted]
    return (
        "【已审核技能】用到某个时调用 load_skill(name) 读取；"
        "未在项目哈希清单中的本机/用户技能不会加载：\n" + "\n".join(lines)
    )


def available() -> bool:
    return bool(list_skills())
