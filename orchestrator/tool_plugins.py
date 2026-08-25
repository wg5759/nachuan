"""Built-in, data-only Skill bundle and its first read-only tool adapter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from orchestrator import skills
from orchestrator.plugin_kernel import ToolDefinition
from orchestrator.skill_bundle import EXPECTED_MANIFEST_SHA256


@dataclass(frozen=True, slots=True)
class SkillBundleEntryV1:
    name: str
    description: str
    content: str
    sha256: str


@dataclass(frozen=True, slots=True)
class SkillBundleV1:
    schema: str
    manifest_sha256: str
    entries: tuple[SkillBundleEntryV1, ...]


LIST_SKILLS_TOOL_DEFINITION = ToolDefinition(
    name="list_skills",
    description=(
        "列出当前发行包中经过哈希清单准入的技能名称和一句话说明；"
        "不扫描用户目录，也不执行技能代码。"
    ),
    parameters={
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
)

LOAD_SKILL_TOOL_DEFINITION = ToolDefinition(
    name="load_skill",
    description=(
        "按精确名称读取当前受审 Skill bundle 中的一份 SKILL.md；"
        "只返回冻结文本，不执行其中的代码或命令。"
    ),
    parameters={
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
        "additionalProperties": False,
    },
)


def build_reviewed_skill_bundle() -> SkillBundleV1 | None:
    """Freeze the existing trusted manifest into a non-executable bundle value."""

    reviewed = skills.list_skills()
    if not reviewed:
        return None
    entries: list[SkillBundleEntryV1] = []
    for item in reviewed:
        name = str(item.get("name") or "").strip()
        description = str(item.get("description") or "").strip()
        content = skills.load_skill(name)
        if (
            not name
            or not description
            or not content
            or content.startswith(
                ("(未找到或未通过哈希准入", "(读取技能失败")
            )
        ):
            return None
        entries.append(
            SkillBundleEntryV1(
                name=name,
                description=description,
                content=content,
                sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
        )
    return SkillBundleV1(
        schema="nachuan.skill-bundle.v1",
        manifest_sha256=EXPECTED_MANIFEST_SHA256,
        entries=tuple(entries),
    )


def render_skill_manifest(bundle: SkillBundleV1) -> str:
    if not isinstance(bundle, SkillBundleV1) or not bundle.entries:
        return "(暂无可用技能)"
    lines = [f"- {entry.name}：{entry.description}" for entry in bundle.entries]
    return (
        "【已审核技能】用到某个时调用 load_skill(name) 读取；"
        "未在项目哈希清单中的本机/用户技能不会加载：\n" + "\n".join(lines)
    )


def render_skill_content(bundle: SkillBundleV1, name: str) -> str:
    if not isinstance(bundle, SkillBundleV1):
        return "(受审 Skill bundle 当前不可用)"
    normalized = str(name or "").strip()
    for entry in bundle.entries:
        if entry.name == normalized:
            return entry.content[:6000]
    return f"(未找到或未通过哈希准入的技能：{normalized})"


__all__ = [
    "LIST_SKILLS_TOOL_DEFINITION",
    "LOAD_SKILL_TOOL_DEFINITION",
    "SkillBundleEntryV1",
    "SkillBundleV1",
    "build_reviewed_skill_bundle",
    "render_skill_content",
    "render_skill_manifest",
]
