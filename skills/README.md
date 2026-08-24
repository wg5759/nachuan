# skills/ —— 项目技能库（Agent Skills / SKILL.md 开放标准）

每个技能 = 一个子目录，里面一个 `SKILL.md`，顶部 YAML frontmatter 至少含 `name` 和 `description`：

```
skills/
  my-skill/
    SKILL.md        # 必需：frontmatter(name/description) + 详细步骤
    scripts/        # 可选：脚本（模型按需调用，受执行权限/审核闸约束）
    references/     # 可选：参考文档（模型按需读）
```

`SKILL.md` 示例：

```markdown
---
name: analyzing-xxx
description: 一句话说明「这个技能干嘛、什么时候用」——模型靠这句决定要不要加载它。
---

# 详细步骤
1. ...
2. ...
```

## 渐进披露（为什么装多也不糊涂）
- **L1**：引擎只把每个技能的 `name + description` 喂给模型（每个约一行）。装 100 个也只是 100 行清单。
- **L2**：模型真要用某个，才调 `load_skill(name)` 读它的 `SKILL.md` 全文。
- **L3**：`SKILL.md` 里再引用的脚本/参考，模型按需读。

## 安全（重要）
- 技能可带可执行脚本 = 供应链风险。**社区技能 26% 带漏洞、36% 有提示注入。**
- 来源优先各大厂**官方第一方库**（如 `anthropics/skills` 含 docx/pptx、`MicrosoftDocs/Agent-Skills`、OpenAI/Google 官方）。
- 放进本目录前**逐个审 `SKILL.md` + 所有脚本**，并用 `safedep/vet` / `skill-scanner` 扫描。
- 机主自己的 `~/.claude/skills/` 也会被加载（视为可信）。

命名：动词-ing + 名词（如 `analyzing-marketing`），≤64 字；`SKILL.md` 控制在 500 行内，细节拆进 `references/`。
