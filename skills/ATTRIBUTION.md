# 第三方技能来源与许可（Attribution）

以下技能取自开源项目 **agency-agents**，固定到已验证签名提交
`00fb28a4cf60a719363dce0de67fafc6301857ce`
（https://github.com/msitarzewski/agency-agents/tree/00fb28a4cf60a719363dce0de67fafc6301857ce ·
MIT License · Copyright (c) 2025 AgentLand Contributors），
经供应链安全审查（Claude Opus 4.8 + Codex 独立复审：install.sh 只本地拷贝、无网络、无 prompt 注入、无隐藏 Unicode）确认安全后，
**精选补纳川空缺**的 6 个纳入（未全量搬入，避免污染常驻技能提示）：

| 纳川技能目录 | 原始 persona | 上游 Git blob |
|---|---|---|
| `security-appsec-engineer/` | security/security-appsec-engineer | `e5f82dc0ad7c164d03e156cf4696f5570273453e` |
| `product-manager/` | product/product-manager | `6a617be2dbf1a1321b23b0b40e693041a1178cbe` |
| `video-optimization-specialist/` | marketing/marketing-video-optimization-specialist | `3d5fbb416b05f297f8649a3ecf39279d150e2290` |
| `content-creator/` | marketing/marketing-content-creator | `4beedb05f5e4f8754c63125649ac8a9763609330` |
| `xiaohongshu-specialist/` | marketing/marketing-xiaohongshu-specialist | `e4dde95726abc734e0c15efcc6d1b39b5dd2ca76` |
| `mcp-builder/` | specialized/specialized-mcp-builder | `e12b89c5e04e2ef483120a672845a9d024318314` |

内容为原文照搬（SKILL.md 标准格式：frontmatter `name`/`description` + 正文），未改写。
MIT 许可证要求保留版权与许可声明，特此声明；完整许可原文随包保存于
`skills/LICENSE.agency-agents`（上游 Git blob `523078c01624b9b1b1c551e75054b9d3a9f953ab`）。

2026-07-13 使用 GitHub API 对上述固定提交逐文件复核：本地六个 `SKILL.md` 的 Git blob
全部与上游一致，提交签名状态为 `verified=true`。此结论只覆盖上述字节快照，不覆盖上游未来提交、
Release、安装脚本或同名仓库。

采纳理由：纳川已有 TRINITY 三角色 + 10 条工程身份覆盖 engineering/debug/UI/API/性能/架构；
这 6 个补的是纳川**没有**的角色——应用安全审查、产品需求拆解、短视频优化、内容策略、小红书分发、MCP 扩展。
