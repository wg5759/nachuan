---
description: 互审入口状态说明（当前正式模式故障关闭，不启动真实模型）
argument-hint: "[commit-sha，默认 HEAD]"
---

当前不能把 `$ARGUMENTS` 送入正式多模型互审：

- Claude/Anthropic 已退出现役花名册，不能自动路由或计票。
- 现役候选是 Moonshot/Kimi K3、OpenAI/GPT-5.6 Sol、智谱/GLM-5.2、MiniMax/M3、DeepSeek/V4-Pro；发起家族必须排除且 `vote_weight=0`。
- GLM、MiniMax、DeepSeek 当前共用 OpenCode/Volcano 连接域，排除发起者后不足四个真正独立连接域。
- 裸 Bash 入口还会受调用方 `BASH_ENV` 影响，Kimi ACP stdin helper 也尚未接入正式入口；正式模式会在启动任何模型前退出 78。

因此这里只向机主如实说明门禁状态，不调用真实或付费模型，也不把 `test-only` fake 输出冒充正式互审。只有仓库外受保护启动器、四个独立连接域、actual-served 身份回执和真实 Kimi 验真全部完成后，才恢复正式互审。
