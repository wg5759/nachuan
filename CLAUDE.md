# 大模型聚合器（纳川）· 项目约定

## 「复查项目」= 发起者零票、其余四家互审

口语说“复查/互审/让几个模型看看”即触发互审意图，不要求机主再输命令。现役候选模型家族固定为 Moonshot/Kimi K3（直接 Kimi Code CLI，会话 `wire.jsonl` 验真）、OpenAI/GPT-5.6 Sol、智谱/GLM-5.2、MiniMax/M3、DeepSeek/V4-Pro；排除本轮发起家族后，由其余四个不同模型家族给出审查意见。发起者只收集、复现、裁决和总结，`vote_weight=0`，不得自审或用别名重复计票。Claude/Anthropic 已退出现役花名册，不能自动路由或计票。

“四个不同模型家族”不等于“四个独立连接域”：Kimi K3 与 Sol 分别使用 Kimi Code/Codex 登录域，GLM、MiniMax、DeepSeek 当前共用 OpenCode/Volcano 连接域。同一连接域最多只能算一个独立票；现配置排除发起者后只有 2~3 个连接域，因此不得声称已经取得四个真正独立票。

当前正式 `xreview` 故障关闭：裸 `bash scripts/xreview.sh ...` 会受脚本第一行之前的调用方 `BASH_ENV` 影响，不是可信启动根；现役花名册也不足四个独立连接域。正式模式会在启动任何模型前退出 78。仓库内 Kimi ACP stdin helper 目前只有 fake-process 合同证据，尚未接入正式 `xreview`，没有经正式 xreview 的真实 Kimi reviewer turn 或 actual-served reviewer model 回执；独立产品 subscription 文本回合成功不构成正式互审证据，也不得据此放宽门禁。

`test-only` 只允许无真实凭据、无真实模型的本地 fake reviewer 回归，返回 `NON_FORMAL_TEST_COMPLETE`、退出 3。待仓库外受保护、句柄绑定且有可验证回执的启动器/控制面、四个独立连接域与 actual-served 身份绑定完成后，才能重新评估正式启用。

取得受信互审意见后仍须逐条回到代码和测试核实，修复真问题、说明误报证据、把未证实项标为待复核，并如实汇报每家发现、判断、改动和验证结果。

## 打包提醒
- 引擎(gateway/ orchestrator/)改动要进安装包 → 得重打引擎(PyInstaller)；纯前端(desktop/)改动 → 只需 electron 重打。
- 打完务必用任务管理器或 PowerShell `Stop-Process -Id <监听 8080 的 PID>` 关闭开发引擎，否则装好的 app 复用旧引擎、表现「没有模型」；禁止用会临时下载包的远程 runner。
- PyInstaller 曾确定性卡死：根因是 `engine.spec` 里 `collect_all('tokenizers')`（已改为显式带 .pyd）。别再往 collect_all 加 Rust 系库。
