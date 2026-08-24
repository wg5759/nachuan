# ADR-0002：聊天与执行能力隔离

- 状态：接受
- 日期：2026-07-13

## 背景

普通文本聊天曾可进入带 danger-full-access、bypassPermissions 或全磁盘访问的 CLI 模型；客户端布尔 approved=true 也能表达过宽的执行许可。

## 决策

纯聊天 provider 永远使用只读、无工具模式。Controlled Execution 必须消费服务端签发的一次性 Capability；Capability 精确绑定用户、任务和工作目录，领取和完成均为原子操作，重放或字段不匹配一律拒绝。

## 后果

- 聊天提示词不能升级自身权限。
- 高风险操作多一次明确批准。
- provider、工具和 HTTP 入口共享同一授权语义。
