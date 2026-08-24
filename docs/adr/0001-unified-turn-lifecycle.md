# ADR-0001：统一 Turn 生命周期

- 状态：接受
- 日期：2026-07-13

## 背景

微信、飞书、桌面聊天、桌面执行和 HTTP 曾分别组合路由、记忆、模型和结果字段，同一句请求可能因入口不同获得不同权限和完成语义。

## 决策

所有入口最终收敛到 Turn Engine。Channel 仅保留身份、消息和媒体 adapter；Turn Engine 统一负责意图、路由、记忆、延迟预算、Capability、WorkGraph、Evidence 和 Outcome。

迁移采用渐进方式：先统一 Outcome、能力隔离和 Channel Delivery，再把仍在 gateway/app.py 的入口编排逐步收进 Turn Engine。

## 后果

- 正面：一个 Turn 可端到端追踪和测试，入口不再复制策略。
- 代价：迁移期保留兼容 adapter，短期存在新旧调用并存。
- 约束：Channel adapter 不得自行调用执行工具或伪造 Outcome。
