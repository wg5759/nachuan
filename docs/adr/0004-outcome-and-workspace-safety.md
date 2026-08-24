# ADR-0004：统一 Outcome，并对写副作用保守串行

- 状态：接受
- 日期：2026-07-13

## 背景

不同编排路径曾各自决定“完成”，verified=false 仍可能返回正常完成外观；Conductor 同层节点共享工作目录并行时可能相互覆盖。

## 决策

所有编排路径使用同一个闭集 Outcome Gate：

- verified=true → completed
- 未执行独立验证 → completed_unverified
- 验证失败且有阶段成果 → partial
- 验证失败且无成果 → failed
- 策略或安全门禁明确拒绝执行 → blocked
- durable 异步作业已创建、当前 Turn 只完成受理回执 → accepted_async
- 异步容量门禁在创建任何作业前拒绝 → rejected_capacity

`accepted_async` 只结束当前消息 Turn，不得被 UI 表示为后台作业已经完成；后续作业必须有独立 `job_id` 和 durable lifecycle。`rejected_capacity` 与 `blocked` 都必须保证没有付费或不可逆副作用发生。HTTP 200 仅表示 Outcome 文档成功送达，不等于 `completed`。

Conductor 只有在工具集合被显式证明为纯只读时允许共享工作目录并行。未知、空配置或包含副作用工具时，同层节点串行。

## 后果

- 终态诚实且可跨入口比较。
- 写任务牺牲部分并发速度，换取确定性。
- 未来若要并行写，必须使用节点级隔离工作树和合并冲突闸。
