# ADR-0003：Channel Delivery 采用持久 inbox/outbox

- 状态：接受
- 日期：2026-07-13

## 背景

微信消息已经进入引擎并生成回复，但 iLink 出站发生 TLS/连接复位后异常被吞掉，用户三分钟仍无响应。HTTP 200 中的业务失败也未被识别。

## 决策

Channel Delivery 必须将入站消息、游标和出站消息持久化：

- 入站先落 inbox，再确认游标；按用户顺序领取并去重。
- 出站先落 outbox，再发送；失败指数退避，超过阈值进入死信。
- HTTP 状态和协议业务码都必须成功才算送达。
- 长任务先确认接收并报告进度。
- 以不含密钥的原子健康快照供 supervisor 和 /health 使用。

## 后果

- 进程重启后仍可继续处理和投递。
- SQLite 成为 Channel Delivery 的本地可靠性依赖，必须纳入备份和 quick-check。
- 其它 Channel adapter 应复用相同语义，而不是复制微信脚本。
