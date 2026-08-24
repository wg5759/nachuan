# ADR-0007：会话历史以有界 SQLite 为真源并保护 Turn 回执

- 状态：接受；存储合同完成，供应商调用路径接线待统一集成
- 日期：2026-07-17

## 背景

旧会话存储会在启动时加载整表，普通 `append` 又可能在 SQLite 写满后只更新内存并吞掉异常，造成“当前进程看得到、重启后丢失”。按固定条数清理回执还可能提前删除仍在保护期内的重放证据。

## 决策

- SQLite 是持久会话真源，内存只保存有界 LRU；首次访问按 session key 延迟读取最近历史。
- 任何持久 `append`、`clear` 或原子 Turn 提交都必须先完成 SQLite 事务，提交成功后才更新内存；失败 rollback 并明确返回 unavailable。
- 会话 key、role、content、served model 使用严格类型与 UTF-8 字节上限，不把 bytes、数字或空 key 隐式转成字符串；只接受 `user`/`assistant` 两种会话角色。所有读接口返回深复制，调用方不能反向修改进程内缓存或幂等回执。
- 数据库页上限默认 1 GiB；会话历史与 Turn 回执分别使用默认 256 MiB 的精确 UTF-8 payload 预算。事务触发器维护 O(1) 行数和字节计数。
- 会话超预算时只回收最旧的完整非当前 session，不从多个会话各切一段制造断裂上下文。
- Turn 回执在 30 天保护窗内绝不因行数或字节压力被淘汰；只有真正过期的回执可以删除。保护窗已满时拒绝新提交，不伪装成功。
- 第一次供应商调用前，调用方必须以 `turn_key + request_sha256` 在 `agent_turn_reservation` 中持久预留一行和最坏情况 `64 + 64 + 1 MiB = 1,048,704` payload 字节。预留与已提交回执共同计入行/字节硬上限，并在 `BEGIN IMMEDIATE` 下串行核算，因此相同容量合同的跨进程并发不能超卖；同一 Turn 的摘要冲突一律故障关闭。
- `reserved` 和 `provider_started` 是占用容量的活跃状态，绝不是成功重放凭据，`idempotent_result` 对它们返回未完成。`reserved` 可在第一次 provider phase 前显式放弃，但放弃会转成永久 `abandoned` 摘要 tombstone，而不是删除 Turn 绑定；tombstone 的预留字节和活跃行计数均为零，同摘要可重新预留，不同摘要永久冲突，且未重新预留的迟到 commit 被拒绝。进入 `provider_started` 后跨重启保持占位，任何自动清理或普通放弃都不得释放，以免重试再次付费。
- Turn 成功提交必须在同一个 SQLite 事务中写入会话 pair、消费对应预留并写入真实回执；任一步失败会整体 rollback，保留原预留和未提交语义。实际回执仍受 1 MiB 上限约束，所以不会大于预留的最坏情况预算。供应商路径提交必须显式启用 `require_provider_started=True`，让存储层拒绝缺失预留或仍停在 `reserved` 的提交；本地无供应商原子提交继续使用默认兼容路径。
- 回执行数、回执 payload 字节上限及容量合同版本写入 `conversation_capacity_meta`，成为数据库权威；第二实例、重启或滚动升级携带不同值时初始化故障关闭，不允许各进程用不同上限解释同一账本。缩容或改合同必须走显式迁移，不能靠换启动参数静默完成。
- 初始化先把 `sqlite_master` 的完整状态归类为受审的新库、旧库或现役合同。只有完整受审旧版可原子迁移；缺 reservation、receipt、metadata、索引或触发器等任何 partial/mixed 状态一律故障关闭且不得静默修补。现役 schema 对 TEXT、摘要、状态、时间、大小和容量合同加数据库约束，数据库对象必须恰好是受审四表、两索引、九触发器与 SQLite 自有 sequence。相似表、额外对象、约束漂移、NULL/BLOB/超限旧数据同样拒绝。
- 启动时在 `BEGIN IMMEDIATE` 内完成 schema/计数验证，并在释放写锁的 `COMMIT` **之前**采样初始 `PRAGMA data_version`；这样提交后抢入的外部变更不能被吸收成未经验证的新基线。后续写路径持写锁重验，`get`、Turn receipt 读取和 `last_model` 等只读入口也会在返回前检查外部提交；验证成功后再失效 LRU 和 served-model 归因，验证失败不擦除最后一份已知良好缓存。
- 主数据库及 WAL/SHM/journal sidecar 在打开前后逐级 `lstat`，只接受非 reparse 的普通文件；路径异常统一使持久回执不可用。

## 后果

- 磁盘满、外部锁和异常 schema 不再产生内存/磁盘分叉；重启后的历史与已确认提交保持一致。
- 每次启动都会做一次精确 `COUNT/SUM` 对账；旧 schema 首次迁移还需要表重建，应安排维护窗口并预留空间。正常单写者热路径不反复全表扫描。
- 容量压力会明确拒绝新 Turn，而不是删掉仍可用于防重复执行的近期证据。
- provider 前预留会保守占用 1 MiB 响应预算，即使实际响应很短；这是避免“保护窗已满却先产生供应商费用”的有意空间换安全。
- `abandoned` tombstone 永久保存摘要绑定但不占逻辑回执槽；它仍会占少量 SQLite 物理空间，因此数据库总页上限仍是最终边界，运维需监控 tombstone 增长，不能把它误计为可回收回执。

## 尚未关闭的边界

本 ADR 已关闭 `ConversationStore` 的供应商调用前回执容量预留缺口，但只有实际 Turn 调用路径严格执行“reserve → provider phase fence → provider call → atomic commit”，该保护才真正生效。尚未接线的调用路径不得宣称已经避免“先付费、后发现保护窗已满”。

Python 的 pathname + `lstat` 无法从原理上消灭同一 Windows SID 恶意进程在检查与 SQLite 打开之间换靶的 TOCTOU；正式运行仍须把 `data/` 放在受保护、拒绝 reparse 的目录，并承认“同 SID 不是沙箱”。只读入口的外部变更重验当前不取得写锁；若另一个合法写者恰好在多条验证查询之间频繁提交，可能保守地返回 unavailable 并在下一次入口再次重验。因此该库不作为高并发多写者架构，生产拓扑仍应由单一 Turn Engine 持有写权。
